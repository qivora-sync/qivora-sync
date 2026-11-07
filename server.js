/* QIVORA sync API — PostgreSQL-backed, local-first. */
'use strict';
const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.QIVORA_JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
if (!SECRET || SECRET.length < 32) throw new Error('QIVORA_JWT_SECRET must be set to a random value of at least 32 characters');
if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });

const b64 = x => Buffer.from(x).toString('base64url');
function signToken(user) {
  const body = b64(JSON.stringify({ sub: user.id, email: user.email, exp: Math.floor(Date.now()/1000) + 30*86400 }));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(value) {
  if (!value) return null;
  const [body, sig] = value.split('.'); if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest();
  let actual; try { actual = Buffer.from(sig, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Math.floor(Date.now()/1000) ? p : null; } catch { return null; }
}
function passwordHash(password, salt = crypto.randomBytes(16)) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64*1024*1024 }, (err, key) => err ? reject(err) : resolve({ salt: salt.toString('hex'), hash: key.toString('hex') })));
}
function safeEqualHex(a,b) { try { const x=Buffer.from(a,'hex'), y=Buffer.from(b,'hex'); return x.length===y.length && crypto.timingSafeEqual(x,y); } catch { return false; } }
function send(res, status, obj) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type, Authorization', 'Access-Control-Allow-Methods':'GET,POST,OPTIONS' }); res.end(JSON.stringify(obj)); }
async function body(req) { let raw=''; for await (const chunk of req) { raw += chunk; if (raw.length > 2_000_000) throw Object.assign(new Error('body-too-large'), { status:413 }); } try { return JSON.parse(raw || '{}'); } catch { throw Object.assign(new Error('invalid-json'), { status:400 }); } }
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_users (
    id UUID PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_state (
    user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}
function requireAuth(req) { return verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i,'')); }
const server = http.createServer(async (req,res) => {
  if (req.method === 'OPTIONS') return send(res,204,{});
  const url = new URL(req.url,'http://localhost');
  try {
    if (url.pathname === '/health' && req.method === 'GET') {
      await pool.query('SELECT 1'); return send(res,200,{ ok:true, database:'connected' });
    }
    if (url.pathname === '/auth/register' && req.method === 'POST') {
      const { email: rawEmail, password } = await body(req);
      const email = String(rawEmail || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 8 || password.length > 256) return send(res,400,{error:'bad-input',message:'Valid email and password (8+ characters) required'});
      const {salt,hash} = await passwordHash(password); const id=crypto.randomUUID();
      try { await pool.query('BEGIN'); await pool.query('INSERT INTO qivora_users(id,email,password_salt,password_hash) VALUES($1,$2,$3,$4)',[id,email,salt,hash]); await pool.query('INSERT INTO qivora_sync_state(user_id,data) VALUES($1,$2::jsonb)',[id,JSON.stringify({})]); await pool.query('COMMIT'); }
      catch(e) { await pool.query('ROLLBACK').catch(()=>{}); if(e.code==='23505') return send(res,409,{error:'exists'}); throw e; }
      return send(res,201,{token:signToken({id,email}),userId:id});
    }
    if (url.pathname === '/auth/login' && req.method === 'POST') {
      const { email: rawEmail, password } = await body(req); const email=String(rawEmail||'').trim().toLowerCase();
      const result=await pool.query('SELECT id,email,password_salt,password_hash FROM qivora_users WHERE email=$1',[email]);
      if (!result.rowCount || typeof password!=='string') return send(res,401,{error:'bad-credentials'});
      const user=result.rows[0], calculated=await passwordHash(password,Buffer.from(user.password_salt,'hex'));
      if(!safeEqualHex(calculated.hash,user.password_hash)) return send(res,401,{error:'bad-credentials'});
      return send(res,200,{token:signToken({id:user.id,email:user.email}),userId:user.id});
    }
    const auth=requireAuth(req); if(!auth) return send(res,401,{error:'unauthorized'});
    if (url.pathname === '/sync/pull' && req.method === 'GET') {
      const r=await pool.query('SELECT data,revision,updated_at FROM qivora_sync_state WHERE user_id=$1',[auth.sub]);
      if(!r.rowCount) return send(res,404,{error:'user-state-not-found'});
      return send(res,200,{data:r.rows[0].data,revision:Number(r.rows[0].revision),updatedAt:r.rows[0].updated_at});
    }
    if (url.pathname === '/sync/push' && req.method === 'POST') {
      const input=await body(req); if(!input.data || typeof input.data!=='object' || Array.isArray(input.data)) return send(res,400,{error:'bad-data'});
      const serialized=JSON.stringify(input.data); if(serialized.length>1_500_000) return send(res,413,{error:'data-too-large'});
      const expectedRevision = Number.isInteger(input.revision) && input.revision >= 0 ? input.revision : null;
      if (expectedRevision === null) return send(res,400,{error:'revision-required'});
      const r=await pool.query('UPDATE qivora_sync_state SET data=$1::jsonb, revision=revision+1, updated_at=NOW() WHERE user_id=$2 AND revision=$3 RETURNING revision,updated_at',[serialized,auth.sub,expectedRevision]);
      if(!r.rowCount) { const current=await pool.query('SELECT data,revision,updated_at FROM qivora_sync_state WHERE user_id=$1',[auth.sub]); if(!current.rowCount) return send(res,404,{error:'user-state-not-found'}); return send(res,409,{error:'revision-conflict',data:current.rows[0].data,revision:Number(current.rows[0].revision),updatedAt:current.rows[0].updated_at}); }
      return send(res,200,{ok:true,revision:Number(r.rows[0].revision),updatedAt:r.rows[0].updated_at});
    }
    return send(res,404,{error:'not-found'});
  } catch(e) { console.error('QIVORA API error:',e.message); return send(res,e.status||500,{error:e.status===400?'invalid-json':'server-error'}); }
});
initDb().then(()=>server.listen(PORT,()=>console.log(`QIVORA sync listening on ${PORT}; PostgreSQL ready`))).catch(e=>{console.error('Database initialization failed:',e.message);process.exit(1)});
process.on('SIGTERM',async()=>{server.close();await pool.end();process.exit(0)});
