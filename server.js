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
function send(res, status, obj) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type, Authorization', 'Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS' }); res.end(JSON.stringify(obj)); }
async function body(req) { let raw=''; for await (const chunk of req) { raw += chunk; if (Buffer.byteLength(raw, 'utf8') > 2_000_000) throw Object.assign(new Error('body-too-large'), { status:413 }); } try { return JSON.parse(raw || '{}'); } catch { throw Object.assign(new Error('invalid-json'), { status:400 }); } }
async function initDb() {
  // Existing Neon qivora_users table was created without password_salt.
  // Add the column safely; do not drop or truncate any table.
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query('ALTER TABLE qivora_users ADD COLUMN IF NOT EXISTS password_salt TEXT');

  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_state (
    user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_applepay_keys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    scope_id TEXT NOT NULL DEFAULT 'personal',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS qivora_applepay_keys_user_active ON qivora_applepay_keys(user_id) WHERE revoked_at IS NULL');

  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_applepay_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    merchant TEXT NOT NULL,
    amount NUMERIC(18,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    transaction_date TIMESTAMPTZ,
    card_label TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, external_id)
  )`);

  // Ensure every account has a sync snapshot. Existing rows are left untouched.
  await pool.query(`INSERT INTO qivora_sync_state(user_id,data)
    SELECT id,'{}'::jsonb FROM qivora_users
    ON CONFLICT(user_id) DO NOTHING`);
}
function requireAuth(req) { return verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i,'')); }

function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function applePayCategory(merchant) {
  const m=String(merchant||'').toLowerCase();
  if(/mercadona|primaprix|carrefour|lidl|aldi|dia\b|consum|eroski|alcampo|supermercad|hiper/.test(m)) return 'Продукти';
  if(/restaurant|restaurante|cafe|coffee|bar\b|burger|mcdonald|starbucks|pizzeria|telepizza/.test(m)) return 'Ресторани';
  if(/farmacia|pharmacy|parafarmacia/.test(m)) return 'Здоров’я';
  if(/gasolinera|repsol|cepsa|shell|bp\b|petrol/.test(m)) return 'Транспорт';
  if(/amazon|ikea|zara|primark|decathlon|leroy merlin/.test(m)) return 'Покупки';
  return 'Інше';
}
function parseApplePayDate(value) {
  if (!value) return new Date();
  const d=new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}
function getApplePayBearer(req) {
  const h=String(req.headers.authorization||'');
  return /^Bearer\s+qva_[A-Za-z0-9_-]{32,}$/i.test(h) ? h.replace(/^Bearer\s+/i,'') : null;
}

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
      const client=await pool.connect();
      try { await client.query('BEGIN'); await client.query('INSERT INTO qivora_users(id,email,password_salt,password_hash) VALUES($1,$2,$3,$4)',[id,email,salt,hash]); await client.query('INSERT INTO qivora_sync_state(user_id,data) VALUES($1,$2::jsonb)',[id,JSON.stringify({})]); await client.query('COMMIT'); }
      catch(e) { await client.query('ROLLBACK').catch(()=>{}); if(e.code==='23505') return send(res,409,{error:'exists'}); throw e; }
      finally { client.release(); }
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

    if (url.pathname === '/applepay/transactions' && req.method === 'POST') {
      const bearer=getApplePayBearer(req);
      if(!bearer) return send(res,401,{error:'applepay-key-required'});
      const input=await body(req);
      const eventId=String(input.eventId||'').trim();
      const merchant=String(input.merchant||'').trim().slice(0,200);
      const currency=String(input.currency||'').trim().toUpperCase();
      const amount=Number(input.amount);
      const transactionDate=parseApplePayDate(input.transactionDate);
      const cardLabel=String(input.cardLabel||'').trim().slice(0,100);
      if(!/^[A-Za-z0-9._:-]{8,128}$/.test(eventId) || !merchant || !/^[A-Z]{3}$/.test(currency) || !Number.isFinite(amount) || amount<=0 || amount>100000000 || !transactionDate)
        return send(res,400,{error:'invalid-transaction'});
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        const key=await client.query('SELECT id,user_id,scope_id FROM qivora_applepay_keys WHERE token_hash=$1 AND revoked_at IS NULL FOR UPDATE',[sha256(bearer)]);
        if(!key.rowCount){await client.query('ROLLBACK');return send(res,401,{error:'invalid-applepay-key'});}
        const userId=key.rows[0].user_id;
        const inserted=await client.query(
          `INSERT INTO qivora_applepay_events(id,user_id,external_id,merchant,amount,currency,transaction_date,card_label)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(user_id,external_id) DO NOTHING RETURNING id`,
          [crypto.randomUUID(),userId,eventId,merchant,amount,currency,transactionDate,cardLabel]
        );
        if(!inserted.rowCount){
          await client.query('COMMIT');
          return send(res,200,{ok:true,duplicate:true});
        }
        const state=await client.query('SELECT data FROM qivora_sync_state WHERE user_id=$1 FOR UPDATE',[userId]);
        if(!state.rowCount){await client.query('ROLLBACK');return send(res,404,{error:'user-state-not-found'});}
        const data=state.rows[0].data&&typeof state.rows[0].data==='object'?state.rows[0].data:{};
        const records=Array.isArray(data.qv_records)?data.qv_records:[];
        const accounts=Array.isArray(data.qv_accounts)?data.qv_accounts:[];
        let scopeId=key.rows[0].scope_id;
        const preferred=accounts.find(a=>a&&a.id===scopeId);
        if(preferred && String(preferred.currency||'EUR').toUpperCase()!==currency) {
          const matching=accounts.find(a=>a&&String(a.currency||'EUR').toUpperCase()===currency);
          if(!matching){await client.query('ROLLBACK');return send(res,422,{error:'currency-account-not-found',currency});}
          scopeId=matching.id;
        } else if(!preferred && accounts.length) {
          const matching=accounts.find(a=>a&&String(a.currency||'EUR').toUpperCase()===currency);
          if(!matching){await client.query('ROLLBACK');return send(res,422,{error:'currency-account-not-found',currency});}
          scopeId=matching.id;
        }
        const dateMatch=String(input.transactionDate||'').match(/^(\d{4}-\d{2}-\d{2})/);
        const date=dateMatch?dateMatch[1]:transactionDate.toISOString().slice(0,10);
        records.push({
          id:'applepay_'+eventId,scope:scopeId,type:'expense',amount:Number(amount.toFixed(2)),
          merchant,category:applePayCategory(merchant),date,
          note:cardLabel?`Apple Pay · ${cardLabel}`:'Apple Pay',
          source:'apple_pay',externalId:eventId,currency
        });
        data.qv_records=records;
        await client.query('UPDATE qivora_sync_state SET data=$1::jsonb,revision=revision+1,updated_at=NOW() WHERE user_id=$2',[JSON.stringify(data),userId]);
        await client.query('COMMIT');
        return send(res,201,{ok:true,duplicate:false,recordId:'applepay_'+eventId});
      } catch(e) {
        await client.query('ROLLBACK').catch(()=>{});
        throw e;
      } finally { client.release(); }
    }

    const auth=requireAuth(req); if(!auth) return send(res,401,{error:'unauthorized'});

    if (url.pathname === '/applepay/status' && req.method === 'GET') {
      const r=await pool.query('SELECT scope_id,created_at FROM qivora_applepay_keys WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1',[auth.sub]);
      return send(res,200,{enabled:!!r.rowCount,scopeId:r.rows[0]?.scope_id||null,createdAt:r.rows[0]?.created_at||null});
    }
    if (url.pathname === '/applepay/setup' && req.method === 'POST') {
      const input=await body(req);
      const scope=String(input.scope||'personal').trim().slice(0,100)||'personal';
      const token='qva_'+crypto.randomBytes(32).toString('base64url');
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('UPDATE qivora_applepay_keys SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL',[auth.sub]);
        await client.query('INSERT INTO qivora_applepay_keys(id,user_id,token_hash,scope_id) VALUES($1,$2,$3,$4)',[crypto.randomUUID(),auth.sub,sha256(token),scope]);
        await client.query('COMMIT');
      } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
      finally { client.release(); }
      return send(res,201,{ok:true,token,endpoint:'https://qivora-sync.onrender.com/applepay/transactions',createdAt:new Date().toISOString()});
    }
    if (url.pathname === '/applepay/setup' && req.method === 'DELETE') {
      await pool.query('UPDATE qivora_applepay_keys SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL',[auth.sub]);
      return send(res,200,{ok:true,enabled:false});
    }

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
