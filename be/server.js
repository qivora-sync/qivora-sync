/* QIVORA sync API — PostgreSQL-backed, local-first. */
'use strict';
const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const RecordSyncStore = require('./sync-record-store');
const SyncProtocolGate = require('./sync-protocol-gate');
const SharedAccessStore = require('./shared-access-store');
const WorkspaceRecordStore = require('./workspace-record-store');
const WorkspaceImportPreview = require('./workspace-import-preview');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.QIVORA_JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const OCR_SPACE_API_KEY = String(process.env.OCR_SPACE_API_KEY || '').trim();
const RP_ID = process.env.QIVORA_RP_ID || 'qivora-semolina-8700b2.netlify.app';
const RP_IDS = String(process.env.QIVORA_RP_IDS || RP_ID).split(',').map(x=>x.trim()).filter(Boolean);
const WEB_ORIGINS = String(process.env.QIVORA_WEB_ORIGINS || process.env.QIVORA_WEB_ORIGIN || 'https://qivora-semolina-8700b2.netlify.app').split(',').map(x=>x.trim()).filter(Boolean);
if (!SECRET || SECRET.length < 32) throw new Error('QIVORA_JWT_SECRET must be set to a random value of at least 32 characters');
if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
const googleOAuthClient = new OAuth2Client(GOOGLE_CLIENT_ID || undefined);
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });

// SSE is a lightweight wake-up channel only: clients still fetch the authenticated
// snapshot over /sync/pull. PostgreSQL LISTEN/NOTIFY propagates updates across instances.
const syncStreams = new Map();
let syncListenerClient = null;
let syncListenerRetry = null;
let shuttingDown = false;
function scheduleSyncListenerRetry() {
  if (shuttingDown || syncListenerRetry) return;
  syncListenerRetry = setTimeout(() => { syncListenerRetry = null; startSyncListener().catch(err => { console.error('QIVORA sync listener reconnect failed:', err.message); scheduleSyncListenerRetry(); }); }, 3000);
  syncListenerRetry.unref?.();
}
function publishSyncUpdate(userId, revision, cursor) {
  const event = { userId: String(userId), revision: Number(revision || 0) };
  if (cursor !== undefined && cursor !== null) event.cursor = Number(cursor);
  const payload = JSON.stringify(event);
  for (const res of syncStreams.get(String(userId)) || []) {
    if (!res.destroyed && !res.writableEnded) res.write(`event: sync\ndata: ${payload}\n\n`);
  }
}
async function startSyncListener() {
  if (shuttingDown || syncListenerClient) return;
  try {
    const client = await pool.connect();
    syncListenerClient = client;
    client.on('notification', msg => {
      if (msg.channel !== 'qivora_sync_updates') return;
      try { const event = JSON.parse(msg.payload || '{}'); if (event.userId) publishSyncUpdate(event.userId, event.revision ?? event.cursor, event.cursor); } catch {}
    });
    let retryScheduled = false;
    const recoverListener = (err) => {
      if (err) console.error('QIVORA sync listener error:', err.message);
      if (syncListenerClient === client) syncListenerClient = null;
      if (!retryScheduled) { retryScheduled = true; scheduleSyncListenerRetry(); }
      try { client.release(true); } catch {}
    };
    client.on('error', recoverListener);
    client.on('end', () => recoverListener());
    await client.query('LISTEN qivora_sync_updates');
  } catch (err) {
    syncListenerClient = null;
    console.error('QIVORA sync listener unavailable; fallback polling remains active:', err.message);
    scheduleSyncListenerRetry();
  }
}

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
function send(res, status, obj) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' }); res.end(JSON.stringify(obj)); }

// Small per-instance abuse guard. For multi-instance deployments, move these
// counters to a shared store (e.g. PostgreSQL/Redis) before scaling horizontally.
const rateBuckets = new Map();
function clientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}
function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) bucket = { count: 0, resetAt: now + windowMs };
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  return bucket.count <= limit ? null : Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
}
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) if (now >= bucket.resetAt) rateBuckets.delete(key);
}, 5 * 60 * 1000).unref?.();

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true; // native clients and server-to-server calls
  if (!WEB_ORIGINS.includes(origin)) return false;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Max-Age', '600');
  return true;
}

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
  await pool.query('ALTER TABLE qivora_users ALTER COLUMN password_hash DROP NOT NULL');
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_email_otps (
    email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_rate_limits (
    rate_key TEXT PRIMARY KEY, window_started TIMESTAMPTZ NOT NULL, count INTEGER NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS qivora_rate_limits_expiry ON qivora_rate_limits(expires_at)');

  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_state (
    user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  // Additive record-level sync schema. Legacy snapshot tables remain untouched.
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_cursors (
    user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
    last_cursor BIGINT NOT NULL DEFAULT 0 CHECK (last_cursor >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_records (
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    collection TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    data JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(user_id,collection,record_id),
    CHECK ((deleted = TRUE AND data IS NULL) OR (deleted = FALSE AND data IS NOT NULL))
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_changes (
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    cursor BIGINT NOT NULL CHECK (cursor >= 1),
    operation_id TEXT NOT NULL,
    collection TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    deleted BOOLEAN NOT NULL,
    data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(user_id,cursor),
    CHECK ((deleted = TRUE AND data IS NULL) OR (deleted = FALSE AND data IS NOT NULL))
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_operations (
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(user_id,operation_id)
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS qivora_sync_changes_created ON qivora_sync_changes(user_id,created_at)');
  await pool.query('CREATE INDEX IF NOT EXISTS qivora_sync_records_updated ON qivora_sync_records(user_id,updated_at)');
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_migrations (
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    migration_key TEXT NOT NULL,
    migration_id UUID NOT NULL,
    snapshot_revision BIGINT NOT NULL CHECK (snapshot_revision >= 0),
    record_count INTEGER NOT NULL DEFAULT 0 CHECK (record_count >= 0),
    cursor_start BIGINT NOT NULL DEFAULT 0 CHECK (cursor_start >= 0),
    cursor_end BIGINT NOT NULL DEFAULT 0 CHECK (cursor_end >= 0),
    baseline_records JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(user_id,migration_key),
    UNIQUE(user_id,migration_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_sync_protocol (
    user_id UUID PRIMARY KEY REFERENCES qivora_users(id) ON DELETE CASCADE,
    records_mode TEXT NOT NULL DEFAULT 'snapshot' CHECK (records_mode IN ('snapshot','record')),
    activated_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  await pool.query(`INSERT INTO qivora_sync_cursors(user_id,last_cursor)
    SELECT id,0 FROM qivora_users ON CONFLICT(user_id) DO NOTHING`);

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

  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_passkeys (
    credential_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT[] NOT NULL DEFAULT '{}',
    device_type TEXT,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS qivora_passkeys_user ON qivora_passkeys(user_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_webauthn_challenges (
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('registration','authentication')),
    challenge TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(user_id,kind)
  )`);

  // Shared access foundation. Additive only: existing financial data is untouched.
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_shared_spaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL DEFAULT 'Сімейний простір',
    owner_user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_shared_space_members (
    space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('owner','member')), status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','removed')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(space_id,user_id)
  )`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS qivora_shared_one_active_space_per_user ON qivora_shared_space_members(user_id) WHERE status='active'`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_shared_invite_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, used_by UUID REFERENCES qivora_users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS qivora_shared_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), space_id UUID NOT NULL REFERENCES qivora_shared_spaces(id) ON DELETE CASCADE,
    invite_id UUID NOT NULL REFERENCES qivora_shared_invite_codes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES qivora_users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), decided_at TIMESTAMPTZ,
    decided_by UUID REFERENCES qivora_users(id) ON DELETE SET NULL, UNIQUE(invite_id,user_id)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS qivora_shared_join_requests_owner ON qivora_shared_join_requests(space_id,status,created_at)`);

  // Additive workspace-scoped record sync schema; personal sync tables remain untouched.
  const workspaceSyncMigration = fs.readFileSync(path.join(__dirname,'migrations','009_workspace_record_sync.sql'),'utf8');
  await pool.query(workspaceSyncMigration);

  // Ensure every account has a sync snapshot. Existing rows are left untouched.
  await pool.query(`INSERT INTO qivora_sync_state(user_id,data)
    SELECT id,'{}'::jsonb FROM qivora_users
    ON CONFLICT(user_id) DO NOTHING`);
}
function requireAuth(req) { return verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i,'')); }

function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function otpHash(email, code) { return crypto.createHmac('sha256', SECRET).update(`${email}:${code}`).digest('hex'); }
async function sendOtpEmail(email, code) {
  const key=process.env.BREVO_API_KEY, from=process.env.QIVORA_EMAIL_FROM;
  if(!key || !from) throw Object.assign(new Error('email-provider-not-configured'),{status:503});
  const htmlContent=`<div style="font-family:Arial,sans-serif;background:#0b1020;color:#fff;padding:28px;border-radius:16px"><h1 style="letter-spacing:4px">QIVORA</h1><p>Твій одноразовий код для входу:</p><div style="font-size:32px;font-weight:700;letter-spacing:10px;color:#67e8f9">${code}</div><p>Код діє 10 хвилин. Якщо ти не запитував його, просто проігноруй цей лист.</p></div>`;
  const response=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':key,'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({sender:{email:extractSenderEmail(from),name:extractSenderName(from)},to:[{email}],subject:'Код входу в QIVORA',htmlContent})});
  if(!response.ok) { const err=await response.text().catch(()=> ''); console.error('Brevo error:',response.status,err.slice(0,300)); throw Object.assign(new Error('email-send-failed'),{status:502}); }
}
function extractSenderEmail(value){const m=String(value||'').match(/<([^<>]+)>/);return (m?m[1]:String(value||'')).trim();}
function extractSenderName(value){const m=String(value||'').match(/^\s*([^<>]+?)\s*</);return (m?m[1]:'QIVORA').trim();}
async function dbRateLimit(key, limit, windowSeconds) {
  const r=await pool.query(`INSERT INTO qivora_rate_limits(rate_key,window_started,count,expires_at)
    VALUES($1,NOW(),1,NOW()+($2::text||' seconds')::interval)
    ON CONFLICT(rate_key) DO UPDATE SET
      count=CASE WHEN qivora_rate_limits.window_started <= NOW()-($2::text||' seconds')::interval THEN 1 ELSE qivora_rate_limits.count+1 END,
      window_started=CASE WHEN qivora_rate_limits.window_started <= NOW()-($2::text||' seconds')::interval THEN NOW() ELSE qivora_rate_limits.window_started END,
      expires_at=NOW()+($2::text||' seconds')::interval
    RETURNING count, GREATEST(1,CEIL(EXTRACT(EPOCH FROM (expires_at-NOW()))))::int AS retry_after`,[key,windowSeconds]);
  return Number(r.rows[0].count)>limit ? Number(r.rows[0].retry_after) : null;
}
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

async function saveWebAuthnChallenge(userId, kind, challenge) {
  await pool.query(`INSERT INTO qivora_webauthn_challenges(user_id,kind,challenge,expires_at)
    VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes')
    ON CONFLICT(user_id,kind) DO UPDATE SET challenge=EXCLUDED.challenge,expires_at=EXCLUDED.expires_at,created_at=NOW()`,[userId,kind,challenge]);
}
async function getWebAuthnChallenge(userId, kind) {
  const r=await pool.query('SELECT challenge FROM qivora_webauthn_challenges WHERE user_id=$1 AND kind=$2 AND expires_at>NOW()',[userId,kind]);
  return r.rows[0]?.challenge || null;
}
async function clearWebAuthnChallenge(userId, kind) {
  await pool.query('DELETE FROM qivora_webauthn_challenges WHERE user_id=$1 AND kind=$2',[userId,kind]);
}
const server = http.createServer(async (req,res) => {
  if (!applyCors(req,res)) return send(res,403,{error:'origin-not-allowed'});
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = new URL(req.url,'http://localhost');
  try {
    if (url.pathname === '/health' && req.method === 'GET') {
      await pool.query('SELECT 1'); return send(res,200,{ ok:true, database:'connected' });
    }
    // Server-side OCR.space proxy. The API key never leaves Render; guest scans are
    // supported, with per-IP throttling and strict image/type/size validation.
    if (url.pathname === '/ocr/accurate' && req.method === 'POST') {
      const wait=rateLimit(`ocr-ip:${clientIp(req)}`,12,15*60*1000);
      if(wait) return send(res,429,{error:'rate-limited',retryAfter:wait});
      if(!OCR_SPACE_API_KEY) return send(res,503,{error:'ocr-not-configured'});
      const input=await body(req);
      const mime=String(input.mimeType||'image/jpeg').toLowerCase();
      if(!['image/jpeg','image/png','image/webp','image/tiff','application/pdf'].includes(mime)) return send(res,415,{error:'unsupported-file-type'});
      const encoded=String(input.fileBase64||'').replace(/^data:[^,]+,/, '');
      if(!encoded || encoded.length>1_300_000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return send(res,413,{error:'file-too-large-or-invalid'});
      const bytes=Buffer.from(encoded,'base64');
      if(!bytes.length || bytes.length>950*1024) return send(res,413,{error:'file-too-large'});
      const form=new FormData();
      form.append('file',new Blob([bytes],{type:mime}),String(input.filename||'qivora-scan').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,100));
      form.append('language','auto');
      form.append('isOverlayRequired','false');
      form.append('isTable','true');
      form.append('scale','true');
      form.append('OCREngine','2');
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort(),55000);
      let upstream;
      try {
        upstream=await fetch('https://api.ocr.space/parse/image',{method:'POST',headers:{apikey:OCR_SPACE_API_KEY},body:form,signal:controller.signal});
      } catch(e) {
        return send(res,e.name==='AbortError'?504:502,{error:e.name==='AbortError'?'ocr-timeout':'ocr-upstream-unavailable'});
      } finally { clearTimeout(timer); }
      let result;
      try { result=await upstream.json(); } catch { return send(res,502,{error:'ocr-invalid-response'}); }
      if(!upstream.ok) return send(res,upstream.status===429?429:502,{error:upstream.status===429?'ocr-rate-limited':'ocr-upstream-error'});
      if(result.IsErroredOnProcessing) return send(res,422,{error:'ocr-processing-failed'});
      const parsedText=(Array.isArray(result.ParsedResults)?result.ParsedResults:[]).map(x=>String(x.ParsedText||'')).join('\n').slice(0,50000);
      if(!parsedText.trim()) return send(res,422,{error:'ocr-no-text'});
      return send(res,200,{ok:true,parsedText,engine:'ocr.space'});
    }
    if (url.pathname === '/auth/google' && req.method === 'POST') {
      const wait=rateLimit(`google-auth-ip:${clientIp(req)}`,30,15*60*1000);
      if(wait) return send(res,429,{error:'rate-limited',retryAfter:wait});
      if(!GOOGLE_CLIENT_ID) return send(res,503,{error:'google-auth-not-configured'});
      const input=await body(req);
      const idToken=String(input.credential || input.idToken || '');
      if(!idToken || idToken.length>10000) return send(res,400,{error:'missing-google-credential'});
      let payload;
      try {
        const ticket=await googleOAuthClient.verifyIdToken({idToken,audience:GOOGLE_CLIENT_ID});
        payload=ticket.getPayload();
      } catch {
        return send(res,401,{error:'invalid-google-credential'});
      }
      const email=String(payload?.email || '').trim().toLowerCase();
      if(!payload?.sub || payload.email_verified!==true || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return send(res,401,{error:'google-email-not-verified'});
      }
      const client=await pool.connect(); let user;
      try {
        await client.query('BEGIN');
        const found=await client.query('SELECT id,email FROM qivora_users WHERE email=$1 FOR UPDATE',[email]);
        if(found.rowCount) {
          user=found.rows[0];
        } else {
          const id=crypto.randomUUID();
          const created=await client.query(
            'INSERT INTO qivora_users(id,email,password_hash,password_salt) VALUES($1,$2,NULL,NULL) RETURNING id,email',
            [id,email]
          );
          user=created.rows[0];
          await client.query('INSERT INTO qivora_sync_state(user_id,data) VALUES($1,$2::jsonb)',[id,'{}']);
        }
        await client.query('COMMIT');
      } catch(e) {
        await client.query('ROLLBACK').catch(()=>{});
        // Concurrent first sign-ins can race on the unique email constraint.
        if(e.code==='23505') {
          const existing=await pool.query('SELECT id,email FROM qivora_users WHERE email=$1',[email]);
          if(existing.rowCount) user=existing.rows[0];
          else throw e;
        } else throw e;
      } finally { client.release(); }
      if(!user) {
        const existing=await pool.query('SELECT id,email FROM qivora_users WHERE email=$1',[email]);
        if(!existing.rowCount) return send(res,500,{error:'google-account-create-failed'});
        user=existing.rows[0];
      }
      return send(res,200,{token:signToken({id:user.id,email:user.email}),userId:user.id,email:user.email,provider:'google'});
    }

    if (url.pathname === '/auth/email-otp/request' && req.method === 'POST') {
      const input=await body(req), email=String(input.email||'').trim().toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length>254) return send(res,400,{error:'invalid-email'});
      const ipWait=await dbRateLimit(`otp-request-ip:${clientIp(req)}`,10,3600);
      const emailWait=await dbRateLimit(`otp-request-email:${email}`,5,3600);
      if(ipWait || emailWait) return send(res,429,{error:'otp-rate-limited',retryAfter:Math.max(ipWait||0,emailWait||0)});
      const recent=await pool.query('SELECT sent_at FROM qivora_email_otps WHERE email=$1',[email]);
      if(recent.rowCount && Date.now()-new Date(recent.rows[0].sent_at).getTime()<60_000) return send(res,429,{error:'otp-rate-limited',retryAfter:60});
      const code=String(crypto.randomInt(0,1_000_000)).padStart(6,'0');
      const codeHash=otpHash(email,code);
      await pool.query(`INSERT INTO qivora_email_otps(email,code_hash,expires_at,attempts,sent_at) VALUES($1,$2,NOW()+INTERVAL '10 minutes',0,NOW()) ON CONFLICT(email) DO UPDATE SET code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at,attempts=0,sent_at=NOW()`,[email,codeHash]);
      try { await sendOtpEmail(email,code); }
      catch(error) { await pool.query('DELETE FROM qivora_email_otps WHERE email=$1 AND code_hash=$2',[email,codeHash]).catch(()=>{}); throw error; }
      return send(res,200,{ok:true,expiresIn:600});
    }
    if (url.pathname === '/auth/email-otp/verify' && req.method === 'POST') {
      const input=await body(req), email=String(input.email||'').trim().toLowerCase(), code=String(input.code||'').trim();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(code)) return send(res,400,{error:'invalid-code'});
      const ipWait=await dbRateLimit(`otp-verify-ip:${clientIp(req)}`,20,900);
      const emailWait=await dbRateLimit(`otp-verify-email:${email}`,10,900);
      if(ipWait || emailWait) return send(res,429,{error:'otp-verify-rate-limited',retryAfter:Math.max(ipWait||0,emailWait||0)});
      const client=await pool.connect(); let user;
      try {
        await client.query('BEGIN');
        const otp=await client.query('SELECT code_hash,expires_at,attempts FROM qivora_email_otps WHERE email=$1 FOR UPDATE',[email]);
        if(!otp.rowCount || new Date(otp.rows[0].expires_at).getTime()<Date.now() || Number(otp.rows[0].attempts)>=5) { await client.query('ROLLBACK'); return send(res,401,{error:'otp-expired-or-invalid'}); }
        if(!safeEqualHex(otpHash(email,code),otp.rows[0].code_hash)) { await client.query('UPDATE qivora_email_otps SET attempts=attempts+1 WHERE email=$1',[email]); await client.query('COMMIT'); return send(res,401,{error:'otp-expired-or-invalid'}); }
        const found=await client.query('SELECT id,email FROM qivora_users WHERE email=$1',[email]);
        if(found.rowCount) user=found.rows[0];
        else { const id=crypto.randomUUID(); const created=await client.query('INSERT INTO qivora_users(id,email,password_hash,password_salt) VALUES($1,$2,NULL,NULL) RETURNING id,email',[id,email]); user=created.rows[0]; await client.query('INSERT INTO qivora_sync_state(user_id,data) VALUES($1,$2::jsonb)',[id,'{}']); }
        await client.query('DELETE FROM qivora_email_otps WHERE email=$1',[email]);
        await client.query('COMMIT');
      } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
      finally { client.release(); }
      return send(res,200,{token:signToken({id:user.id,email:user.email}),userId:user.id,email:user.email});
    }

    if (url.pathname === '/auth/register' && req.method === 'POST') {
      const wait=rateLimit(`register-ip:${clientIp(req)}`,15,15*60*1000);
      if(wait) return send(res,429,{error:'rate-limited',retryAfter:wait});
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
      const wait=rateLimit(`login-ip:${clientIp(req)}`,30,15*60*1000);
      if(wait) return send(res,429,{error:'rate-limited',retryAfter:wait});
      const { email: rawEmail, password } = await body(req); const email=String(rawEmail||'').trim().toLowerCase();
      const result=await pool.query('SELECT id,email,password_salt,password_hash FROM qivora_users WHERE email=$1',[email]);
      if (!result.rowCount || typeof password!=='string' || !result.rows[0].password_hash || !result.rows[0].password_salt) return send(res,401,{error:'bad-credentials'});
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
        const applePayRecord={
          id:'applepay_'+eventId,scope:scopeId,type:'expense',amount:Number(amount.toFixed(2)),
          merchant,category:applePayCategory(merchant),date,
          note:cardLabel?`Apple Pay · ${cardLabel}`:'Apple Pay',
          source:'apple_pay',externalId:eventId,currency
        };
        const protocol=await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR SHARE',[userId]);
        if(protocol.rows[0]?.records_mode==='record'){
          const current=await client.query(
            'SELECT version FROM qivora_sync_records WHERE user_id=$1 AND collection=$2 AND record_id=$3 FOR UPDATE',
            [userId,'qv_records',applePayRecord.id]
          );
          const result=await RecordSyncStore.pushChanges(pool,userId,[{
            opId:`applepay-${eventId}`,collection:'qv_records',recordId:applePayRecord.id,
            baseVersion:Number(current.rows[0]?.version||0),deleted:false,data:applePayRecord
          }],{client,transactionActive:true,requireRecordMode:true});
          if(result.conflict){
            await client.query('ROLLBACK');
            return send(res,409,{error:'applepay-record-sync-conflict',details:result});
          }
          await client.query('COMMIT');
          return send(res,201,{ok:true,duplicate:false,recordId:applePayRecord.id,recordSyncMode:'record'});
        }
        records.push(applePayRecord);
        data.qv_records=records;
        const syncUpdate=await client.query('UPDATE qivora_sync_state SET data=$1::jsonb,revision=revision+1,updated_at=NOW() WHERE user_id=$2 RETURNING revision',[JSON.stringify(data),userId]);
        await client.query('SELECT pg_notify($1,$2)', ['qivora_sync_updates', JSON.stringify({userId:String(userId),revision:Number(syncUpdate.rows[0].revision)})]);
        await client.query('COMMIT');
        return send(res,201,{ok:true,duplicate:false,recordId:'applepay_'+eventId});
      } catch(e) {
        await client.query('ROLLBACK').catch(()=>{});
        throw e;
      } finally { client.release(); }
    }

    if (url.pathname === '/webauthn/auth/options' && req.method === 'POST') {
      const input=await body(req), email=String(input.email||'').trim().toLowerCase();
      const user=await pool.query('SELECT id,email FROM qivora_users WHERE email=$1',[email]);
      if(!user.rowCount) return send(res,404,{error:'account-not-found'});
      const userRow=user.rows[0];
      const existing=await pool.query('SELECT credential_id,transports FROM qivora_passkeys WHERE user_id=$1',[userRow.id]);
      if(!existing.rowCount) return send(res,404,{error:'no-passkey'});
      const options=await generateAuthenticationOptions({rpID:RP_ID,allowCredentials:existing.rows.map(x=>({id:x.credential_id,transports:x.transports||[]})),userVerification:'required',timeout:60000});
      await saveWebAuthnChallenge(userRow.id,'authentication',options.challenge);
      return send(res,200,options);
    }
    if (url.pathname === '/webauthn/auth/verify' && req.method === 'POST') {
      const input=await body(req), email=String(input.email||'').trim().toLowerCase();
      const user=await pool.query('SELECT id,email FROM qivora_users WHERE email=$1',[email]);
      if(!user.rowCount) return send(res,401,{error:'account-not-found'});
      const userRow=user.rows[0], expectedChallenge=await getWebAuthnChallenge(userRow.id,'authentication');
      if(!expectedChallenge) return send(res,400,{error:'authentication-challenge-expired'});
      const found=await pool.query('SELECT credential_id,public_key,counter,transports FROM qivora_passkeys WHERE user_id=$1 AND credential_id=$2',[userRow.id,String(input.id||'')]);
      if(!found.rowCount) return send(res,401,{error:'passkey-not-found'});
      const row=found.rows[0];
      const response={...input};delete response.email;
      const verification=await verifyAuthenticationResponse({response,expectedChallenge,expectedOrigin:WEB_ORIGINS,expectedRPID:RP_IDS,requireUserVerification:true,credential:{id:row.credential_id,publicKey:new Uint8Array(row.public_key),counter:Number(row.counter),transports:row.transports||[]}});
      if(!verification.verified) return send(res,401,{error:'passkey-verification-failed'});
      await pool.query('UPDATE qivora_passkeys SET counter=$1,last_used_at=NOW() WHERE credential_id=$2 AND user_id=$3',[verification.authenticationInfo.newCounter,row.credential_id,userRow.id]);
      await clearWebAuthnChallenge(userRow.id,'authentication');
      return send(res,200,{verified:true,token:signToken({id:userRow.id,email:userRow.email}),userId:userRow.id,email:userRow.email});
    }

    const auth=requireAuth(req); if(!auth) return send(res,401,{error:'unauthorized'});

    if (url.pathname === '/shared-access/code' && req.method === 'POST') {
      const wait=await dbRateLimit(`shared-code:${auth.sub}`,5,3600);
      if(wait) return send(res,429,{error:'rate-limited',retryAfter:wait});
      const result=await SharedAccessStore.createCode(pool,auth.sub);
      return send(res,201,{ok:true,...result});
    }
    if (url.pathname === '/shared-access/redeem' && req.method === 'POST') {
      const userWait=await dbRateLimit(`shared-redeem-user:${auth.sub}`,8,15*60);
      const ipWait=await dbRateLimit(`shared-redeem-ip:${clientIp(req)}`,30,15*60);
      if(userWait || ipWait) return send(res,429,{error:'rate-limited',retryAfter:Math.max(userWait||0,ipWait||0)});
      const input=await body(req);
      const result=await SharedAccessStore.redeemCode(pool,auth.sub,input.code);
      return send(res,result.status||200,result);
    }
    if (url.pathname === '/shared-access/requests' && req.method === 'GET') {
      return send(res,200,{requests:await SharedAccessStore.listRequests(pool,auth.sub)});
    }
    if (url.pathname === '/shared-access/requests/decision' && req.method === 'POST') {
      const input=await body(req);
      if(typeof input.requestId!=='string' || !['approve','reject'].includes(input.decision)) return send(res,400,{error:'invalid-request'});
      const result=await SharedAccessStore.decideRequest(pool,auth.sub,input.requestId,input.decision==='approve');
      return send(res,result.status||200,result);
    }
    if (url.pathname === '/shared-access/code' && req.method === 'DELETE') {
      const inviteId=url.searchParams.get('inviteId');
      if(!inviteId) return send(res,400,{error:'invite-id-required'});
      const result=await SharedAccessStore.revokeCode(pool,auth.sub,inviteId);
      return send(res,result.status||200,result);
    }
    if (url.pathname === '/shared-access/status' && req.method === 'GET') {
      return send(res,200,{space:await SharedAccessStore.getSpace(pool,auth.sub)});
    }

    // Shared workspace record sync. Every store call re-checks active membership.
    if (url.pathname === '/workspace/import/preview' && req.method === 'GET') {
      const space=await SharedAccessStore.getSpace(pool,auth.sub);
      if(!space) return send(res,409,{error:'shared-space-required'});
      return send(res,200,await WorkspaceImportPreview.previewPersonalRecords(pool,space.id,auth.sub));
    }
    if (url.pathname === '/workspace/import/commit' && req.method === 'POST') {
      const space=await SharedAccessStore.getSpace(pool,auth.sub);
      if(!space) return send(res,409,{error:'shared-space-required'});
      const input=await body(req);
      const result=await WorkspaceImportPreview.commitPersonalImport(pool,space.id,auth.sub,input.planHash);
      return send(res,200,result);
    }
    if (url.pathname === '/workspace/sync/bootstrap' && req.method === 'GET') {
      const space=await SharedAccessStore.getSpace(pool,auth.sub);
      if(!space) return send(res,409,{error:'shared-space-required'});
      return send(res,200,await WorkspaceRecordStore.getBootstrap(pool,space.id,auth.sub));
    }
    if (url.pathname === '/workspace/sync/push' && req.method === 'POST') {
      const space=await SharedAccessStore.getSpace(pool,auth.sub);
      if(!space) return send(res,409,{error:'shared-space-required'});
      const input=await body(req);
      const result=await WorkspaceRecordStore.pushChanges(pool,space.id,auth.sub,input.operations);
      if(result.conflict) return send(res,409,{error:'workspace-record-conflict',...result});
      return send(res,200,result);
    }
    if (url.pathname === '/workspace/sync/pull' && req.method === 'GET') {
      const space=await SharedAccessStore.getSpace(pool,auth.sub);
      if(!space) return send(res,409,{error:'shared-space-required'});
      const cursor=url.searchParams.get('cursor')??'0';
      const limit=url.searchParams.get('limit')??'200';
      return send(res,200,await WorkspaceRecordStore.pullChanges(pool,space.id,auth.sub,cursor,limit));
    }

    if (url.pathname === '/account' && req.method === 'DELETE') {
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        const removed=await client.query('DELETE FROM qivora_users WHERE id=$1 RETURNING id',[auth.sub]);
        if(!removed.rowCount){await client.query('ROLLBACK');return send(res,404,{error:'account-not-found'});}
        // All user-owned rows (sync snapshot, Apple Pay keys/events, passkeys and
        // WebAuthn challenges) are removed by PostgreSQL ON DELETE CASCADE.
        await client.query('COMMIT');
        return send(res,200,{ok:true,deleted:true});
      } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
      finally { client.release(); }
    }

    if (url.pathname === '/webauthn/register/options' && req.method === 'POST') {
      const existing=await pool.query('SELECT credential_id,transports FROM qivora_passkeys WHERE user_id=$1',[auth.sub]);
      const options=await generateRegistrationOptions({
        rpName:'QIVORA', rpID:RP_ID, userID:Buffer.from(String(auth.sub).replace(/-/g,''),'hex'),
        userName:String(auth.email||auth.sub), userDisplayName:String(auth.email||'QIVORA user'),
        attestationType:'none', timeout:60000,
        authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},
        excludeCredentials:existing.rows.map(x=>({id:x.credential_id,transports:x.transports||[]})),
        supportedAlgorithmIDs:[-7,-257]
      });
      await saveWebAuthnChallenge(auth.sub,'registration',options.challenge);
      return send(res,200,options);
    }
    if (url.pathname === '/webauthn/register/verify' && req.method === 'POST') {
      const input=await body(req), expectedChallenge=await getWebAuthnChallenge(auth.sub,'registration');
      if(!expectedChallenge) return send(res,400,{error:'registration-challenge-expired'});
      const verification=await verifyRegistrationResponse({response:input,expectedChallenge,expectedOrigin:WEB_ORIGINS,expectedRPID:RP_IDS,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});
      if(!verification.verified||!verification.registrationInfo) return send(res,400,{error:'passkey-verification-failed'});
      const info=verification.registrationInfo, credential=info.credential;
      await pool.query(`INSERT INTO qivora_passkeys(credential_id,user_id,public_key,counter,transports,device_type,backed_up)
        VALUES($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT(credential_id) DO UPDATE SET user_id=EXCLUDED.user_id,public_key=EXCLUDED.public_key,counter=EXCLUDED.counter,transports=EXCLUDED.transports,device_type=EXCLUDED.device_type,backed_up=EXCLUDED.backed_up`,
        [credential.id,auth.sub,Buffer.from(credential.publicKey),credential.counter,credential.transports||[],info.credentialDeviceType||null,!!info.credentialBackedUp]);
      await clearWebAuthnChallenge(auth.sub,'registration');
      return send(res,200,{verified:true,enabled:true,credentialId:credential.id});
    }
    if (url.pathname === '/webauthn/passkeys' && req.method === 'DELETE') {
      await pool.query('DELETE FROM qivora_passkeys WHERE user_id=$1',[auth.sub]);
      await clearWebAuthnChallenge(auth.sub,'registration');
      await clearWebAuthnChallenge(auth.sub,'authentication');
      return send(res,200,{ok:true,enabled:false});
    }
    if (url.pathname === '/webauthn/status' && req.method === 'GET') {
      const r=await pool.query('SELECT COUNT(*)::int AS count FROM qivora_passkeys WHERE user_id=$1',[auth.sub]);
      return send(res,200,{enabled:Number(r.rows[0]?.count||0)>0,count:Number(r.rows[0]?.count||0)});
    }

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

    if (url.pathname === '/sync/events' && req.method === 'GET') {
      const auth = requireAuth(req);
      if (!auth) return send(res,401,{error:'unauthorized'});
      res.writeHead(200, {
        'Content-Type':'text/event-stream; charset=utf-8',
        'Cache-Control':'no-cache, no-transform',
        'Connection':'keep-alive',
        'X-Accel-Buffering':'no'
      });
      res.write(': qivora-sync-connected\n\n');
      const userId=String(auth.sub);
      if(!syncStreams.has(userId)) syncStreams.set(userId,new Set());
      syncStreams.get(userId).add(res);
      const heartbeat=setInterval(()=>{if(!res.destroyed&&!res.writableEnded)res.write(': heartbeat\n\n');},20000);
      const cleanup=()=>{
        clearInterval(heartbeat);
        const clients=syncStreams.get(userId);
        if(clients){clients.delete(res);if(!clients.size)syncStreams.delete(userId);}
      };
      req.on('aborted',cleanup);
      res.on('close',cleanup);
      return;
    }
    if (url.pathname === '/sync/protocol/status' && req.method === 'GET') {
      return send(res,200,await SyncProtocolGate.getStatus(pool,auth.sub));
    }
    if (url.pathname === '/sync/protocol/enable-records' && req.method === 'POST') {
      const input=await body(req);
      return send(res,200,await SyncProtocolGate.activate(pool,auth.sub,input.confirmation));
    }
    if (url.pathname === '/sync/protocol/rollback' && req.method === 'POST') {
      const input=await body(req);
      const result=await SyncProtocolGate.rollback(pool,auth.sub,input.confirmation);
      return send(res,200,result);
    }
    if (url.pathname === '/sync/changes/migrate-snapshot' && req.method === 'POST') {
      const input = await body(req);
      if (input.confirmation !== 'MIGRATE_QV_RECORDS_V1') return send(res,400,{error:'explicit-migration-confirmation-required'});
      const result = await RecordSyncStore.migrateSnapshotRecords(pool, auth.sub, input.expectedRevision);
      if (result.conflict) return send(res,409,{error:result.reason,...result});
      return send(res,200,result);
    }
    if (url.pathname === '/sync/changes/bootstrap' && req.method === 'GET') {
      return send(res,200,await RecordSyncStore.getBootstrapState(pool,auth.sub));
    }
    if (url.pathname === '/sync/changes/push' && req.method === 'POST') {
      if (!(await SyncProtocolGate.isRecordMode(pool,auth.sub))) return send(res,409,{error:'record-sync-not-enabled'});
      const input = await body(req);
      const result = await RecordSyncStore.pushChanges(pool, auth.sub, input.operations, {requireRecordMode:true});
      if (result.conflict) return send(res,409,{error:'record-version-conflict',...result});
      return send(res,200,result);
    }
    if (url.pathname === '/sync/changes/pull' && req.method === 'GET') {
      if (!(await SyncProtocolGate.isRecordMode(pool,auth.sub))) return send(res,409,{error:'record-sync-not-enabled'});
      const rawCursor = url.searchParams.get('cursor') ?? '0';
      const rawLimit = url.searchParams.get('limit') ?? '200';
      const result = await RecordSyncStore.pullChanges(pool, auth.sub, rawCursor, rawLimit, {requireRecordMode:true});
      return send(res,200,result);
    }
    if (url.pathname === '/sync/pull' && req.method === 'GET') {
      const r=await pool.query(
        `SELECT s.data,s.revision,s.updated_at,COALESCE(p.records_mode,'snapshot') AS records_mode
         FROM qivora_sync_state s LEFT JOIN qivora_sync_protocol p ON p.user_id=s.user_id WHERE s.user_id=$1`,[auth.sub]);
      if(!r.rowCount) return send(res,404,{error:'user-state-not-found'});
      const recordMode=r.rows[0].records_mode==='record';
      const data={...(r.rows[0].data||{})};
      // Do not send qv_records in record mode: old clients must preserve their local copy.
      if(recordMode) delete data.qv_records;
      return send(res,200,{data,revision:Number(r.rows[0].revision),updatedAt:r.rows[0].updated_at,recordSyncMode:recordMode?'record':'snapshot'});
    }
    if (url.pathname === '/sync/push' && req.method === 'POST') {
      const input=await body(req); if(!input.data || typeof input.data!=='object' || Array.isArray(input.data)) return send(res,400,{error:'bad-data'});
      const expectedRevision = Number.isInteger(input.revision) && input.revision >= 0 ? input.revision : null;
      if (expectedRevision === null) return send(res,400,{error:'revision-required'});
      const client=await pool.connect();
      let saved;
      try {
        await client.query('BEGIN');
        const current=await client.query('SELECT data,revision FROM qivora_sync_state WHERE user_id=$1 FOR UPDATE',[auth.sub]);
        if(!current.rowCount){await client.query('ROLLBACK');return send(res,404,{error:'user-state-not-found'});}
        const currentRevision=Number(current.rows[0].revision);
        if(currentRevision!==expectedRevision){await client.query('ROLLBACK');return send(res,409,{error:'revision-conflict',data:current.rows[0].data,revision:currentRevision,updatedAt:null});}
        const protocol=await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1',[auth.sub]);
        const recordMode=protocol.rows[0]?.records_mode==='record';
        const safeData={...input.data};
        if(recordMode) safeData.qv_records=Array.isArray(current.rows[0].data?.qv_records)?current.rows[0].data.qv_records:[];
        const safeSerialized=JSON.stringify(safeData);
        if(safeSerialized.length>1_500_000){await client.query('ROLLBACK');return send(res,413,{error:'data-too-large'});}
        const updated=await client.query('UPDATE qivora_sync_state SET data=$1::jsonb,revision=revision+1,updated_at=NOW() WHERE user_id=$2 RETURNING revision,updated_at',[safeSerialized,auth.sub]);
        saved=updated.rows[0];
        await client.query('SELECT pg_notify($1,$2)', ['qivora_sync_updates', JSON.stringify({userId:String(auth.sub),revision:Number(saved.revision),kind:'snapshot-update'})]);
        await client.query('COMMIT');
        return send(res,200,{ok:true,revision:Number(saved.revision),updatedAt:saved.updated_at,recordSyncMode:recordMode?'record':'snapshot'});
      } catch(error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
      finally { client.release(); }
    }
    return send(res,404,{error:'not-found'});
  } catch(e) { console.error('QIVORA API error:',e.message); return send(res,e.status||500,{error:e.status===400?'invalid-json':'server-error'}); }
});
initDb().then(()=>{server.listen(PORT,()=>console.log(`QIVORA sync listening on ${PORT}; PostgreSQL ready`));startSyncListener();}).catch(e=>{console.error('Database initialization failed:',e.message);process.exit(1)});
process.on('SIGTERM',async()=>{shuttingDown=true;if(syncListenerRetry)clearTimeout(syncListenerRetry);server.close();await pool.end();process.exit(0)});
