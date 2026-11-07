const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8787;
const SECRET = process.env.QIVORA_JWT_SECRET || "qivora-secret-key-2026";
const DATA = path.join(__dirname, "sync-data.json");

function load() { try { return JSON.parse(fs.readFileSync(DATA, "utf8")); } catch (e) { return { users: {}, blobs: {} }; } }
function save(db) { fs.writeFileSync(DATA, JSON.stringify(db)); }
function hash(pw) { return crypto.createHash("sha256").update(pw).digest("hex"); }
function token(userId, email) {
  const body = Buffer.from(JSON.stringify({ userId, email, exp: Date.now() + 30 * 864e5 })).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(t) {
  if (!t) return null;
  const [body, sig] = t.split(".");
  if (!body || !sig) return null;
  const expect = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  if (expect !== sig) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); if (p.exp < Date.now()) return null; return p; } catch (e) { return null; }
}
function readBody(req) {
  return new Promise(r => { let d = ""; req.on("data", c => d += c); req.on("end", () => { try { r(JSON.parse(d || "{}")); } catch (e) { r({}); } }); });
}
function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") return json(res, 204, {});
  const url = new URL(req.url, "http://x");
  const db = load();
  if (url.pathname === "/auth/register" && req.method === "POST") {
    const { email, password } = await readBody(req);
    if (!email || !password || password.length < 6) return json(res, 400, { error: "bad-input" });
    if (db.users[email]) return json(res, 409, { error: "exists" });
    const userId = crypto.randomUUID();
    db.users[email] = { userId, hash: hash(password) };
    db.blobs[userId] = { updatedAt: new Date().toISOString(), data: {} };
    save(db);
    return json(res, 200, { token: token(userId, email), userId });
  }
  if (url.pathname === "/auth/login" && req.method === "POST") {
    const { email, password } = await readBody(req);
    const u = db.users[email];
    if (!u || u.hash !== hash(password)) return json(res, 401, { error: "bad-credentials" });
    return json(res, 200, { token: token(u.userId, email), userId: u.userId });
  }
  const auth = verify((req.headers.authorization || "").replace("Bearer ", ""));
  if (!auth) return json(res, 401, { error: "unauthorized" });
  if (url.pathname === "/sync/push" && req.method === "POST") {
    const body = await readBody(req);
    db.blobs[auth.userId] = { updatedAt: body.updatedAt || new Date().toISOString(), data: body.data || {} };
    save(db);
    return json(res, 200, { ok: true });
  }
  if (url.pathname === "/sync/pull" && req.method === "GET") {
    return json(res, 200, db.blobs[auth.userId] || { updatedAt: null, data: {} });
  }
  json(res, 404, { error: "not-found" });
});
server.listen(PORT, () => console.log("QIVORA sync on", PORT));
