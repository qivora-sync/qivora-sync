'use strict';
const crypto = require('crypto');
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_TTL_HOURS = 24;
function normalizeCode(value) { return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16); }
function hashCode(value) { return crypto.createHash('sha256').update(normalizeCode(value)).digest('hex'); }
function generateCode() {
  const bytes = crypto.randomBytes(8);
  let out = '';
  for (const byte of bytes) out += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  return `${out.slice(0,4)}-${out.slice(4)}`;
}
async function ensureSpace(client, userId) {
  let found = await client.query(`SELECT s.id,s.name,m.role FROM qivora_shared_space_members m JOIN qivora_shared_spaces s ON s.id=m.space_id WHERE m.user_id=$1 AND m.status='active' LIMIT 1`, [userId]);
  if (found.rowCount) {
    if (found.rows[0].role !== 'owner') throw Object.assign(new Error('owner-role-required'), { status: 403 });
    return found.rows[0];
  }
  const created = await client.query(`INSERT INTO qivora_shared_spaces(name,owner_user_id) VALUES('Сімейний простір',$1) RETURNING id,name`, [userId]);
  await client.query(`INSERT INTO qivora_shared_space_members(space_id,user_id,role,status) VALUES($1,$2,'owner','active')`, [created.rows[0].id,userId]);
  return created.rows[0];
}
async function createCode(pool, ownerId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const space = await ensureSpace(client, ownerId);
    await client.query(`UPDATE qivora_shared_invite_codes SET revoked_at=NOW() WHERE space_id=$1 AND created_by=$2 AND used_at IS NULL AND revoked_at IS NULL`, [space.id,ownerId]);
    let code, inserted;
    for (let i=0;i<5;i++) {
      code = generateCode();
      inserted = await client.query(`INSERT INTO qivora_shared_invite_codes(space_id,created_by,code_hash,expires_at) VALUES($1,$2,$3,NOW()+($4::text||' hours')::interval) ON CONFLICT(code_hash) DO NOTHING RETURNING id,expires_at`, [space.id,ownerId,hashCode(code),String(CODE_TTL_HOURS)]);
      if (inserted.rowCount) break;
    }
    if (!inserted?.rowCount) throw new Error('invite-code-generation-failed');
    await client.query('COMMIT');
    return { inviteId: inserted.rows[0].id, code, expiresAt: inserted.rows[0].expires_at };
  } catch (error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
  finally { client.release(); }
}
async function redeemCode(pool, userId, rawCode) {
  const code = normalizeCode(rawCode);
  if (code.length !== 8) return { error:'invalid-code', status:400 };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const invite = await client.query(`SELECT i.id,i.space_id,i.created_by,s.name FROM qivora_shared_invite_codes i JOIN qivora_shared_spaces s ON s.id=i.space_id WHERE i.code_hash=$1 AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>NOW() FOR UPDATE OF i`, [hashCode(code)]);
    if (!invite.rowCount) { await client.query('ROLLBACK'); return {error:'code-invalid-expired-or-used',status:404}; }
    const row = invite.rows[0];
    if (String(row.created_by) === String(userId)) { await client.query('ROLLBACK'); return {error:'cannot-join-own-space',status:400}; }
    const existing = await client.query(`SELECT space_id FROM qivora_shared_space_members WHERE user_id=$1 AND status='active' LIMIT 1`, [userId]);
    if (existing.rowCount) { await client.query('ROLLBACK'); return {error:'already-in-shared-space',status:409}; }
    const request = await client.query(`INSERT INTO qivora_shared_join_requests(space_id,invite_id,user_id,status) VALUES($1,$2,$3,'pending') ON CONFLICT(invite_id,user_id) DO UPDATE SET status='pending',created_at=NOW(),decided_at=NULL RETURNING id`, [row.space_id,row.id,userId]);
    await client.query('COMMIT');
    return {ok:true,requestId:request.rows[0].id,spaceName:row.name,status:'pending-approval'};
  } catch(error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
  finally { client.release(); }
}
async function listRequests(pool, ownerId) {
  const r = await pool.query(`SELECT r.id,r.user_id,u.email,r.created_at,s.name AS space_name FROM qivora_shared_join_requests r JOIN qivora_shared_spaces s ON s.id=r.space_id JOIN qivora_shared_space_members m ON m.space_id=s.id AND m.user_id=$1 AND m.role='owner' AND m.status='active' JOIN qivora_users u ON u.id=r.user_id WHERE r.status='pending' ORDER BY r.created_at`, [ownerId]);
  return r.rows;
}
async function decideRequest(pool, ownerId, requestId, approve) {
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const r=await client.query(`SELECT r.id,r.space_id,r.user_id FROM qivora_shared_join_requests r JOIN qivora_shared_space_members m ON m.space_id=r.space_id AND m.user_id=$1 AND m.role='owner' AND m.status='active' WHERE r.id=$2 AND r.status='pending' FOR UPDATE OF r`,[ownerId,requestId]);
    if(!r.rowCount){await client.query('ROLLBACK');return {error:'request-not-found',status:404};}
    const row=r.rows[0];
    if(approve){
      const existing=await client.query(`SELECT 1 FROM qivora_shared_space_members WHERE user_id=$1 AND status='active' LIMIT 1`,[row.user_id]);
      if(existing.rowCount){await client.query('ROLLBACK');return {error:'user-already-in-shared-space',status:409};}
      await client.query(`INSERT INTO qivora_shared_space_members(space_id,user_id,role,status) VALUES($1,$2,'member','active') ON CONFLICT(space_id,user_id) DO UPDATE SET role='member',status='active',joined_at=NOW()`,[row.space_id,row.user_id]);
      await client.query(`UPDATE qivora_shared_invite_codes SET used_at=NOW(),used_by=$1 WHERE id=(SELECT invite_id FROM qivora_shared_join_requests WHERE id=$2) AND used_at IS NULL`,[row.user_id,requestId]);
      await client.query(`UPDATE qivora_shared_join_requests SET status='rejected',decided_at=NOW(),decided_by=$1 WHERE invite_id=(SELECT invite_id FROM qivora_shared_join_requests WHERE id=$2) AND id<>$2 AND status='pending'`,[ownerId,requestId]);
    }
    await client.query(`UPDATE qivora_shared_join_requests SET status=$1,decided_at=NOW(),decided_by=$2 WHERE id=$3`,[approve?'approved':'rejected',ownerId,requestId]);
    await client.query('COMMIT'); return {ok:true,status:approve?'approved':'rejected'};
  } catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;} finally{client.release();}
}
async function revokeCode(pool, ownerId, inviteId) {
  const r=await pool.query(`UPDATE qivora_shared_invite_codes i SET revoked_at=NOW() FROM qivora_shared_space_members m WHERE i.id=$1 AND m.space_id=i.space_id AND m.user_id=$2 AND m.role='owner' AND m.status='active' AND i.used_at IS NULL AND i.revoked_at IS NULL RETURNING i.id`,[inviteId,ownerId]);
  return r.rowCount?{ok:true}:{error:'invite-not-found-or-not-revocable',status:404};
}
async function getSpace(pool,userId){
  const r=await pool.query(`SELECT s.id,s.name,m.role FROM qivora_shared_space_members m JOIN qivora_shared_spaces s ON s.id=m.space_id WHERE m.user_id=$1 AND m.status='active' LIMIT 1`,[userId]);
  return r.rows[0]||null;
}
module.exports={createCode,redeemCode,listRequests,decideRequest,revokeCode,getSpace,normalizeCode,hashCode,generateCode};
