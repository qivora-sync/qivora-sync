'use strict';
const crypto = require('crypto');
const TTL_HOURS = 24;
const normalizeEmail = value => String(value || '').trim().toLowerCase();
const validEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 320;
const tokenHash = value => crypto.createHash('sha256').update(String(value || '')).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');

async function ensureOwnerSpace(client, ownerId) {
  const found = await client.query(`SELECT s.id,s.name,m.role FROM qivora_shared_space_members m JOIN qivora_shared_spaces s ON s.id=m.space_id WHERE m.user_id=$1 AND m.status='active' LIMIT 1`, [ownerId]);
  if (found.rowCount) {
    if (found.rows[0].role !== 'owner') throw Object.assign(new Error('owner-required'), { status: 403 });
    return found.rows[0];
  }
  const created = await client.query(`INSERT INTO qivora_shared_spaces(name,owner_user_id) VALUES('Сімейний простір',$1) RETURNING id,name`, [ownerId]);
  await client.query(`INSERT INTO qivora_shared_space_members(space_id,user_id,role,status) VALUES($1,$2,'owner','active')`, [created.rows[0].id, ownerId]);
  return { ...created.rows[0], role: 'owner' };
}

async function createInvite(pool, ownerId, rawEmail) {
  const email = normalizeEmail(rawEmail);
  if (!validEmail(email)) return { error: 'invalid-email', status: 400 };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const space = await ensureOwnerSpace(client, ownerId);
    const owner = await client.query('SELECT email FROM qivora_users WHERE id=$1', [ownerId]);
    if (!owner.rowCount) throw Object.assign(new Error('owner-not-found'), { status: 404 });
    if (normalizeEmail(owner.rows[0].email) === email) { await client.query('ROLLBACK'); return { error: 'cannot-invite-self', status: 400 }; }
    const existingUser = await client.query('SELECT id FROM qivora_users WHERE email=$1', [email]);
    if (existingUser.rowCount) {
      const membership = await client.query(`SELECT space_id,status FROM qivora_shared_space_members WHERE user_id=$1 AND status='active' LIMIT 1`, [existingUser.rows[0].id]);
      if (membership.rowCount) { await client.query('ROLLBACK'); return { error: String(membership.rows[0].space_id) === String(space.id) ? 'already-member' : 'user-in-other-space', status: 409 }; }
    }
    await client.query(`UPDATE qivora_shared_email_invites SET revoked_at=NOW() WHERE space_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, [space.id, email]);
    const token = newToken();
    const inserted = await client.query(`INSERT INTO qivora_shared_email_invites(space_id,created_by,email,token_hash,expires_at) VALUES($1,$2,$3,$4,NOW()+($5::text||' hours')::interval) RETURNING id,expires_at`, [space.id, ownerId, email, tokenHash(token), String(TTL_HOURS)]);
    await client.query('COMMIT');
    return { ok: true, inviteId: inserted.rows[0].id, email, token, expiresAt: inserted.rows[0].expires_at, spaceName: space.name };
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
  finally { client.release(); }
}

async function removeUndeliveredInvite(pool, inviteId, ownerId) {
  await pool.query(`UPDATE qivora_shared_email_invites i SET revoked_at=NOW() FROM qivora_shared_space_members m WHERE i.id=$1 AND i.created_by=$2 AND m.space_id=i.space_id AND m.user_id=$2 AND m.role='owner' AND m.status='active' AND i.accepted_at IS NULL AND i.revoked_at IS NULL`, [inviteId, ownerId]);
}

async function listInvites(pool, ownerId) {
  const r = await pool.query(`SELECT i.id,i.email,i.created_at,i.expires_at,i.accepted_at,i.revoked_at,CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.accepted_at IS NOT NULL THEN 'accepted' WHEN i.expires_at<=NOW() THEN 'expired' ELSE 'pending' END AS status FROM qivora_shared_email_invites i JOIN qivora_shared_space_members m ON m.space_id=i.space_id AND m.user_id=$1 AND m.role='owner' AND m.status='active' ORDER BY i.created_at DESC`, [ownerId]);
  return r.rows;
}

async function revokeInvite(pool, ownerId, inviteId) {
  const r = await pool.query(`UPDATE qivora_shared_email_invites i SET revoked_at=NOW() FROM qivora_shared_space_members m WHERE i.id=$1 AND m.space_id=i.space_id AND m.user_id=$2 AND m.role='owner' AND m.status='active' AND i.accepted_at IS NULL AND i.revoked_at IS NULL RETURNING i.id`, [inviteId, ownerId]);
  return r.rowCount ? { ok: true } : { error: 'invite-not-found-or-not-revocable', status: 404 };
}

async function acceptInvite(pool, userId, authenticatedEmail, rawToken) {
  const email = normalizeEmail(authenticatedEmail);
  const token = String(rawToken || '').trim();
  if (token.length < 32 || token.length > 128) return { error: 'invalid-invite-token', status: 400 };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('SELECT email FROM qivora_users WHERE id=$1', [userId]);
    if (!user.rowCount || normalizeEmail(user.rows[0].email) !== email) { await client.query('ROLLBACK'); return { error: 'authenticated-email-mismatch', status: 403 }; }
    const found = await client.query(`SELECT i.id,i.space_id,i.email,s.name FROM qivora_shared_email_invites i JOIN qivora_shared_spaces s ON s.id=i.space_id WHERE i.token_hash=$1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>NOW() FOR UPDATE OF i`, [tokenHash(token)]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return { error: 'invite-invalid-expired-or-used', status: 404 }; }
    const invite = found.rows[0];
    if (normalizeEmail(invite.email) !== email) { await client.query('ROLLBACK'); return { error: 'invited-email-mismatch', status: 403 }; }
    const existing = await client.query(`SELECT space_id FROM qivora_shared_space_members WHERE user_id=$1 AND status='active' LIMIT 1`, [userId]);
    if (existing.rowCount) { await client.query('ROLLBACK'); return { error: String(existing.rows[0].space_id) === String(invite.space_id) ? 'already-member' : 'user-in-other-space', status: 409 }; }
    await client.query(`INSERT INTO qivora_shared_space_members(space_id,user_id,role,status) VALUES($1,$2,'member','active') ON CONFLICT(space_id,user_id) DO UPDATE SET role='member',status='active',joined_at=NOW()`, [invite.space_id, userId]);
    await client.query(`UPDATE qivora_shared_email_invites SET accepted_at=NOW(),accepted_by=$1 WHERE id=$2 AND accepted_at IS NULL`, [userId, invite.id]);
    await client.query('COMMIT');
    return { ok: true, membershipStatus: 'accepted', space: { id: invite.space_id, name: invite.name, role: 'member' } };
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
  finally { client.release(); }
}

module.exports = { createInvite, removeUndeliveredInvite, listInvites, revokeInvite, acceptInvite, normalizeEmail, validEmail, tokenHash };
