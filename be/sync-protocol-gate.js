/* QIVORA protocol gate: one authoritative writer for qv_records per account. */
'use strict';

const RECORDS_COLLECTION = 'qv_records';
const ACTIVATION_CONFIRMATION = 'ENABLE_RECORD_SYNC_V1';
const ROLLBACK_CONFIRMATION = 'ROLLBACK_TO_SNAPSHOT_V1';

function stableJson(value) {
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key)+':'+stableJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function normalizedRecords(records) {
  return (Array.isArray(records) ? records : []).slice().sort((a,b) => String(a?.id).localeCompare(String(b?.id)));
}

async function getStatus(pool, userId) {
  const result = await pool.query(
    `SELECT p.records_mode,p.activated_at,p.updated_at,m.migration_id,m.snapshot_revision,m.record_count,m.cursor_end
     FROM (SELECT $1::uuid AS user_id) u
     LEFT JOIN qivora_sync_protocol p ON p.user_id=u.user_id
     LEFT JOIN qivora_sync_migrations m ON m.user_id=u.user_id AND m.migration_key='snapshot-to-qv-records-v1'`,
    [userId]
  );
  const row = result.rows[0] || {};
  return {
    ok: true,
    recordsMode: row.records_mode || 'snapshot',
    activatedAt: row.activated_at || null,
    updatedAt: row.updated_at || null,
    migration: row.migration_id ? {
      id: row.migration_id,
      snapshotRevision: Number(row.snapshot_revision),
      recordCount: Number(row.record_count),
      cursor: Number(row.cursor_end)
    } : null
  };
}

async function isRecordMode(pool, userId) {
  const result = await pool.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1', [userId]);
  return result.rows[0]?.records_mode === 'record';
}

async function activate(pool, userId, confirmation) {
  if (confirmation !== ACTIVATION_CONFIRMATION) {
    const error = new Error('explicit-protocol-activation-required'); error.status = 400; throw error;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const snapshot = await client.query('SELECT data,revision FROM qivora_sync_state WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!snapshot.rowCount) { await client.query('ROLLBACK'); const error = new Error('user-state-not-found'); error.status = 404; throw error; }
    const migration = await client.query(
      `SELECT migration_id,snapshot_revision,record_count,cursor_end
       FROM qivora_sync_migrations WHERE user_id=$1 AND migration_key='snapshot-to-qv-records-v1' FOR UPDATE`,
      [userId]
    );
    if (!migration.rowCount) {
      await client.query('ROLLBACK');
      const error = new Error('snapshot-migration-required'); error.status = 409; throw error;
    }
    const existing = await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR UPDATE', [userId]);
    if (existing.rows[0]?.records_mode === 'record') {
      await client.query('COMMIT');
      return { ok: true, recordsMode: 'record', alreadyEnabled: true };
    }
    const currentRecords = await client.query(
      `SELECT record_id,data FROM qivora_sync_records WHERE user_id=$1 AND collection=$2 AND deleted=FALSE`,
      [userId, RECORDS_COLLECTION]
    );
    const snapshotRecords = snapshot.rows[0].data?.qv_records ?? [];
    const recordStoreRecords = currentRecords.rows.map(row => row.data);
    if (stableJson(normalizedRecords(snapshotRecords)) !== stableJson(normalizedRecords(recordStoreRecords))) {
      await client.query('ROLLBACK');
      const error = new Error('snapshot-records-diverged-after-rollback'); error.status = 409; throw error;
    }
    await client.query(
      `INSERT INTO qivora_sync_protocol(user_id,records_mode,activated_at,updated_at)
       VALUES($1,'record',NOW(),NOW())
       ON CONFLICT(user_id) DO UPDATE SET records_mode='record',activated_at=NOW(),updated_at=NOW()`,
      [userId]
    );
    await client.query('COMMIT');
    const row = migration.rows[0];
    return { ok: true, recordsMode: 'record', migrationId: row.migration_id, recordCount: Number(row.record_count), cursor: Number(row.cursor_end) };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function rollback(pool, userId, confirmation) {
  if (confirmation !== ROLLBACK_CONFIRMATION) {
    const error = new Error('explicit-protocol-rollback-required'); error.status = 400; throw error;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const snapshot = await client.query('SELECT data,revision FROM qivora_sync_state WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!snapshot.rowCount) {
      await client.query('ROLLBACK');
      const error = new Error('user-state-not-found'); error.status = 404; throw error;
    }
    const protocol = await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR UPDATE', [userId]);
    if (protocol.rows[0]?.records_mode !== 'record') {
      await client.query('COMMIT');
      return { ok: true, recordsMode: 'snapshot', alreadyRolledBack: true };
    }
    const records = await client.query(
      `SELECT record_id,data FROM qivora_sync_records
       WHERE user_id=$1 AND collection=$2 AND deleted=FALSE ORDER BY record_id ASC`,
      [userId, RECORDS_COLLECTION]
    );
    const liveRecords = records.rows.map(row => row.data);
    const revision = Number(snapshot.rows[0].revision);
    await client.query(
      `UPDATE qivora_sync_state
       SET data=jsonb_set(COALESCE(data,'{}'::jsonb),'{qv_records}',$2::jsonb,TRUE),
           revision=revision+1,updated_at=NOW()
       WHERE user_id=$1`,
      [userId, JSON.stringify(liveRecords)]
    );
    await client.query(
      `UPDATE qivora_sync_protocol SET records_mode='snapshot',activated_at=NULL,updated_at=NOW() WHERE user_id=$1`,
      [userId]
    );
    const updated = await client.query('SELECT revision,updated_at FROM qivora_sync_state WHERE user_id=$1', [userId]);
    await client.query('SELECT pg_notify($1,$2)', ['qivora_sync_updates', JSON.stringify({ userId: String(userId), revision: Number(updated.rows[0].revision), kind: 'record-sync-rollback' })]);
    await client.query('COMMIT');
    return { ok: true, recordsMode: 'snapshot', restoredRecordCount: liveRecords.length, previousRevision: revision, revision: Number(updated.rows[0].revision), updatedAt: updated.rows[0].updated_at };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

module.exports = {
  RECORDS_COLLECTION, ACTIVATION_CONFIRMATION, ROLLBACK_CONFIRMATION,
  getStatus, isRecordMode, activate, rollback
};
