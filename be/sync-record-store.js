/* QIVORA record-level sync store.
 * PostgreSQL-backed, transactionally ordered per-user change log.
 * Does not alter or replace legacy snapshot sync.
 */
'use strict';

const DEFAULT_COLLECTIONS = Object.freeze([
  'qv_records', 'qv_accounts', 'qv_transfers', 'qv_recurring', 'qv_goals', 'qv_budgets', 'qv_category_budgets'
]);
const MAX_BATCH = 100;
const MAX_RECORD_BYTES = 64 * 1024;
const MAX_PULL_LIMIT = 500;

function httpError(status, code) {
  const error = new Error(code);
  error.status = status;
  error.code = code;
  return error;
}
function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function validateOperation(input, allowedCollections = DEFAULT_COLLECTIONS) {
  if (!isPlainObject(input)) throw httpError(400, 'invalid-operation');
  const opId = String(input.opId || '');
  const collection = String(input.collection || '');
  const recordId = String(input.recordId || '');
  if (opId.length < 8 || opId.length > 128) throw httpError(400, 'invalid-operation-id');
  if (!allowedCollections.includes(collection)) throw httpError(400, 'unsupported-collection');
  if (!recordId || recordId.length > 256) throw httpError(400, 'invalid-record-id');
  if (!Number.isSafeInteger(input.baseVersion) || input.baseVersion < 0) throw httpError(400, 'invalid-base-version');
  if (typeof input.deleted !== 'boolean') throw httpError(400, 'invalid-delete-flag');
  if (input.deleted) {
    if (input.data !== null && input.data !== undefined) throw httpError(400, 'deleted-record-must-not-have-data');
  } else {
    if (!isPlainObject(input.data) || String(input.data.id) !== recordId) throw httpError(400, 'invalid-record-data');
    if (Buffer.byteLength(JSON.stringify(input.data), 'utf8') > MAX_RECORD_BYTES) throw httpError(413, 'record-too-large');
  }
  return {
    opId, collection, recordId,
    baseVersion: input.baseVersion,
    deleted: input.deleted,
    data: input.deleted ? null : input.data
  };
}
function validateBatch(operations, allowedCollections = DEFAULT_COLLECTIONS) {
  if (!Array.isArray(operations) || operations.length < 1 || operations.length > MAX_BATCH) {
    throw httpError(400, 'invalid-operation-batch');
  }
  const seen = new Set();
  return operations.map(raw => {
    const op = validateOperation(raw, allowedCollections);
    if (seen.has(op.opId)) throw httpError(400, 'duplicate-operation-id-in-batch');
    seen.add(op.opId);
    return op;
  });
}
function stableJson(value) {
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  if (isPlainObject(value)) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k)+':'+stableJson(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
function safeInteger(value, code = 'cursor-out-of-range') {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw httpError(400, code);
  return n;
}

async function pushChanges(pool, userId, rawOperations, options = {}) {
  const operations = validateBatch(rawOperations);
  const ownsClient = !options.client;
  const client = options.client || await pool.connect();
  const manageTransaction = options.transactionActive !== true;
  const accepted = [];
  const duplicates = [];
  try {
    if (manageTransaction) await client.query('BEGIN');
    if (options.requireRecordMode) {
      const protocol = await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR SHARE', [userId]);
      if (protocol.rows[0]?.records_mode !== 'record') throw httpError(409, 'record-sync-not-enabled');
    }
    await client.query(
      'INSERT INTO qivora_sync_cursors(user_id,last_cursor) VALUES($1,0) ON CONFLICT(user_id) DO NOTHING',
      [userId]
    );
    const cursorRow = await client.query(
      'SELECT last_cursor FROM qivora_sync_cursors WHERE user_id=$1 FOR UPDATE',
      [userId]
    );
    let lastCursor = safeInteger(cursorRow.rows[0]?.last_cursor ?? 0);

    for (const op of operations) {
      const prior = await client.query(
        'SELECT result FROM qivora_sync_operations WHERE user_id=$1 AND operation_id=$2',
        [userId, op.opId]
      );
      if (prior.rowCount) {
        const priorResult = prior.rows[0].result;
        const request = { collection: op.collection, recordId: op.recordId, baseVersion: op.baseVersion, deleted: op.deleted, data: op.data };
        if (!priorResult.request || stableJson(priorResult.request) !== stableJson(request)) {
          if (manageTransaction) await client.query('ROLLBACK');
          return {
            conflict: true,
            reason: 'idempotency-key-reused',
            operationId: op.opId,
            collection: op.collection,
            recordId: op.recordId
          };
        }
        const { request: _internalRequest, ...publicResult } = priorResult;
        duplicates.push(publicResult);
        continue;
      }

      const currentResult = await client.query(
        `SELECT version,deleted,data FROM qivora_sync_records
         WHERE user_id=$1 AND collection=$2 AND record_id=$3 FOR UPDATE`,
        [userId, op.collection, op.recordId]
      );
      const current = currentResult.rows[0] || { version: 0, deleted: false, data: null };
      const currentVersion = safeInteger(current.version ?? 0, 'record-version-out-of-range');
      if (currentVersion !== op.baseVersion) {
        if (manageTransaction) await client.query('ROLLBACK');
        return {
          conflict: true,
          operationId: op.opId,
          collection: op.collection,
          recordId: op.recordId,
          expectedVersion: op.baseVersion,
          current: {
            version: currentVersion,
            deleted: Boolean(current.deleted),
            data: current.deleted ? null : current.data
          }
        };
      }

      const nextVersion = currentVersion + 1;
      lastCursor += 1;
      const change = {
        cursor: lastCursor,
        operationId: op.opId,
        collection: op.collection,
        recordId: op.recordId,
        version: nextVersion,
        deleted: op.deleted,
        data: op.deleted ? null : op.data
      };

      await client.query(
        `INSERT INTO qivora_sync_records(user_id,collection,record_id,version,deleted,data,updated_at)
         VALUES($1,$2,$3,$4,$5,$6::jsonb,NOW())
         ON CONFLICT(user_id,collection,record_id) DO UPDATE SET
           version=EXCLUDED.version, deleted=EXCLUDED.deleted, data=EXCLUDED.data, updated_at=NOW()`,
        [userId, op.collection, op.recordId, nextVersion, op.deleted, op.deleted ? null : JSON.stringify(op.data)]
      );
      await client.query(
        `INSERT INTO qivora_sync_changes(user_id,cursor,operation_id,collection,record_id,version,deleted,data,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW())`,
        [userId, lastCursor, op.opId, op.collection, op.recordId, nextVersion, op.deleted, op.deleted ? null : JSON.stringify(op.data)]
      );
      await client.query(
        `INSERT INTO qivora_sync_operations(user_id,operation_id,result,created_at)
         VALUES($1,$2,$3::jsonb,NOW())`,
        [userId, op.opId, JSON.stringify({
          ...change, ok: true,
          request: { collection: op.collection, recordId: op.recordId, baseVersion: op.baseVersion, deleted: op.deleted, data: op.data }
        })]
      );
      accepted.push(change);
    }

    if (accepted.length) {
      await client.query(
        'UPDATE qivora_sync_cursors SET last_cursor=$2,updated_at=NOW() WHERE user_id=$1',
        [userId, lastCursor]
      );
      // PostgreSQL delivers NOTIFY only after this transaction commits.
      await client.query(
        'SELECT pg_notify($1,$2)',
        ['qivora_sync_updates', JSON.stringify({ userId: String(userId), cursor: lastCursor, kind: 'record-changes' })]
      );
    }
    if (manageTransaction) await client.query('COMMIT');
    return { ok: true, accepted, duplicates, cursor: lastCursor };
  } catch (error) {
    if (manageTransaction) await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    if (ownsClient) client.release();
  }
}

async function pullChanges(pool, userId, rawCursor, rawLimit = 200, options = {}) {
  const cursor = safeInteger(rawCursor);
  const limit = Math.min(MAX_PULL_LIMIT, Math.max(1, safeInteger(rawLimit, 'invalid-limit') || 200));
  const client = options.requireRecordMode ? await pool.connect() : null;
  const executor = client || pool;
  try {
    if (client) {
      await client.query('BEGIN');
      const protocol = await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR SHARE', [userId]);
      if (protocol.rows[0]?.records_mode !== 'record') throw httpError(409, 'record-sync-not-enabled');
    }
    const result = await executor.query(
      `SELECT cursor,operation_id,collection,record_id,version,deleted,data,created_at
       FROM qivora_sync_changes
       WHERE user_id=$1 AND cursor>$2
       ORDER BY cursor ASC
       LIMIT $3`,
      [userId, cursor, limit + 1]
    );
    const hasMore = result.rows.length > limit;
    const rows = hasMore ? result.rows.slice(0, limit) : result.rows;
    const changes = rows.map(row => ({
      cursor: safeInteger(row.cursor),
      operationId: row.operation_id,
      collection: row.collection,
      recordId: row.record_id,
      version: safeInteger(row.version, 'record-version-out-of-range'),
      deleted: Boolean(row.deleted),
      data: row.deleted ? null : row.data,
      createdAt: row.created_at
    }));
    const current = await executor.query(
      'SELECT last_cursor FROM qivora_sync_cursors WHERE user_id=$1',
      [userId]
    );
    const serverCursor = safeInteger(current.rows[0]?.last_cursor ?? 0);
    if (client) await client.query('COMMIT');
    return {
      ok: true,
      changes,
      cursor: changes.length ? changes[changes.length - 1].cursor : cursor,
      serverCursor,
      hasMore
    };
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    if (client) client.release();
  }
}


const SNAPSHOT_MIGRATION_KEY = 'snapshot-to-qv-records-v1';
function validateSnapshotRecords(records) {
  if (!Array.isArray(records)) throw httpError(409, 'snapshot-records-not-array');
  const seen = new Set();
  for (const record of records) {
    if (!isPlainObject(record) || record.id === undefined || record.id === null || String(record.id).trim() === '') {
      throw httpError(409, 'snapshot-record-invalid');
    }
    const id = String(record.id);
    if (id.length > 256) throw httpError(409, 'snapshot-record-id-too-long');
    if (seen.has(id)) throw httpError(409, 'snapshot-record-duplicate-id');
    seen.add(id);
    if (Buffer.byteLength(JSON.stringify(record), 'utf8') > MAX_RECORD_BYTES) throw httpError(413, 'record-too-large');
  }
  return records;
}

/*
 * One-time, revision-guarded bootstrap of qv_records from the legacy snapshot.
 * This intentionally does not activate record sync or modify the snapshot.
 */
async function migrateSnapshotRecords(pool, userId, expectedRevision) {
  const revision = safeInteger(expectedRevision, 'snapshot-revision-required');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const snapshotResult = await client.query(
      'SELECT data,revision FROM qivora_sync_state WHERE user_id=$1 FOR UPDATE', [userId]
    );
    if (!snapshotResult.rowCount) throw httpError(404, 'user-state-not-found');
    const snapshot = snapshotResult.rows[0];
    const actualRevision = safeInteger(snapshot.revision, 'snapshot-revision-out-of-range');

    const prior = await client.query(
      'SELECT migration_id,snapshot_revision,record_count,cursor_start,cursor_end,baseline_records FROM qivora_sync_migrations WHERE user_id=$1 AND migration_key=$2 FOR UPDATE',
      [userId, SNAPSHOT_MIGRATION_KEY]
    );
    if (prior.rowCount) {
      const row = prior.rows[0];
      if (safeInteger(row.snapshot_revision) !== revision) {
        await client.query('ROLLBACK');
        return { conflict: true, reason: 'migration-already-completed', snapshotRevision: Number(row.snapshot_revision) };
      }
      await client.query('COMMIT');
      const baselineRecords = Array.isArray(row.baseline_records) ? row.baseline_records : [];
      return {
        ok: true, alreadyMigrated: true, migrationId: row.migration_id,
        snapshotRevision: Number(row.snapshot_revision), recordCount: Number(row.record_count),
        cursorStart: Number(row.cursor_start), cursor: Number(row.cursor_end),
        baselineRecords, versions: Object.fromEntries(baselineRecords.map(record => [String(record.id), 1]))
      };
    }

    if (actualRevision !== revision) {
      await client.query('ROLLBACK');
      return { conflict: true, reason: 'snapshot-revision-conflict', expectedRevision: revision, actualRevision };
    }

    const data = snapshot.data && typeof snapshot.data === 'object' && !Array.isArray(snapshot.data) ? snapshot.data : {};
    const records = validateSnapshotRecords(data.qv_records ?? []);
    const existing = await client.query(
      'SELECT COUNT(*)::int AS count FROM qivora_sync_records WHERE user_id=$1 AND collection=$2',
      [userId, 'qv_records']
    );
    if (Number(existing.rows[0]?.count || 0) > 0) {
      await client.query('ROLLBACK');
      return { conflict: true, reason: 'record-store-not-empty' };
    }

    await client.query(
      'INSERT INTO qivora_sync_cursors(user_id,last_cursor) VALUES($1,0) ON CONFLICT(user_id) DO NOTHING', [userId]
    );
    const cursorResult = await client.query(
      'SELECT last_cursor FROM qivora_sync_cursors WHERE user_id=$1 FOR UPDATE', [userId]
    );
    let cursor = safeInteger(cursorResult.rows[0]?.last_cursor ?? 0);
    const cursorStart = records.length ? cursor + 1 : cursor;
    const migrationId = require('crypto').randomUUID();

    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      const recordId = String(record.id);
      cursor += 1;
      const operationId = `migration:${migrationId}:${index}`;
      await client.query(
        `INSERT INTO qivora_sync_records(user_id,collection,record_id,version,deleted,data,updated_at)
         VALUES($1,'qv_records',$2,1,FALSE,$3::jsonb,NOW())`,
        [userId, recordId, JSON.stringify(record)]
      );
      await client.query(
        `INSERT INTO qivora_sync_changes(user_id,cursor,operation_id,collection,record_id,version,deleted,data,created_at)
         VALUES($1,$2,$3,'qv_records',$4,1,FALSE,$5::jsonb,NOW())`,
        [userId, cursor, operationId, recordId, JSON.stringify(record)]
      );
    }

    await client.query(
      'UPDATE qivora_sync_cursors SET last_cursor=$2,updated_at=NOW() WHERE user_id=$1', [userId, cursor]
    );
    await client.query(
      `INSERT INTO qivora_sync_migrations(user_id,migration_key,migration_id,snapshot_revision,record_count,cursor_start,cursor_end,baseline_records,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW())`,
      [userId, SNAPSHOT_MIGRATION_KEY, migrationId, revision, records.length, cursorStart, cursor, JSON.stringify(records)]
    );
    if (records.length) {
      await client.query('SELECT pg_notify($1,$2)', [
        'qivora_sync_updates', JSON.stringify({ userId: String(userId), cursor, kind: 'snapshot-record-migration' })
      ]);
    }
    await client.query('COMMIT');
    return {
      ok: true, alreadyMigrated: false, migrationId, snapshotRevision: revision,
      recordCount: records.length, cursorStart, cursor,
      baselineRecords: records,
      versions: Object.fromEntries(records.map(record => [String(record.id), 1]))
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function getBootstrapState(pool, userId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const protocol = await client.query(
      'SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 FOR SHARE', [userId]
    );
    if (protocol.rows[0]?.records_mode !== 'record') throw httpError(409, 'record-sync-not-enabled');
    const migration = await client.query(
      "SELECT migration_id FROM qivora_sync_migrations WHERE user_id=$1 AND migration_key=$2",
      [userId, SNAPSHOT_MIGRATION_KEY]
    );
    if (!migration.rowCount) throw httpError(409, 'snapshot-migration-required');
    // Writers lock this row FOR UPDATE before allocating cursors. Holding FOR SHARE
    // makes the records and cursor a consistent bootstrap snapshot.
    const cursorResult = await client.query(
      'SELECT last_cursor FROM qivora_sync_cursors WHERE user_id=$1 FOR SHARE', [userId]
    );
    const recordsResult = await client.query(
      `SELECT record_id,version,deleted,data FROM qivora_sync_records
       WHERE user_id=$1 AND collection=$2 ORDER BY record_id ASC`, [userId, 'qv_records']
    );
    const records = recordsResult.rows.filter(row => !row.deleted).map(row => row.data);
    const tombstones = recordsResult.rows.filter(row => row.deleted).map(row => ({ recordId: String(row.record_id), version: safeInteger(row.version, 'record-version-out-of-range') }));
    const versions = Object.fromEntries(recordsResult.rows.map(row => [String(row.record_id), safeInteger(row.version, 'record-version-out-of-range')]));
    const cursor = safeInteger(cursorResult.rows[0]?.last_cursor ?? 0);
    await client.query('COMMIT');
    return { ok: true, records, versions, tombstones, cursor, recordCount: records.length };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

module.exports = {
  DEFAULT_COLLECTIONS, MAX_BATCH, MAX_RECORD_BYTES, MAX_PULL_LIMIT,
  validateOperation, validateBatch, pushChanges, pullChanges,
  SNAPSHOT_MIGRATION_KEY, validateSnapshotRecords, migrateSnapshotRecords, getBootstrapState
};
