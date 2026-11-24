/* QIVORA workspace-scoped record sync.
 * Separate tables keep personal sync isolated. Every operation verifies active membership.
 */
'use strict';
const Base = require('./sync-record-store');
const crypto = require('crypto');
const { validateBatch, MAX_PULL_LIMIT } = Base;

function httpError(status, code) { const e = new Error(code); e.status=status; e.code=code; return e; }
function safeInt(value, code='cursor-out-of-range') {
  const n=Number(value); if(!Number.isSafeInteger(n)||n<0) throw httpError(400,code); return n;
}
function stable(value) {
  if(Array.isArray(value)) return '['+value.map(stable).join(',')+']';
  if(value && typeof value==='object') return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
async function assertMember(client, spaceId, userId, lock=false) {
  const r=await client.query(
    `SELECT role FROM qivora_shared_space_members
     WHERE space_id=$1 AND user_id=$2 AND status='active' ${lock?'FOR SHARE':''}`,
    [spaceId,userId]
  );
  if(!r.rowCount) throw httpError(403,'workspace-membership-required');
  return r.rows[0].role;
}
async function pushChanges(pool, spaceId, actorId, rawOps) {
  const ops=validateBatch(rawOps);
  const client=await pool.connect(), accepted=[],duplicates=[];
  try {
    await client.query('BEGIN');
    await assertMember(client,spaceId,actorId,true);
    await client.query(`INSERT INTO qivora_workspace_sync_cursors(space_id,last_cursor)
      VALUES($1,0) ON CONFLICT(space_id) DO NOTHING`,[spaceId]);
    const c=await client.query('SELECT last_cursor FROM qivora_workspace_sync_cursors WHERE space_id=$1 FOR UPDATE',[spaceId]);
    let cursor=safeInt(c.rows[0]?.last_cursor??0);
    for(const op of ops) {
      const prior=await client.query(`SELECT result FROM qivora_workspace_sync_operations
        WHERE space_id=$1 AND operation_id=$2`,[spaceId,op.opId]);
      const request={collection:op.collection,recordId:op.recordId,baseVersion:op.baseVersion,deleted:op.deleted,data:op.data};
      if(prior.rowCount) {
        if(!prior.rows[0].result.request || stable(prior.rows[0].result.request)!==stable(request)) {
          await client.query('ROLLBACK');
          return {conflict:true,reason:'idempotency-key-reused',operationId:op.opId};
        }
        const {request:_internal,...publicResult}=prior.rows[0].result;
        duplicates.push(publicResult); continue;
      }
      const currentResult=await client.query(`SELECT version,deleted,data,created_by,updated_by
        FROM qivora_workspace_sync_records WHERE space_id=$1 AND collection=$2 AND record_id=$3 FOR UPDATE`,
        [spaceId,op.collection,op.recordId]);
      const current=currentResult.rows[0]||{version:0,deleted:false,data:null};
      const version=safeInt(current.version??0,'record-version-out-of-range');
      if(version!==op.baseVersion) {
        await client.query('ROLLBACK');
        return {conflict:true,operationId:op.opId,collection:op.collection,recordId:op.recordId,
          expectedVersion:op.baseVersion,current:{version,deleted:Boolean(current.deleted),data:current.deleted?null:current.data}};
      }
      const next=version+1; cursor+=1;
      const createdBy=current.created_by||actorId;
      const change={cursor,operationId:op.opId,collection:op.collection,recordId:op.recordId,
        version:next,deleted:op.deleted,data:op.deleted?null:op.data,
        createdBy:String(createdBy),updatedBy:String(actorId)};
      await client.query(`INSERT INTO qivora_workspace_sync_records
        (space_id,collection,record_id,version,deleted,data,created_by,updated_by,updated_at)
        VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,NOW())
        ON CONFLICT(space_id,collection,record_id) DO UPDATE SET
        version=EXCLUDED.version,deleted=EXCLUDED.deleted,data=EXCLUDED.data,
        updated_by=EXCLUDED.updated_by,updated_at=NOW()`,
        [spaceId,op.collection,op.recordId,next,op.deleted,op.deleted?null:JSON.stringify(op.data),createdBy,actorId]);
      await client.query(`INSERT INTO qivora_workspace_sync_changes
        (space_id,cursor,operation_id,collection,record_id,version,deleted,data,actor_id,created_by,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,NOW())`,
        [spaceId,cursor,op.opId,op.collection,op.recordId,next,op.deleted,op.deleted?null:JSON.stringify(op.data),actorId,createdBy]);
      await client.query(`INSERT INTO qivora_workspace_sync_operations(space_id,operation_id,result)
        VALUES($1,$2,$3::jsonb)`,
        [spaceId,op.opId,JSON.stringify({...change,ok:true,request})]);
      accepted.push(change);
    }
    if(accepted.length) {
      await client.query('UPDATE qivora_workspace_sync_cursors SET last_cursor=$2,updated_at=NOW() WHERE space_id=$1',[spaceId,cursor]);
      await client.query('SELECT pg_notify($1,$2)',['qivora_sync_updates',
        JSON.stringify({workspaceId:String(spaceId),cursor,kind:'workspace-record-changes'})]);
    }
    await client.query('COMMIT');
    return {ok:true,accepted,duplicates,cursor};
  } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
  finally { client.release(); }
}
async function pullChanges(pool,spaceId,userId,rawCursor,rawLimit=200) {
  const cursor=safeInt(rawCursor), limit=Math.min(MAX_PULL_LIMIT,Math.max(1,safeInt(rawLimit,'invalid-limit')||200));
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    await assertMember(client,spaceId,userId,true);
    const r=await client.query(`SELECT cursor,operation_id,collection,record_id,version,deleted,data,
      actor_id,created_by,created_at FROM qivora_workspace_sync_changes
      WHERE space_id=$1 AND cursor>$2 ORDER BY cursor LIMIT $3`,[spaceId,cursor,limit+1]);
    const hasMore=r.rows.length>limit, rows=hasMore?r.rows.slice(0,limit):r.rows;
    const changes=rows.map(x=>({cursor:safeInt(x.cursor),operationId:x.operation_id,collection:x.collection,
      recordId:x.record_id,version:safeInt(x.version,'record-version-out-of-range'),deleted:Boolean(x.deleted),
      data:x.deleted?null:x.data,actorId:String(x.actor_id),createdBy:String(x.created_by),createdAt:x.created_at}));
    const c=await client.query('SELECT last_cursor FROM qivora_workspace_sync_cursors WHERE space_id=$1',[spaceId]);
    const serverCursor=safeInt(c.rows[0]?.last_cursor??0);
    await client.query('COMMIT');
    return {ok:true,changes,cursor:changes.length?changes[changes.length-1].cursor:cursor,serverCursor,hasMore};
  } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
  finally { client.release(); }
}
async function getBootstrap(pool,spaceId,userId) {
  const client=await pool.connect();
  try {
    await client.query('BEGIN'); await assertMember(client,spaceId,userId,true);
    const c=await client.query('SELECT last_cursor FROM qivora_workspace_sync_cursors WHERE space_id=$1',[spaceId]);
    const r=await client.query(`SELECT collection,record_id,version,deleted,data,created_by,updated_by
      FROM qivora_workspace_sync_records WHERE space_id=$1 ORDER BY collection,record_id`,[spaceId]);
    const records=r.rows.filter(x=>!x.deleted).map(x=>({collection:x.collection,id:x.record_id,
      version:safeInt(x.version),data:x.data,createdBy:String(x.created_by),updatedBy:String(x.updated_by)}));
    const tombstones=r.rows.filter(x=>x.deleted).map(x=>({collection:x.collection,recordId:x.record_id,version:safeInt(x.version)}));
    await client.query('COMMIT');
    return {ok:true,records,tombstones,cursor:safeInt(c.rows[0]?.last_cursor??0)};
  } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
  finally { client.release(); }
}
module.exports={pushChanges,pullChanges,getBootstrap,assertMember};
