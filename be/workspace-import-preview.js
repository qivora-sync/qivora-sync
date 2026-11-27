/* Read-only preview for copying personal QIVORA data into a shared workspace.
 * No source rows are modified. Conflicting IDs and malformed source data are reported.
 */
'use strict';
const crypto=require('crypto');
const RECORD_COLLECTIONS=['qv_records','qv_accounts','qv_transfers','qv_recurring','qv_goals'];
const SNAPSHOT_COLLECTIONS=['qv_budgets','qv_category_budgets'];
const ALL_COLLECTIONS=[...RECORD_COLLECTIONS,...SNAPSHOT_COLLECTIONS];
function httpError(status,code){const e=new Error(code);e.status=status;e.code=code;return e;}
function stable(v){
  if(Array.isArray(v)) return '['+v.map(stable).join(',')+']';
  if(v&&typeof v==='object') return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
  return JSON.stringify(v);
}
function digest(v){return crypto.createHash('sha256').update(stable(v)).digest('hex');}
function normalizeSnapshotCollection(collection,value,warnings,member){
  if(collection==='qv_budgets'||collection==='qv_category_budgets'){
    if(value===undefined||value===null)return [];
    if(!value||typeof value!=='object'||Array.isArray(value)){
      warnings.push({userId:member.userId,collection,reason:'invalid-collection-shape'});return [];
    }
    return Object.entries(value).map(([id,payload])=>({id:String(id),data:{id:String(id),value:payload}}));
  }
  if(value===undefined||value===null)return [];
  if(!Array.isArray(value)){
    warnings.push({userId:member.userId,collection,reason:'invalid-collection-shape'});return [];
  }
  const out=[];
  for(let i=0;i<value.length;i++){
    const item=value[i];
    if(!item||typeof item!=='object'||Array.isArray(item)||item.id===undefined||item.id===null||String(item.id).trim()===''){
      warnings.push({userId:member.userId,collection,index:i,reason:'invalid-record-identity'});continue;
    }
    out.push({id:String(item.id),data:item});
  }
  return out;
}
async function buildPreview(client,spaceId,ownerId,lockForImport=false){
    await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
    const owner=await client.query(`SELECT role FROM qivora_shared_space_members
      WHERE space_id=$1 AND user_id=$2 AND status='active' ${lockForImport?'FOR SHARE':''}`,[spaceId,ownerId]);
    if(!owner.rowCount||owner.rows[0].role!=='owner') throw httpError(403,'workspace-owner-required');
    const members=await client.query(`SELECT m.user_id,m.role,u.email FROM qivora_shared_space_members m
      JOIN qivora_users u ON u.id=m.user_id WHERE m.space_id=$1 AND m.status='active'
      ORDER BY m.joined_at,m.user_id ${lockForImport?'FOR SHARE OF m':''}`,[spaceId]);
    const warnings=[],all=[];
    for(const member of members.rows){
      const protocol=await client.query(`SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1 ${lockForImport?'FOR SHARE':''}`,[member.user_id]);
      const mode=protocol.rows[0]?.records_mode==='record'?'record':'snapshot';
      const snapshot=await client.query('SELECT data FROM qivora_sync_state WHERE user_id=$1 FOR SHARE',[member.user_id]);
      if(!snapshot.rowCount) warnings.push({userId:String(member.user_id),reason:'personal-snapshot-missing'});
      const snapshotData=snapshot.rows[0]?.data&&typeof snapshot.rows[0].data==='object'?snapshot.rows[0].data:{};
      const collections={};
      for(const collection of ALL_COLLECTIONS){
        if(RECORD_COLLECTIONS.includes(collection)&&mode==='record'){
          const r=await client.query(`SELECT record_id,data FROM qivora_sync_records
            WHERE user_id=$1 AND collection=$2 AND deleted=FALSE ORDER BY record_id FOR SHARE`,[member.user_id,collection]);
          collections[collection]=r.rows.map(x=>({id:String(x.record_id),data:x.data}));
        }else{
          collections[collection]=normalizeSnapshotCollection(collection,snapshotData[collection],warnings,{userId:String(member.user_id)});
        }
      }
      all.push({userId:String(member.user_id),email:member.email,role:member.role,mode,collections});
    }
    const existing=await client.query(`SELECT collection,record_id,data,deleted,version,created_by,updated_by
      FROM qivora_workspace_sync_records WHERE space_id=$1 ORDER BY collection,record_id ${lockForImport?'FOR UPDATE':''}`,[spaceId]);
    const byKey=new Map();
    for(const row of existing.rows)byKey.set(`${row.collection}:${row.record_id}`,{
      data:row.data,deleted:Boolean(row.deleted),source:'workspace',version:Number(row.version),
      createdBy:String(row.created_by),updatedBy:String(row.updated_by)});
    const identical=[],conflicts=[],newRecords=[],seenSource=new Map();
    for(const member of all){
      for(const collection of ALL_COLLECTIONS){
        for(const rec of member.collections[collection]){
          const key=`${collection}:${rec.id}`;
          if(!rec.data||typeof rec.data!=='object'||Array.isArray(rec.data)||String(rec.data.id)!==rec.id){
            warnings.push({userId:member.userId,collection,id:rec.id,reason:'invalid-record-data'});continue;
          }
          const sourceKey=`${member.userId}:${key}`;
          if(seenSource.has(sourceKey)){
            conflicts.push({collection,id:rec.id,reason:'duplicate-id-within-source',sourceUserId:member.userId});continue;
          }
          seenSource.set(sourceKey,true);
          const prev=byKey.get(key);
          if(!prev){byKey.set(key,{data:rec.data,source:member.userId});newRecords.push({collection,id:rec.id,sourceUserId:member.userId,contentHash:digest(rec.data)});}
          else if(prev.deleted){conflicts.push({collection,id:rec.id,reason:'workspace-record-is-deleted',sourceUserId:member.userId});}
          else if(digest(prev.data)===digest(rec.data)){identical.push({collection,id:rec.id,sourceUserId:member.userId,existingSource:prev.source});}
          else conflicts.push({collection,id:rec.id,reason:'same-id-different-content',sourceUserId:member.userId,existingSource:prev.source});
        }
      }
    }
    const counts={};
    for(const collection of ALL_COLLECTIONS)counts[collection]=all.reduce((n,m)=>n+m.collections[collection].length,0);
    const summary={members:all.map(m=>({userId:m.userId,email:m.email,role:m.role,mode:m.mode})),
      collections:counts,totalPersonalRecords:Object.values(counts).reduce((a,b)=>a+b,0),newRecords:newRecords.length,
      identicalDuplicates:identical.length,conflicts:conflicts.length,warnings:warnings.length,
      existingWorkspaceRecords:existing.rows.filter(x=>!x.deleted).length};
    const planHash=digest({spaceId,summary,members:all.map(m=>({userId:m.userId,mode:m.mode,
      collections:Object.fromEntries(ALL_COLLECTIONS.map(c=>[c,m.collections[c].map(r=>({id:r.id,hash:digest(r.data)}))]))})),
      existing:existing.rows.map(x=>({collection:x.collection,id:x.record_id,version:Number(x.version),deleted:Boolean(x.deleted),hash:x.deleted?null:digest(x.data)})),newRecords,identical,conflicts,warnings});
    return {ok:true,readOnly:true,planHash,summary,identicalDuplicates:identical,conflicts,warnings,
      safeToImport:conflicts.length===0&&warnings.length===0,
      collections:ALL_COLLECTIONS,newRecords,notice:'Попередній перегляд. Жодні дані не змінено.'};
}
async function previewPersonalRecords(pool,spaceId,ownerId){
  const client=await pool.connect();
  try{await client.query('BEGIN');const result=await buildPreview(client,spaceId,ownerId);await client.query('COMMIT');return result;}
  catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}
async function commitPersonalImport(pool,spaceId,ownerId,expectedPlanHash){
  if(typeof expectedPlanHash!=='string'||expectedPlanHash.length!==64)throw httpError(400,'invalid-plan-hash');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const preview=await buildPreview(client,spaceId,ownerId,true);
    if(preview.planHash!==expectedPlanHash)throw httpError(409,'import-plan-changed');
    if(!preview.safeToImport)throw httpError(409,'import-has-conflicts-or-warnings');
    await client.query(`INSERT INTO qivora_workspace_sync_cursors(space_id,last_cursor) VALUES($1,0) ON CONFLICT(space_id) DO NOTHING`,[spaceId]);
    const cursorRow=await client.query('SELECT last_cursor FROM qivora_workspace_sync_cursors WHERE space_id=$1 FOR UPDATE',[spaceId]);
    let cursor=Number(cursorRow.rows[0]?.last_cursor||0);
    const sourceData=new Map();
    // Re-read source data inside the same repeatable-read transaction; preview locked these rows.
    for(const member of preview.summary.members){
      const protocol=await client.query('SELECT records_mode FROM qivora_sync_protocol WHERE user_id=$1',[member.userId]);
      const mode=protocol.rows[0]?.records_mode==='record'?'record':'snapshot';
      const snap=await client.query('SELECT data FROM qivora_sync_state WHERE user_id=$1',[member.userId]);
      const data=snap.rows[0]?.data||{};
      for(const collection of ALL_COLLECTIONS){
        let items=[];
        if(RECORD_COLLECTIONS.includes(collection)&&mode==='record'){
          const q=await client.query(`SELECT record_id,data FROM qivora_sync_records WHERE user_id=$1 AND collection=$2 AND deleted=FALSE ORDER BY record_id`,[member.userId,collection]);
          items=q.rows.map(x=>({id:String(x.record_id),data:x.data}));
        }else items=normalizeSnapshotCollection(collection,data[collection],[],{userId:member.userId});
        for(const item of items)sourceData.set(`${member.userId}:${collection}:${item.id}`,{...item,sourceUserId:member.userId});
      }
    }
    const imported=[];
    for(const item of preview.newRecords){
      const source=sourceData.get(`${item.sourceUserId}:${item.collection}:${item.id}`);
      if(!source||digest(source.data)!==item.contentHash)throw httpError(409,'import-source-changed');
      cursor+=1;const operationId=`import-${crypto.randomUUID()}`;
      await client.query(`INSERT INTO qivora_workspace_sync_records(space_id,collection,record_id,version,deleted,data,created_by,updated_by,updated_at)
        VALUES($1,$2,$3,1,FALSE,$4::jsonb,$5,$6,NOW())`,[spaceId,item.collection,item.id,JSON.stringify(source.data),source.sourceUserId,ownerId]);
      await client.query(`INSERT INTO qivora_workspace_sync_changes(space_id,cursor,operation_id,collection,record_id,version,deleted,data,actor_id,created_by,created_at)
        VALUES($1,$2,$3,$4,$5,1,FALSE,$6::jsonb,$7,$8,NOW())`,[spaceId,cursor,operationId,item.collection,item.id,JSON.stringify(source.data),ownerId,source.sourceUserId]);
      await client.query(`INSERT INTO qivora_workspace_sync_operations(space_id,operation_id,result) VALUES($1,$2,$3::jsonb)`,[spaceId,operationId,JSON.stringify({ok:true,imported:true,collection:item.collection,recordId:item.id,version:1,createdBy:source.sourceUserId,updatedBy:ownerId})]);
      imported.push({collection:item.collection,id:item.id,sourceUserId:source.sourceUserId});
    }
    if(imported.length){
      await client.query('UPDATE qivora_workspace_sync_cursors SET last_cursor=$2,updated_at=NOW() WHERE space_id=$1',[spaceId,cursor]);
      await client.query('SELECT pg_notify($1,$2)',['qivora_sync_updates',JSON.stringify({workspaceId:String(spaceId),cursor,kind:'workspace-record-changes'})]);
    }
    await client.query('COMMIT');
    return {ok:true,imported:imported.length,records:imported,cursor,planHash:preview.planHash,sourcePreserved:true};
  }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}
module.exports={previewPersonalRecords,commitPersonalImport,ALL_COLLECTIONS,RECORD_COLLECTIONS,SNAPSHOT_COLLECTIONS};
