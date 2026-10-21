import {existsSync,lstatSync,readdirSync,statSync,truncateSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';

const reportPattern=/^ssh_(?:reporte|eventos)_[A-Za-z0-9_-]+\.(?:txt|csv)$/;
const logPattern=/^(?:server-v\d+-[\d-]+(?:\.err)?|(?:forwarding|puertos)-[\d-]+(?:\.error)?)\.log$/;

export function validateReset(reset){
  if(!reset)return null;
  if(typeof reset!=='object'||!/^[a-f0-9]{32}$/.test(reset.id||'')||!Number.isSafeInteger(reset.cutoff)||reset.cutoff<=0)
    throw new Error('El servidor devolvió un marcador de limpieza inválido.');
  return {id:reset.id,cutoff:reset.cutoff,completed_at:reset.completed_at};
}

export function createHistoryStore({db,dataDir,reportDir,stateValue,saveState,onReset}){
  let generation=0,warnings=[];
  function matched(dir,pattern){
    if(!dir||!existsSync(dir)||lstatSync(dir).isSymbolicLink())return [];
    return readdirSync(dir).filter(name=>pattern.test(name)).map(name=>join(dir,name))
      .filter(path=>{const info=lstatSync(path);return info.isFile()&&!info.isSymbolicLink()&&info.nlink===1;});
  }
  function storage(){
    let bytes=0;
    for(const name of ['storypulse.db','storypulse.db-wal','storypulse.db-shm']){
      const path=join(dataDir,name);if(existsSync(path))bytes+=statSync(path).size;
    }
    const logs=matched(dataDir,logPattern),reports=matched(reportDir,reportPattern);
    const fileBytes=[...logs,...reports].reduce((sum,path)=>sum+statSync(path).size,0);
    const outgoing=db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='outgoing_events'").get()?db.prepare('SELECT COUNT(*) count FROM outgoing_events').get().count:0;
    return {database_bytes:bytes,files_bytes:fileBytes,total_bytes:bytes+fileBytes,
      events:db.prepare('SELECT COUNT(*) count FROM events').get().count+outgoing,outgoing_events:outgoing,warnings};
  }
  function pruneFiles(){
    for(const path of matched(dataDir,logPattern)){
      try{truncateSync(path,0);}catch{warnings.push('Un archivo de diagnÃ³stico local estÃ¡ en uso.');}
    }
    for(const path of matched(reportDir,reportPattern)){
      try{unlinkSync(path);}catch{warnings.push('No se pudo eliminar un reporte SSH descargado.');}
    }
  }
  function applyReset(value){
    const reset=validateReset(value);
    if(!reset||stateValue('cleanup_reset',null)?.id===reset.id)return false;
    generation++;onReset();warnings=[];
    db.exec('BEGIN IMMEDIATE');
    try{
      if(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='notifications'").get())db.exec('DELETE FROM notifications');
      if(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='outgoing_events'").get())db.exec('DELETE FROM outgoing_events');
      if(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='panel_alert_outbox'").get())db.exec('DELETE FROM panel_alert_outbox');
      db.exec("DELETE FROM events; DELETE FROM geo_cache; DELETE FROM block_audit; DELETE FROM state WHERE key NOT IN ('geo_backend_version');");
      saveState('last_remote_timestamp',reset.cutoff);saveState('cleanup_reset',reset);
      db.exec('COMMIT');
    }catch(error){db.exec('ROLLBACK');throw error;}
    // VACUUM releases the free pages; DELETE by itself would keep the large DB.
    db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');
    pruneFiles();
    return true;
  }
  return {storage,applyReset,pruneFiles,generation:()=>generation};
}
