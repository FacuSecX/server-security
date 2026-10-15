/*
Server Security Monitor v2.0
Created by FacuSecX
https://github.com/FacuSecX/
*/
import {randomBytes} from 'node:crypto';
import {isIP} from 'node:net';

export function createNotifications(db,{isAuthorized=()=>false}={}) {
  db.exec(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL, service TEXT NOT NULL, ip TEXT NOT NULL,
    type TEXT NOT NULL, detail TEXT NOT NULL, read_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS notifications_unread_idx ON notifications(id) WHERE read_at IS NULL;`);
  if(!db.prepare('PRAGMA table_info(notifications)').all().some(column=>column.name==='deleted_at'))
    db.exec('ALTER TABLE notifications ADD COLUMN deleted_at INTEGER');
  db.exec('CREATE INDEX IF NOT EXISTS notifications_visible_idx ON notifications(id) WHERE deleted_at IS NULL');
  
  db.exec("DELETE FROM notifications WHERE type='connection'");
  db.exec('CREATE TABLE IF NOT EXISTS notification_identity(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL)');
  db.prepare('INSERT OR IGNORE INTO notification_identity VALUES(1,?)').run(randomBytes(16).toString('hex'));
  const inboxId=db.prepare('SELECT value FROM notification_identity WHERE id=1').get().value;
  const insert=db.prepare(`INSERT OR IGNORE INTO notifications
    (event_id,timestamp,service,ip,type,detail) VALUES(?,?,?,?,?,?)`);
  const allowedServices=new Set(['SSH','FTP','MySQL','MariaDB']);
  function ingest(event) {
    const alert=event.security_alert;
    if(!alert || !allowedServices.has(alert.service) || alert.type!=='login' ||
      typeof event.ip!=='string' || !isIP(event.ip) || !Number.isSafeInteger(event.timestamp) || event.timestamp<1 ||
      !/^[a-f0-9]{32}$/.test(event.id||''))return;
    const kinds={SSH:'ssh_success',FTP:'ftp_success',MySQL:'mysql_success',MariaDB:'mariadb_success'};
    if(event.kind!==kinds[alert.service]||isAuthorized(event.ip))return;
    const methods={publickey:'llave pública',password:'contraseña','keyboard-interactive/pam':'autenticación interactiva',
      'keyboard-interactive':'autenticación interactiva','gssapi-with-mic':'GSSAPI',hostbased:'hostbased',none:'sin método de autenticación'};
    const detail=alert.service==='SSH'?'Inicio de sesión SSH confirmado'+(methods[event.auth_method]?' mediante '+methods[event.auth_method]:'')+' desde una IP no autorizada.':
      event.auth_method==='session-observed'?'Sesión '+alert.service+' autenticada observada desde una IP no autorizada.':
      'Inicio de sesión '+alert.service+' confirmado desde una IP no autorizada.';
    insert.run(event.id,event.timestamp,alert.service,event.ip,alert.type,detail);
  }
  function snapshot(before=null) {
    if(before!==null && (!Number.isSafeInteger(before)||before<1))throw new Error('Cursor no válido.');
    const rows=db.prepare(`SELECT id,timestamp,service,ip,type,detail,read_at FROM notifications
      WHERE deleted_at IS NULL ${before===null?'':'AND id<?'} ORDER BY id DESC LIMIT 51`).all(...(before===null?[]:[before]));
    const more=rows.length>50;rows.length=Math.min(rows.length,50);
    return {inbox_id:inboxId,latest_notice_id:db.prepare('SELECT COALESCE(MAX(id),0) id FROM notifications WHERE deleted_at IS NULL').get().id,items:rows,unread:db.prepare('SELECT COUNT(*) count FROM notifications WHERE read_at IS NULL AND deleted_at IS NULL').get().count,
      read_count:db.prepare('SELECT COUNT(*) count FROM notifications WHERE read_at IS NOT NULL AND deleted_at IS NULL').get().count,
      through_id:db.prepare('SELECT COALESCE(MAX(id),0) id FROM notifications').get().id,
      next_before:more?rows.at(-1).id:null};
  }
  function markRead(body) {
    if(!body || Array.isArray(body) || typeof body!=='object')throw new Error('Solicitud no válida.');
    const keys=Object.keys(body);
    if(keys.length!==1 || !['id','through_id'].includes(keys[0]) ||
      !Number.isSafeInteger(body[keys[0]]) || body[keys[0]]<0 || (keys[0]==='id'&&body.id===0))
      throw new Error('Indicá una notificación o el último identificador recibido.');
    const query=keys[0]==='id'?'id=?':'id<=?';
    db.prepare(`UPDATE notifications SET read_at=? WHERE read_at IS NULL AND deleted_at IS NULL AND ${query}`)
      .run(Math.floor(Date.now()/1000),body[keys[0]]);
  }
  function deleteRead(body) {
    if(!body || Array.isArray(body) || typeof body!=='object')throw new Error('Solicitud no válida.');
    const keys=Object.keys(body);
    if(keys.length!==1 || !['id','through_id'].includes(keys[0]) ||
      !Number.isSafeInteger(body[keys[0]]) || body[keys[0]]<0 || (keys[0]==='id'&&body.id===0))
      throw new Error('Indicá una notificación leída o el último identificador recibido.');
    if(keys[0]==='id'&&db.prepare('SELECT id FROM notifications WHERE id=? AND read_at IS NULL AND deleted_at IS NULL').get(body.id))
      throw new Error('Primero marcá la notificación como leída.');
    
    
    db.prepare(`UPDATE notifications SET deleted_at=?,ip='',detail=''
      WHERE read_at IS NOT NULL AND deleted_at IS NULL AND ${keys[0]==='id'?'id=?':'id<=?'}`)
      .run(Math.floor(Date.now()/1000),body[keys[0]]);
  }
  function reconcileAuthorization(){
    
    const rows=db.prepare('SELECT id,ip FROM notifications WHERE read_at IS NULL AND deleted_at IS NULL').all();
    const update=db.prepare('UPDATE notifications SET read_at=? WHERE id=?');
    const now=Math.floor(Date.now()/1000);
    for(const row of rows)if(isAuthorized(row.ip))update.run(now,row.id);
  }
  return {ingest,snapshot,markRead,deleteRead,reconcileAuthorization};
}
