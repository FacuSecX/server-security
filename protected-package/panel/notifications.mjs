// Local, persistent inbox. Remote event classification never executes an action.
import {randomBytes,createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {ACCESS_TARGETS} from './panel-permissions.mjs';

export function createNotifications(db,{isAuthorized=()=>false,now=()=>Math.floor(Date.now()/1000)}={}) {
  db.exec(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL, service TEXT NOT NULL, ip TEXT NOT NULL,
    type TEXT NOT NULL, detail TEXT NOT NULL, read_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS notifications_unread_idx ON notifications(id) WHERE read_at IS NULL;`);
  if(!db.prepare('PRAGMA table_info(notifications)').all().some(column=>column.name==='deleted_at'))
    db.exec('ALTER TABLE notifications ADD COLUMN deleted_at INTEGER');
  const columns=new Set(db.prepare('PRAGMA table_info(notifications)').all().map(c=>c.name));
  for(const [name,type] of [['admin_only','INTEGER NOT NULL DEFAULT 0'],['actor_id',"TEXT NOT NULL DEFAULT ''"],['target',"TEXT NOT NULL DEFAULT ''"]])
    if(!columns.has(name))db.exec('ALTER TABLE notifications ADD COLUMN '+name+' '+type);
  db.exec("CREATE INDEX IF NOT EXISTS notifications_actor_idx ON notifications(actor_id,target,timestamp) WHERE admin_only=1");
  db.exec("CREATE TABLE IF NOT EXISTS panel_alert_outbox(event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, next_try INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)");
  db.exec('CREATE INDEX IF NOT EXISTS notifications_visible_idx ON notifications(id) WHERE deleted_at IS NULL');
  // Obsolete v26 connection notices are not evidence of authentication. Keep their original events.
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
  const scope=options=>options?.administrator===true?'1=1':'admin_only=0';
  function snapshot(before=null,options={}) {
    if(before!==null && (!Number.isSafeInteger(before)||before<1))throw new Error('Cursor no válido.');
    const rows=db.prepare(`SELECT id,timestamp,service,ip,type,detail,read_at FROM notifications
      WHERE deleted_at IS NULL AND ${scope(options)} ${before===null?'':'AND id<?'} ORDER BY id DESC LIMIT 51`).all(...(before===null?[]:[before]));
    const more=rows.length>50;rows.length=Math.min(rows.length,50);
    return {inbox_id:options.administrator===true?inboxId:createHash('sha256').update(inboxId+':general').digest('hex').slice(0,32),latest_notice_id:db.prepare('SELECT COALESCE(MAX(id),0) id FROM notifications WHERE deleted_at IS NULL AND '+scope(options)).get().id,items:rows,unread:db.prepare('SELECT COUNT(*) count FROM notifications WHERE read_at IS NULL AND deleted_at IS NULL AND '+scope(options)).get().count,
      read_count:db.prepare('SELECT COUNT(*) count FROM notifications WHERE read_at IS NOT NULL AND deleted_at IS NULL AND '+scope(options)).get().count,
      through_id:db.prepare('SELECT COALESCE(MAX(id),0) id FROM notifications WHERE '+scope(options)).get().id,
      next_before:more?rows.at(-1).id:null};
  }
  function markRead(body,options={}) {
    if(!body || Array.isArray(body) || typeof body!=='object')throw new Error('Solicitud no válida.');
    const keys=Object.keys(body);
    if(keys.length!==1 || !['id','through_id'].includes(keys[0]) ||
      !Number.isSafeInteger(body[keys[0]]) || body[keys[0]]<0 || (keys[0]==='id'&&body.id===0))
      throw new Error('Indicá una notificación o el último identificador recibido.');
    const query=keys[0]==='id'?'id=?':'id<=?';
    db.prepare(`UPDATE notifications SET read_at=? WHERE read_at IS NULL AND deleted_at IS NULL AND ${scope(options)} AND ${query}`)
      .run(Math.floor(Date.now()/1000),body[keys[0]]);
  }
  function deleteRead(body,options={}) {
    if(!body || Array.isArray(body) || typeof body!=='object')throw new Error('Solicitud no válida.');
    const keys=Object.keys(body);
    if(keys.length!==1 || !['id','through_id'].includes(keys[0]) ||
      !Number.isSafeInteger(body[keys[0]]) || body[keys[0]]<0 || (keys[0]==='id'&&body.id===0))
      throw new Error('Indicá una notificación leída o el último identificador recibido.');
    if(keys[0]==='id'&&db.prepare('SELECT id FROM notifications WHERE id=? AND read_at IS NULL AND deleted_at IS NULL AND '+scope(options)).get(body.id))
      throw new Error('Primero marcá la notificación como leída.');
    // Keep only a deduplication tombstone, so overlapping collection cannot revive it.
    // Original security events remain available in the activity/history views.
    db.prepare(`UPDATE notifications SET deleted_at=?,ip='',detail=''
      WHERE read_at IS NOT NULL AND deleted_at IS NULL AND ${scope(options)} AND ${keys[0]==='id'?'id=?':'id<=?'}`)
      .run(Math.floor(Date.now()/1000),body[keys[0]]);
  }
  function reconcileAuthorization(){
    // A newly authorized IP no longer contributes an old unread warning.
    const rows=db.prepare('SELECT id,ip FROM notifications WHERE read_at IS NULL AND deleted_at IS NULL AND admin_only=0').all();
    const update=db.prepare('UPDATE notifications SET read_at=? WHERE id=?');
    const now=Math.floor(Date.now()/1000);
    for(const row of rows)if(isAuthorized(row.ip))update.run(now,row.id);
  }

  function accessDenied(user,target,source='api'){
    if(!user||user.administrator===true||!/^([a-f0-9]{32}|primary-admin)$/.test(user.id||'')||
      !/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(user.username||'')||!Object.hasOwn(ACCESS_TARGETS,target)||!['view','api'].includes(source))return false;
    const timestamp=now();
    const last=db.prepare("SELECT MAX(timestamp) stamp FROM notifications WHERE admin_only=1 AND actor_id=? AND target=?").get(user.id,target).stamp;
    if(last!==null&&timestamp-last<60)return false;
    const event_id=randomBytes(16).toString('hex');
    const detail='El usuario '+user.username+' intentó acceder a '+ACCESS_TARGETS[target]+', una sección o función no autorizada. El acceso fue bloqueado.';
    db.exec('BEGIN IMMEDIATE');
    try{
      db.prepare("INSERT INTO notifications(event_id,timestamp,service,ip,type,detail,admin_only,actor_id,target) VALUES(?,?, 'Panel','', 'permission_denied',?,1,?,?)").run(event_id,timestamp,detail,user.id,target);
      db.prepare('DELETE FROM panel_alert_outbox WHERE created_at<?').run(timestamp-86400);
      if(db.prepare('SELECT COUNT(*) n FROM panel_alert_outbox').get().n<500)
        db.prepare('INSERT INTO panel_alert_outbox(event_id,payload,created_at) VALUES(?,?,?)').run(event_id,JSON.stringify({event_id,timestamp,username:user.username,target,source}),timestamp);
      db.exec('COMMIT');return true;
    }catch(error){db.exec('ROLLBACK');throw error;}
  }
  function pendingTelegram(){
    db.prepare('DELETE FROM panel_alert_outbox WHERE created_at<?').run(now()-86400);
    return db.prepare('SELECT payload FROM panel_alert_outbox WHERE next_try<=? ORDER BY created_at LIMIT 20').all(now()).map(row=>JSON.parse(row.payload));
  }
  function finishTelegram(events,accepted){
    for(const event of events){
      if(accepted)db.prepare('DELETE FROM panel_alert_outbox WHERE event_id=?').run(event.event_id);
      else db.prepare('UPDATE panel_alert_outbox SET attempts=attempts+1,next_try=?+MIN(900,15*(1 << MIN(attempts,6))) WHERE event_id=?').run(now(),event.event_id);
    }
  }
  return {ingest,snapshot,markRead,deleteRead,reconcileAuthorization,accessDenied,pendingTelegram,finishTelegram};

}
