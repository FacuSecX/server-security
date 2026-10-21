#!/usr/bin/env python3
"""Independent confirmed-login notifier. No shell input, no legacy bot mutations."""
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CONFIG = Path('/etc/storypulse-security/panel-alerts.json')
STATE_DIR = Path('/var/lib/server-monitor-alerts')
LEGACY_ENV = Path('/etc/storypulse-alerts/telegram.env')
UNIT = 'server-monitor-alerts.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
LOCK = Path('/run/lock/server-monitor-alerts-config.lock')
KINDS = {'ssh_success':'SSH', 'ftp_success':'FTP', 'mysql_success':'MySQL', 'mariadb_success':'MariaDB'}
TOKEN = re.compile(r'[0-9]{5,20}:[A-Za-z0-9_-]{25,80}\Z')


class AlertError(RuntimeError):
    pass


def secure_json(path, fallback=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return fallback
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 16384:
            raise AlertError('La configuración de alertas tiene permisos inseguros.')
        return json.load(source)


def atomic_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.panel-alerts-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as target:
            os.fchmod(target.fileno(), 0o600)
            json.dump(value, target, ensure_ascii=True)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def config_lock():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise AlertError('Ya se está modificando la configuración de alertas.') from None
    finally:
        os.close(fd)


def configuration():
    return secure_json(CONFIG, {})


def revision(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def normalize(body):
    if not isinstance(body, dict) or set(body) != {'token', 'chat_id', 'admin_id', 'enabled'}:
        raise AlertError('Completá únicamente los parámetros del bot.')
    token, chat, admin = body['token'], body['chat_id'], body['admin_id']
    if not isinstance(token, str) or (token and not TOKEN.fullmatch(token)):
        raise AlertError('El token del bot no tiene un formato válido.')
    if not isinstance(chat, str) or not re.fullmatch(r'-?[1-9][0-9]{0,18}', chat):
        raise AlertError('El chat ID debe ser un número válido.')
    if not isinstance(admin, str) or (admin and not re.fullmatch(r'[1-9][0-9]{0,18}', admin)):
        raise AlertError('El identificador del administrador debe ser numérico.')
    if int(chat) < 0 and not admin:
        raise AlertError('Para grupos, indicá el ID de la persona que podrá usar los botones.')
    if int(chat) > 0 and admin and admin != chat:
        raise AlertError('En un chat privado, el administrador debe coincidir con el chat ID.')
    if type(body['enabled']) is not bool:
        raise AlertError('El estado de envío no es válido.')
    return dict(token=token, chat_id=chat, admin_id=admin or chat, enabled=body['enabled'])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def telegram(token, method, payload, timeout=12):
    if not TOKEN.fullmatch(token or '') or method not in {'getMe','getChat','getWebhookInfo','sendMessage','getUpdates','answerCallbackQuery'}:
        raise AlertError('Solicitud de Telegram no permitida.')
    request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method,
        data=json.dumps(payload).encode(), headers={'Content-Type':'application/json'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise AlertError('Telegram devolvió una respuesta demasiado grande.')
        result = json.loads(raw)
        if result.get('ok') is not True:
            raise AlertError('Telegram rechazó la solicitud. Revisá la configuración y los permisos.')
        return result['result']
    except urllib.error.HTTPError as exc:
        # Never propagate an exception containing the token-bearing request URL.
        retry = 30
        if exc.code == 429:
            try: retry = min(3600, max(5, int(json.loads(exc.read(8192)).get('parameters',{}).get('retry_after',30))))
            except (ValueError, TypeError, AttributeError): pass
        error = AlertError('Telegram limitó los envíos.' if exc.code == 429 else 'Telegram rechazó las credenciales o la operación.')
        error.retry_after = retry
        raise error from None
    except (OSError, ValueError, KeyError):
        raise AlertError('No se pudo contactar con Telegram. Se reintentará con espera.') from None


def reject_legacy_token(token):
    # Comparison only. Never change, restart, import or publish the separate legacy monitor.
    path = LEGACY_ENV
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536 or info.st_uid != 0:
            raise AlertError('No se pudo comprobar la independencia del bot anterior.')
        text = source.read(65537)
    match = re.search(r'^\s*(?:export\s+)?BOT_TOKEN\s*=\s*[\"\']?([0-9]+):', text, re.M)
    if match and match.group(1) == token.split(':',1)[0]:
        raise AlertError('Ese bot pertenece al sistema de alertas anterior. Creá otro bot para este panel.')


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise AlertError('No se pudo actualizar el servicio independiente de alertas.')
    return result.stdout


def status():
    config = configuration()
    runtime = secure_json(STATE_DIR/'status.json', {})
    return dict(ok=True, installed=UNIT_FILE.is_file(), configured=bool(config.get('token')),
        enabled=bool(config.get('enabled')), chat_id=config.get('chat_id',''), admin_id=config.get('admin_id',''),
        bot_username=config.get('bot_username',''), revision=revision(config),
        running=subprocess.run(['systemctl','is-active','--quiet',UNIT], capture_output=True, timeout=5).returncode == 0,
        runtime=runtime)


def change(body):
    if not isinstance(body, dict) or body.get('confirm') is not True or not re.fullmatch('[a-f0-9]{64}', str(body.get('revision',''))):
        raise AlertError('Confirmá una configuración vigente.')
    with config_lock():
        config = configuration()
        if revision(config) != body['revision']:
            raise AlertError('Cambió el estado del bot. Actualizá antes de guardar.')
        if set(body) == {'enabled','confirm','revision'}:
            if type(body['enabled']) is not bool or not config.get('token'):
                raise AlertError('Primero configurá un bot nuevo.')
            config['enabled'] = body['enabled']
        else:
            clean = normalize({key:value for key,value in body.items() if key not in {'confirm','revision'}})
            clean['token'] = clean['token'] or config.get('token','')
            if not clean['token']:
                raise AlertError('Ingresá el token de un bot nuevo.')
            reject_legacy_token(clean['token'])
            me = telegram(clean['token'],'getMe',{})
            if not me.get('is_bot'):
                raise AlertError('La credencial no corresponde a un bot.')
            if telegram(clean['token'],'getWebhookInfo',{}).get('url'):
                raise AlertError('Ese bot tiene una integración activa. Usá un bot dedicado sin webhook.')
            chat = telegram(clean['token'],'getChat',{'chat_id':clean['chat_id']})
            if str(chat.get('id')) != clean['chat_id']:
                raise AlertError('El chat no coincide con la configuración.')
            if int(clean['chat_id']) > 0 and chat.get('type') != 'private':
                raise AlertError('El destino privado no es válido.')
            if int(clean['chat_id']) < 0 and chat.get('type') not in ('group','supergroup'):
                raise AlertError('Los controles requieren un chat privado o un grupo.')
            # Private nonce makes buttons from an old token/chat invalid.
            changed_identity = any(clean[k] != config.get(k) for k in ('token','chat_id','admin_id'))
            config = dict(clean, bot_username=str(me.get('username',''))[:64],
                nonce=os.urandom(8).hex() if changed_identity else config.get('nonce',os.urandom(8).hex()),
                updated_at=int(time.time()))
        if not UNIT_FILE.is_file():
            raise AlertError('Ejecutá el instalador del servidor para preparar el servicio.')
        atomic_json(CONFIG, config)
    # The control listener remains alive when sending is disabled.
    command(['systemctl','enable','--now',UNIT])
    return status()


def buttons(config):
    nonce = config['nonce']
    return {'inline_keyboard':[[{'text':'🟢 Activar alertas','callback_data':'panel:on:'+nonce},
                               {'text':'⏸ Desactivar alertas','callback_data':'panel:off:'+nonce}]]}


def callback(update):
    query = update.get('callback_query')
    if not isinstance(query,dict): return False
    config = configuration()
    message = query.get('message') or {}
    if (str((message.get('chat') or {}).get('id')) != config.get('chat_id') or
            str((query.get('from') or {}).get('id')) != config.get('admin_id')):
        return False
    options = {'panel:on:'+config.get('nonce',''):True,'panel:off:'+config.get('nonce',''):False}
    if query.get('data') not in options: return False
    with config_lock():
        current = configuration()
        if current.get('nonce') != config.get('nonce'): return False
        if current.get('enabled') == options[query['data']]: return True
        if time.time()-current.get('control_at',0)<5: return True
        current['enabled'] = options[query['data']]
        current['control_at'] = int(time.time())
        atomic_json(CONFIG,current)
    telegram(current['token'],'answerCallbackQuery',{'callback_query_id':query['id'],
        'text':'Alertas activadas' if current['enabled'] else 'Alertas desactivadas'})
    telegram(current['token'],'sendMessage',{'chat_id':current['chat_id'],
        'text':'🟢 Alertas activadas' if current['enabled'] else '⏸ Alertas desactivadas', 'reply_markup':buttons(current)})
    return True


def open_store():
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    db = sqlite3.connect(str(STATE_DIR/'events.sqlite'), timeout=3)
    os.chmod(STATE_DIR/'events.sqlite',0o600)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL,
        payload TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS event_pending ON events(state,next_try,timestamp);''')
    return db


def get_state(db,key,default=None):
    row=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
    return json.loads(row[0]) if row else default


def set_state(db,key,value):
    db.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps(value)))


PANEL_TARGETS = {
 'overview':'Resumen','activity':'Actividad en vivo','providers':'Proveedores','ssh':'Accesos SSH','reports':'Generar Reporte',
 'ports':'Gestión de puertos','forwarding':'Port Forwarding','port-traffic':'Tráfico en puertos',
 'services-install':'Instalar servicios','services-manage':'Gestionar servicios','services-remove':'Eliminar servicios',
 'databases':'Bases de datos','investigate':'Investigar IP','blocks':'Bloqueos de IP','authorized-ips':'IP autorizadas',
 'system':'Estado del sistema','alerts':'Alertas','appearance':'Personalizar panel','cleanup':'Borrado de datos',
 'terminal':'Terminal','panel-users':'Usuarios panel','restricted-api':'Función restringida'}


def enqueue_panel_events(body):
    if not isinstance(body,dict) or set(body)!={'events'} or not isinstance(body['events'],list) or not 1<=len(body['events'])<=20:
        raise AlertError('Lote de alertas del panel no válido.')
    events=body['events'];now=int(time.time())
    for event in events:
        if (not isinstance(event,dict) or set(event)!={'event_id','timestamp','username','target','source'} or
                not isinstance(event['event_id'],str) or not re.fullmatch('[a-f0-9]{32}',event['event_id']) or
                type(event['timestamp']) is not int or not now-86400<=event['timestamp']<=now+300 or
                not isinstance(event['username'],str) or not re.fullmatch('[a-z0-9][a-z0-9_.-]{2,31}',event['username']) or
                not isinstance(event['target'],str) or event['target'] not in PANEL_TARGETS or event['source'] not in ('api','view')):
            raise AlertError('Una alerta del panel contiene campos no válidos.')
    config=configuration()
    if not config.get('token') or not config.get('enabled'):
        return dict(ok=True,ignored=True)
    identity=hashlib.sha256((config['token']+'|'+config['chat_id']).encode()).hexdigest()
    db=open_store()
    try:
        if get_state(db,'bot_identity')!=identity:
            return dict(ok=True,retry=True)
        if db.execute("SELECT COUNT(*) FROM events WHERE state='pending'").fetchone()[0]+len(events)>500:
            return dict(ok=True,retry=True)
        for event in events:
            payload=dict(event,kind='panel_permission_denied')
            db.execute("INSERT OR IGNORE INTO events(id,timestamp,payload,state) VALUES(?,?,?,'pending')",
                       (event['event_id'],event['timestamp'],json.dumps(payload)))
        db.commit()
        return dict(ok=True,accepted=True)
    finally:
        db.close()


def authenticated_event(row, collector):
    if row.get('SYSLOG_IDENTIFIER') in ('sshd','sshd-session') or row.get('_COMM') in ('sshd','sshd-session'):
        if str(row.get('_UID','')) != '0': return None
        match=collector.ACCEPTED_SSH.search(str(row.get('MESSAGE','')))
        if not match: return None
        address=collector.valid_ip(match.group('ip'))
        try: timestamp=int(row['__REALTIME_TIMESTAMP'])//1000000
        except (ValueError,KeyError,TypeError): return None
        if not address or timestamp<1: return None
        return collector.journal_identity(dict(id='',timestamp=timestamp,kind='ssh_success',ip=address,
            service='SSH',port='22',auth_method=match.group('method')),row)
    return collector.service_auth_event(row)


def enqueue(db, events, policy, enabled):
    if not policy.get('ready'):
        raise AlertError('No está disponible la lista de IP autorizadas; el envío queda suspendido.')
    networks=[ipaddress.ip_network(value,strict=False) for value in policy['authorized_ips']]
    count=0
    for event in events:
        if event.get('kind') not in KINDS or not re.fullmatch('[a-f0-9]{32}',str(event.get('id',''))): continue
        try:
            address=ipaddress.ip_address(event['ip'])
            if getattr(address,'ipv4_mapped',None): address=address.ipv4_mapped
        except (KeyError,ValueError): continue
        if address.is_loopback or address.is_unspecified or address.is_multicast or any(address in net for net in networks): continue
        payload=dict(event,ip=str(address),service=KINDS[event['kind']])
        result=db.execute('INSERT OR IGNORE INTO events(id,timestamp,payload,state) VALUES(?,?,?,?)',
            (event['id'],int(event['timestamp']),json.dumps(payload) if enabled else '{}', 'pending' if enabled else 'paused'))
        count+=result.rowcount
    return count


def journal_batch(db, collector):
    cursor=get_state(db,'cursor')
    since=get_state(db,'since',int(time.time()))
    args=['journalctl','-o','json','--no-pager','--output-fields=MESSAGE,__REALTIME_TIMESTAMP,__CURSOR,SYSLOG_IDENTIFIER,_COMM,_UID',
        '--after-cursor='+cursor] if cursor else ['journalctl','-o','json','--no-pager','--since=@'+str(max(0,since-3))]
    filters=['_COMM=sshd','+','SYSLOG_IDENTIFIER=sshd','+','SYSLOG_IDENTIFIER=sshd-session','+',
        'SYSLOG_IDENTIFIER=vsftpd','+','_COMM=vsftpd','+','SYSLOG_IDENTIFIER=storypulse-db-audit','+','SYSLOG_IDENTIFIER=mysql-server_auditing']
    # Oldest 500 matching rows, without --lines (which would select the tail and skip events).
    child=subprocess.Popen(args+filters,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    rows=[];events=[];size=0;buffer=b''
    try:
        import select
        deadline=time.monotonic()+8
        while len(rows)<500 and time.monotonic()<deadline:
            if b'\n' in buffer:
                raw,buffer=buffer.split(b'\n',1)
            else:
                if not select.select([child.stdout],[],[],max(0,deadline-time.monotonic()))[0]: break
                chunk=os.read(child.stdout.fileno(),32768)
                if not chunk: break
                buffer+=chunk;size+=len(chunk)
                if size>4*1024*1024 or (b'\n' not in buffer and len(buffer)>32768):
                    raise AlertError('El lote de registros supera el límite de seguridad.')
                continue
            if len(raw)>32768: raise AlertError('Un registro supera el límite de seguridad.')
            try: row=json.loads(raw)
            except (ValueError,UnicodeError): continue
            if not isinstance(row,dict) or '__CURSOR' not in row: continue
            rows.append(row)
            event=authenticated_event(row,collector)
            if event: events.append(event)
        child.stdout.close()
        if child.poll() is None: child.terminate()
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired: child.kill();child.wait(timeout=2)
        if not rows and child.returncode not in (0,-15):
            if cursor:
                set_state(db,'cursor',None);db.commit()
            raise AlertError('No se pudieron leer los registros de autenticación.')
    finally:
        if child.poll() is None: child.kill();child.wait(timeout=2)
    if rows:
        set_state(db,'cursor',rows[-1]['__CURSOR'])
        set_state(db,'since',int(rows[-1]['__REALTIME_TIMESTAMP'])//1000000)
    else: set_state(db,'since',int(time.time()))
    return events


def geolocation(db,ip):
    cached=get_state(db,'geo:'+ip)
    if cached and time.time()-cached['at']<86400: return cached['country'],cached['isp']
    if not ipaddress.ip_address(ip).is_global: return 'Red privada','No disponible'
    country=isp='No disponible'
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open('https://ipwho.is/'+ip,timeout=4) as response: raw=response.read(16385)
        if len(raw)>16384: raise ValueError()
        data=json.loads(raw)
        if data.get('success') is True:
            country=str(data.get('country') or country)[:100]
            isp=str((data.get('connection') or {}).get('isp') or isp)[:160]
    except (OSError,ValueError,TypeError,AttributeError): pass
    set_state(db,'geo:'+ip,dict(at=int(time.time()),country=country,isp=isp))
    return country,isp


def send_pending(db,config,policy):
    if not config.get('enabled'): return 0
    networks=[ipaddress.ip_network(value,strict=False) for value in policy.get('authorized_ips',[])] if policy.get('ready') else None
    sent=0
    rows=db.execute("SELECT id,payload,attempts FROM events WHERE state='pending' AND next_try<=? ORDER BY timestamp LIMIT 3",(int(time.time()),)).fetchall()
    for identity,payload,attempts in rows:
        # Recheck flag/config each time: a panel or callback pause cannot send the remaining batch.
        current=configuration()
        if not current.get('enabled') or current.get('nonce')!=config.get('nonce'): break
        event=json.loads(payload)
        when=dt.datetime.fromtimestamp(event['timestamp'],dt.timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')
        if event.get('kind')=='panel_permission_denied':
            if event.get('target') not in PANEL_TARGETS or not re.fullmatch('[a-z0-9][a-z0-9_.-]{2,31}',str(event.get('username',''))):
                db.execute("UPDATE events SET state='invalid',payload='{}' WHERE id=?",(identity,));db.commit();continue
            text=('🚨 INTENTO DE ACCESO RESTRINGIDO EN EL PANEL\n\nServidor: '+socket.gethostname()[:128]+
                  '\nFecha: '+when+'\nUsuario: '+event['username']+'\nSección: '+PANEL_TARGETS[event['target']]+
                  '\nTipo: '+('URL del panel' if event.get('source')=='view' else 'Función de la API')+
                  '\n\nAcceso bloqueado por falta de permisos.\nEvento: '+identity[:12])
        else:
            if networks is None:continue
            address=ipaddress.ip_address(event['ip'])
            if any(address in network for network in networks):
                db.execute("UPDATE events SET state='authorized' WHERE id=?",(identity,));continue
            country,isp=geolocation(db,event['ip'])
            text='🚨 ACCESO NO AUTORIZADO\n\nServidor: '+socket.gethostname()[:128]+'\nFecha: '+when+'\nIP: '+event['ip']+'\nPaís: '+country+'\nISP: '+isp+'\nServicio: '+event['service']+'\nPuerto: '+str(event.get('port','No disponible'))+'\n\nAcceso autenticado confirmado.\nEvento: '+identity[:12]
        try:
            telegram(current['token'],'sendMessage',{'chat_id':current['chat_id'],'text':text,'reply_markup':buttons(current)})
            db.execute("UPDATE events SET state='sent',payload='{}' WHERE id=?",(identity,));set_state(db,'last_sent',int(time.time()));sent+=1
        except AlertError as error:
            delay=max(getattr(error,'retry_after',0),min(3600,15*2**min(attempts,8)))
            db.execute('UPDATE events SET attempts=attempts+1,next_try=? WHERE id=?',(int(time.time())+delay,identity))
            raise
        finally: db.commit()
    return sent


def main():
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import storypulse_collector as collector
    import storypulse_trusted as trusted
    os.umask(0o077)
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    instance=os.open(STATE_DIR/'daemon.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try: fcntl.flock(instance,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(instance);return  # Never spawn a second Telegram update reader.
    db=None
    try:
        db=open_store()
        run_daemon(db,collector,trusted)
    finally:
        if db is not None:db.close()
        os.close(instance)


def run_daemon(db,collector,trusted):
    last_db_check=-1000000;last_prune=0;poll_after=0
    if get_state(db,'since') is None: set_state(db,'since',int(time.time()));db.commit()
    while True:
        started=time.monotonic();runtime={'checked_at':int(time.time()),'error':'','coverage':[]}
        try:
            config=configuration();policy=trusted.policy()
            if not config.get('token'): time.sleep(5);continue
            identity=hashlib.sha256((config['token']+'|'+config['chat_id']).encode()).hexdigest()
            if get_state(db,'bot_identity')!=identity:
                set_state(db,'bot_identity',identity);set_state(db,'offset',None)
                # New chat/token never inherits old pending security messages.
                db.execute("UPDATE events SET state='paused',payload='{}' WHERE state='pending'")
                set_state(db,'welcome',None)
            events=journal_batch(db,collector)
            if time.monotonic()-last_db_check>=15:
                states=collector.service_states()
                catalog=collector.monitored_services(states,collector.run(['ss','-H','-ltnp'],timeout=5))
                observed,coverage=collector.database_access_snapshot(catalog)
                events.extend(observed)
                runtime['coverage']=[{'service':'SSH','mode':'journal-auth','ready':True},*collector.ftp_access_source(catalog),*coverage]
                set_state(db,'coverage',runtime['coverage']);set_state(db,'catalog',catalog);last_db_check=time.monotonic()
            else: runtime['coverage']=get_state(db,'coverage',[])
            known_ports={item['service']:item.get('ports',[]) for item in get_state(db,'catalog',[])}
            for event in events:
                ports=known_ports.get(KINDS.get(event.get('kind')),[])
                if ports: event['port']=','.join(str(port) for port in ports)
            enqueue(db,events,policy,bool(config.get('enabled')))
            if not config.get('enabled'):
                db.execute("UPDATE events SET state='paused',payload='{}' WHERE state='pending'")
            db.commit()
            if time.time()>=poll_after:
                try:
                    parameters={'timeout':0,'limit':20,'allowed_updates':['callback_query','message']}
                    offset=get_state(db,'offset')
                    if offset is not None:parameters['offset']=offset
                    updates=telegram(config['token'],'getUpdates',parameters)
                    for update in updates:
                        if not isinstance(update.get('update_id'),int): continue
                        message=update.get('message') or {}
                        if (str((message.get('chat') or {}).get('id'))==config.get('chat_id') and
                            str((message.get('from') or {}).get('id'))==config.get('admin_id') and
                            message.get('text') in ('/start','/estado')):
                            telegram(config['token'],'sendMessage',{'chat_id':config['chat_id'],
                                'text':'Alertas '+('activadas' if configuration().get('enabled') else 'desactivadas'),
                                'reply_markup':buttons(config)})
                        callback(update)
                        set_state(db,'offset',update['update_id']+1);db.commit()
                except AlertError as error:
                    poll_after=time.time()+max(15,getattr(error,'retry_after',15));raise
            config=configuration()
            if get_state(db,'welcome')!=identity:
                telegram(config['token'],'sendMessage',{'chat_id':config['chat_id'],
                    'text':'Server Monitor: alertas '+('activadas' if config.get('enabled') else 'desactivadas')+'.\nSólo accesos autenticados desde IP no autorizadas.', 'reply_markup':buttons(config)})
                set_state(db,'welcome',identity);db.commit()
            send_pending(db,config,trusted.policy())
            runtime['last_sent']=get_state(db,'last_sent')
            runtime['pending']=db.execute("SELECT COUNT(*) FROM events WHERE state='pending'").fetchone()[0]
            if time.monotonic()-last_prune>3600:
                db.execute("DELETE FROM events WHERE state!='pending' AND timestamp<?",(int(time.time())-30*86400,))
                db.execute("DELETE FROM state WHERE key LIKE 'geo:%' AND CAST(json_extract(value,'$.at') AS INTEGER)<?",(int(time.time())-7*86400,))
                last_prune=time.monotonic()
            db.commit()
        except Exception as error:
            db.rollback()
            runtime['error']=str(error)[:200] if isinstance(error,AlertError) else 'No se pudo completar la comprobación. Se reintentará.'
        atomic_json(STATE_DIR/'status.json',runtime)
        time.sleep(max(1,5-(time.monotonic()-started)))


if __name__=='__main__':
    main()
