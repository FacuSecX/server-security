"""Allowlisted service management: isolated virtual FTP users, explicit TLS only."""
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import storypulse_platform as linux
import storypulse_versions as versions

PROFILE=None
def configure_platform(profile=None):
    global PROFILE
    PROFILE=profile or linux.detect()
    return PROFILE

def distribution():return PROFILE or linux.detect()

BASE=Path('/etc/storypulse-ftp')
CONFIG=BASE/'state.json'
SPOOL=Path('/srv/storypulse-ftp')
PAM=Path('/etc/pam.d/storypulse-ftp')
UNIT=Path('/etc/systemd/system/storypulse-ftp.service')
BACKUPS=Path('/var/lib/storypulse-security/ftp-backups')
SERVICE='storypulse-ftp.service'
GUEST='spftp'
PASSIVE=(50000,50019)
PERMISSIONS=('list','download','upload','mkdir','rename','delete')
MAX_USERS=100

class ServiceError(RuntimeError):pass

def run(args,*,input=None,timeout=30,check=True):
    result=subprocess.run(args,input=input,text=True,encoding='utf-8',errors='replace',stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=timeout,env={**os.environ,'PATH':linux.SAFE_PATH,'LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    if check and result.returncode:raise ServiceError(f'Falló {Path(args[0]).name} (código {result.returncode}). Revisá el registro del servicio.')
    return result

def canonical(data):return json.dumps(data,sort_keys=True,separators=(',',':'))
def now():return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
def atomic(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    descriptor,name=tempfile.mkstemp(prefix='.ftp-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as output:
            if hasattr(os,'fchmod'):os.fchmod(output.fileno(),mode)
            else:os.chmod(name,mode)
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def username(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}',value) or value in ('root','debian','admin','anonymous','ftp',GUEST):
        raise ServiceError('Usuario: 3 a 32 letras minúsculas, números, guiones o guiones bajos. Ese nombre debe ser una cuenta FTP independiente.')
    return value

def root_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}',value) or value=='disabled':
        raise ServiceError('La carpeta raíz debe ser un nombre simple, sin barras, puntos ni rutas externas.')
    return value

def password(value):
    if not isinstance(value,str) or not 12<=len(value)<=128 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ServiceError('La contraseña debe tener entre 12 y 128 caracteres, sin saltos de línea ni caracteres de control.')
    try:value.encode('utf-8')
    except UnicodeError as exc:raise ServiceError('La contraseña contiene un carácter no válido.') from exc
    return value

def permissions(value):
    if not isinstance(value,dict) or set(value)!=set(PERMISSIONS) or any(type(v) is not bool for v in value.values()):
        raise ServiceError('Los permisos FTP no son válidos.')
    return dict(value)

def safe_root(name):
    result=SPOOL/root_name(name)
    for path in (SPOOL.parent,SPOOL,result,result/'archivos'):
        if path.is_symlink():raise ServiceError('La raíz FTP no puede usar enlaces simbólicos.')
    if result.resolve().parent!=SPOOL.resolve():raise ServiceError('La carpeta debe permanecer dentro del almacenamiento FTP.')
    return result

def load():
    if not CONFIG.exists():return {'version':1,'installed':False,'users':[]}
    try:data=json.loads(CONFIG.read_text())
    except (OSError,ValueError) as exc:raise ServiceError('No se pudo leer la configuración FTP.') from exc
    if not isinstance(data,dict) or data.get('version')!=1 or type(data.get('installed')) is not bool or not isinstance(data.get('users'),list) or len(data['users'])>MAX_USERS:
        raise ServiceError('La configuración FTP no es válida.')
    names=set();roots=set()
    for item in data['users']:
        username(item.get('username'));root_name(item.get('root'));permissions(item.get('permissions'))
        if 'game' in item and (item['game']!='samp' or item['root']!='game-samp'):raise ServiceError('La cuenta FTP de juegos tiene una raíz no válida.')
        if type(item.get('enabled')) is not bool or not re.fullmatch(r'\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}',str(item.get('password_hash',''))):
            raise ServiceError('La configuración de una cuenta FTP no es válida.')
        if item['username'] in names or item['root'] in roots:raise ServiceError('Hay usuarios o raíces FTP duplicados.')
        names.add(item['username']);roots.add(item['root'])
    return data

def service_state():
    result=run(['systemctl','is-active',SERVICE],check=False)
    return result.stdout.strip() or 'inactive'

def wait_ready():
    # Type=simple can report active before a bad configuration makes vsftpd exit.
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        try:
            with socket.create_connection(('127.0.0.1',21),timeout=0.7) as client:
                client.settimeout(0.7)
                if client.recv(256).startswith(b'220 '):return
        except OSError:pass
        time.sleep(0.15)
    raise ServiceError('FTP no respondió correctamente. Revisá el registro del servicio.')

def network():
    data=json.loads(run(['ip','-j','-4','route','get','1.1.1.1']).stdout)
    value=str(ipaddress.IPv4Address(data[0]['prefsrc']))
    if not ipaddress.ip_address(value).is_global:raise ServiceError('No se detectó la IPv4 pública del servidor.')
    return value

def revision(config):
    material=canonical(config)+service_state()
    for path in (BASE/'vsftpd.conf',PAM,UNIT):
        if path.exists():material+=hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(material.encode()).hexdigest()

def collision():
    output=run(['ss','-H','-lntp']).stdout
    for line in output.splitlines():
        fields=line.split()
        if len(fields)<4:continue
        try:port=int(fields[3].rsplit(':',1)[1])
        except ValueError:continue
        if (port==21 or PASSIVE[0]<=port<=PASSIVE[1]) and 'vsftpd' not in line:
            raise ServiceError('Un puerto FTP necesario ya está usado por otro servicio.')
    path=Path('/etc/storypulse-security/forwarding.json')
    if path.exists():
        try:entries=json.loads(path.read_text())['entries']
        except (ValueError,KeyError) as exc:raise ServiceError('No se pudo comprobar Port Forwarding.') from exc
        if any(r.get('enabled') and r.get('protocol')=='tcp' and (r.get('port')==21 or PASSIVE[0]<=r.get('port',0)<=PASSIVE[1]) for r in entries):
            raise ServiceError('Pausá las redirecciones de los puertos FTP antes de instalar o iniciar el servicio.')

def firewall_preflight():
    import importlib.util
    spec=importlib.util.spec_from_file_location('ftp_ports',Path(__file__).with_name('storypulse_ports.py'))
    ports=importlib.util.module_from_spec(spec);spec.loader.exec_module(ports)
    snapshot=ports.read_snapshot()
    if not snapshot['active']:raise ServiceError('UFW debe estar activo para habilitar los puertos desde la instalación.')
    selected=(21,*range(PASSIVE[0],PASSIVE[1]+1))
    for port in selected:
        reason=snapshot['protected'].get((port,'tcp'),'')
        if reason and not reason.startswith('FTP administrado'):raise ServiceError('Un puerto necesario para FTP protege otro acceso del servidor.')
        for rule in snapshot['rules']:
            if rule['family']!=4 or rule['direction']!='IN':continue
            if not rule['spans'] and not rule['any_port']:raise ServiceError('Hay perfiles UFW por aplicación que requieren revisión antes de habilitar FTP.')
            if rule['any_source'] and rule['action'] in ('DENY','REJECT') and ports.rule_matches(rule,port,'tcp'):
                raise ServiceError('Hay un bloqueo explícito de un puerto FTP. Revisalo en Gestión de puertos antes de instalar con apertura de puertos.')

def plan(payload):
    if payload.get('action')=='uninstall':return removal(payload)
    if payload.get('action')=='upgrade':return versions.upgrade_plan('ftp',__import__('types').SimpleNamespace(**globals()),payload)
    config=load();action=payload.get('action');user=None
    if action not in ('install','create-user','update-user','enable-user','disable-user','delete-user','start','stop','restart'):
        raise ServiceError('Acción de servicio no permitida.')
    if action=='install':
        if set(payload)-{'action','selection','open_firewall','confirm','revision'}:raise ServiceError('Campos de instalación no válidos.')
        if type(payload.get('open_firewall')) is not bool:raise ServiceError('Indicá si querés habilitar los puertos FTP en UFW.')
        if not CONFIG.exists() and (BASE.exists() or linux.installed(run,distribution(),'vsftpd')):
            raise ServiceError('Hay una instalación FTP ajena al panel. Se conserva su configuración y requiere revisión antes de administrarla.')
        if config['installed']:raise ServiceError('FTP ya está instalado. Usá Gestionar servicios.')
        collision()
        if payload['open_firewall']:firewall_preflight()
    else:
        if not config['installed']:raise ServiceError('Instalá primero FTP desde Instalar servicios.')
        if action in ('start','restart'):collision()
        if action.endswith('-user'):
            name=username(payload.get('username'));existing=next((r for r in config['users'] if r['username']==name),None)
            if action=='create-user':
                if existing:raise ServiceError('El usuario FTP ya existe.')
                if len(config['users'])>=MAX_USERS:raise ServiceError('Se alcanzó el límite de 100 usuarios FTP.')
                root=root_name(payload.get('root',name));target=safe_root(root)
                if target.exists() or any(r['root']==root for r in config['users']):raise ServiceError('La carpeta ya existe. Elegí otra para evitar reutilizar archivos de otra cuenta.')
                user={'username':name,'root':root,'permissions':permissions(payload.get('permissions')),'enabled':True}
            else:
                if not existing:raise ServiceError('El usuario FTP ya no existe.')
                if existing.get('game'):raise ServiceError('Esta cuenta pertenece a SA-MP y se administra desde Juegos.')
                user={k:v for k,v in existing.items() if k!='password_hash'}
                if action=='update-user':user['permissions']=permissions(payload.get('permissions'))
    selected=versions.select('ftp',__import__('types').SimpleNamespace(**globals()),payload.get('selection')) if action=='install' else None
    selected_revision=hashlib.sha256((revision(config)+payload['selection']).encode()).hexdigest() if selected else revision(config)
    return {'target_version':selected['version'] if selected else '', 'ok':True,'action':action,'revision':selected_revision,'user':user,'service':'FTP seguro (FTPS explícito)',
      'ports':[21,*PASSIVE],'open_firewall':payload.get('open_firewall',False),
      'notice':('Se instalarán vsftpd y la utilidad de base de usuarios. Se exige TLS para contraseña y archivos. '+
        ('Se permitirán en IPv4 TCP 21 y 50000–50019, conservando bloqueos y excepciones existentes.' if payload.get('open_firewall') else 'No se abrirán puertos automáticamente.')) if action=='install' else
        'Los cambios de usuarios reinician únicamente FTP para revocar los permisos y sesiones anteriores. Los archivos no se eliminan y las contraseñas nunca se muestran.'}

def hash_password(value):
    result=run(['openssl','passwd','-6','-stdin'],input=password(value)+'\n').stdout.strip()
    if not re.fullmatch(r'\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}',result):raise ServiceError('No se pudo proteger la contraseña.')
    return result

def user_config(item):
    if item.get('game'):
        from storypulse_game_ftp import user_config as game_config
        return game_config(item)
    p=permissions(item['permissions']);denied=['PORT','EPRT','SITE']
    for key,commands in {'upload':['STOR','STOU','APPE'],'mkdir':['MKD','XMKD'],'rename':['RNFR','RNTO'],'delete':['DELE','RMD','XRMD']}.items():
        if not p[key]:denied.extend(commands)
    return '\n'.join(['local_root='+str(safe_root(item['root'])),
        'write_enable='+('YES' if any(p[k] for k in ('upload','mkdir','rename','delete')) else 'NO'),
        'download_enable='+('YES' if p['download'] else 'NO'),'dirlist_enable='+('YES' if p['list'] else 'NO'),
        'cmds_denied='+','.join(denied),''])

def server_config(ip):
    return f'''# Managed by StoryPulse. FTP virtual users, no system/SSH login.
listen=YES
listen_ipv6=NO
background=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
guest_enable=YES
guest_username={GUEST}
ftp_username={GUEST}
virtual_use_local_privs=YES
pam_service_name=storypulse-ftp
user_config_dir={BASE}/users
userlist_enable=YES
userlist_deny=NO
userlist_file={BASE}/allowed-users
local_root={SPOOL}/disabled
chroot_local_user=YES
allow_writeable_chroot=NO
chmod_enable=NO
mdtm_write=NO
hide_ids=YES
ls_recurse_enable=NO
local_umask=007
file_open_mode=0660
port_enable=NO
pasv_enable=YES
pasv_min_port={PASSIVE[0]}
pasv_max_port={PASSIVE[1]}
pasv_address={ip}
pasv_promiscuous=NO
ssl_enable=YES
force_local_logins_ssl=YES
force_local_data_ssl=YES
ssl_sslv2=NO
ssl_sslv3=NO
ssl_tlsv1=NO
ssl_ciphers=HIGH:!aNULL:!MD5:!3DES
ssl_request_cert=NO
require_ssl_reuse=YES
rsa_cert_file={BASE}/tls/server.crt
rsa_private_key_file={BASE}/tls/server.key
secure_chroot_dir={BASE}/empty
max_clients=20
max_per_ip=4
max_login_fails=3
delay_failed_login=2
idle_session_timeout=300
data_connection_timeout=120
accept_timeout=60
connect_timeout=60
xferlog_enable=YES
xferlog_file=/var/log/storypulse-ftp/transfers.log
xferlog_std_format=YES
dual_log_enable=YES
syslog_enable=YES
log_ftp_protocol=NO
utf8_filesystem=YES
'''

def pam_backend():
    candidates=[Path('/usr/lib/security/pam_userdb.so'),Path('/usr/lib64/security/pam_userdb.so'),
                *Path('/usr/lib').glob('*/security/pam_userdb.so')]
    for path in candidates:
        if not path.is_file():continue
        data=path.read_bytes()
        if b'gdbm_open' in data:return 'gdbm'
        if b'libdb-' in data or b'libdb.so' in data or b'db_ndbm_open' in data:return 'berkeley'
    raise ServiceError('No se reconoció el formato de pam_userdb; no se reemplazó la autenticación.')

def write_auth(config):
    directory=BASE/'users';directory.mkdir(exist_ok=True,mode=0o755);os.chmod(directory,0o755)
    # pam_userdb crypt=crypt stores salted hashes, never plaintext passwords.
    active=[u for u in config['users'] if u['enabled']]
    content=''.join(u['username']+'\n'+u['password_hash']+'\n' for u in active)
    descriptor,name=tempfile.mkstemp(prefix='.users-',suffix='.db',dir=BASE);os.close(descriptor);os.unlink(name)
    try:
        backend=pam_backend()
        if backend=='gdbm':
            import dbm.gnu
            with dbm.gnu.open(name,'n',0o600) as database:
                for item in active:database[item['username'].encode()]=item['password_hash'].encode()
        else:
            loader=next((shutil.which(tool,path=linux.SAFE_PATH) for tool in ('db5.3_load','db_load') if shutil.which(tool,path=linux.SAFE_PATH)),None)
            if not loader:raise ServiceError('Falta el cargador Berkeley DB requerido por PAM.')
            run([loader,'-T','-t','hash',name],input=content)
        os.chmod(name,0o600);os.replace(name,BASE/'login.db')
        pam_file=BASE/('login.db' if backend=='gdbm' else 'login')
        atomic(PAM,('auth required pam_userdb.so db='+str(pam_file)+' crypt=crypt\naccount required pam_permit.so\n').encode(),0o644)
    finally:
        if os.path.exists(name):os.unlink(name)
    for item in config['users']:atomic(directory/item['username'],user_config(item).encode(),0o644)
    for path in directory.iterdir():
        if path.is_file() and path.name not in {u['username'] for u in config['users']} and re.fullmatch(r'[a-z][a-z0-9_-]{2,31}',path.name):path.unlink()
    atomic(BASE/'allowed-users',(''.join(u['username']+'\n' for u in active)).encode())

def make_root(item):
    target=safe_root(item['root']);target.mkdir(mode=0o755)
    os.chown(target,0,0);os.chmod(target,0o755)
    files=target/'archivos';files.mkdir(mode=0o770)
    import pwd
    identity=pwd.getpwnam(GUEST);os.chown(files,identity.pw_uid,identity.pw_gid);os.chmod(files,0o770)
    if linux.selinux_active(run):
        linux.label_path(run,'public_content_t',target)
        linux.label_path(run,'public_content_rw_t',files)

def unit_config():
    return f'''[Unit]
Description=StoryPulse isolated FTP over explicit TLS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={linux.executable('vsftpd') if PROFILE else '/usr/sbin/vsftpd'} {BASE}/vsftpd.conf
Environment=OPENSSL_CONF={BASE}/openssl.cnf
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={SPOOL} /var/log/storypulse-ftp -/opt/server-monitor/games/samp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
NoNewPrivileges=true
LockPersonality=true
RestrictRealtime=true
UMask=0077
KillMode=control-group

[Install]
WantedBy=multi-user.target
'''

def openssl_config():
    # The Debian binary lacks some newer vsftpd TLS option names; enforce the floor in OpenSSL itself.
    return '''openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_settings
[ssl_settings]
system_default = tls_defaults
[tls_defaults]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
'''

def open_ports(repair_monitor):
    import fcntl
    # Only the short firewall operation holds the shared lock; apt uses a separate lock.
    with Path('/run/lock/storypulse-securityctl.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for port in ('21','50000:50019'):
            run(['ufw','allow','in','proto','tcp','from','0.0.0.0/0','to','0.0.0.0/0','port',port,'comment','StoryPulse FTP'])
        repair_monitor(4)

def _install(payload,repair_monitor,repository_current=False):
    # vsftpd reads per-user non-secret settings after dropping privileges. Hashes/keys remain 0600.
    BASE.mkdir(parents=True,exist_ok=True,mode=0o755);os.chmod(BASE,0o755)
    config=load();atomic(CONFIG,(canonical(config)+'\n').encode()) # Own marker permits repairing an interrupted installation.
    run(['systemctl','mask','vsftpd.service']) # Prevent the package from starting an unconfigured plaintext daemon.
    linux.install_packages(run,distribution(),[p for p in linux.ftp_packages(distribution()) if p!='vsftpd'])
    if repository_current:linux.install_packages(run,distribution(),['vsftpd'])
    else:versions.install_selected('ftp',__import__('types').SimpleNamespace(**globals()),payload['selection'])
    nologin=linux.executable('nologin')
    if run(['id','-u',GUEST],check=False).returncode:
        run(['useradd','--system','--no-create-home','--home-dir',str(SPOOL/'disabled'),'--shell',nologin,GUEST])
    else:
        import pwd
        identity=pwd.getpwnam(GUEST)
        if identity.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/usr/bin/nologin') or identity.pw_dir!=str(SPOOL/'disabled'):
            raise ServiceError('El usuario interno spftp ya existe con otra configuración. No se modificó.')
    SPOOL.mkdir(parents=True,exist_ok=True,mode=0o755)
    if SPOOL.is_symlink():raise ServiceError('El almacenamiento FTP no puede ser un enlace.')
    (SPOOL/'disabled').mkdir(exist_ok=True,mode=0o755);os.chown(SPOOL/'disabled',0,0);os.chmod(SPOOL/'disabled',0o755)
    (BASE/'empty').mkdir(exist_ok=True,mode=0o755);os.chown(BASE/'empty',0,0);os.chmod(BASE/'empty',0o755)
    (BASE/'tls').mkdir(exist_ok=True,mode=0o700)
    ip=network()
    if not certificate_ready():
        run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365','-subj','/CN='+ip,'-addext','subjectAltName=IP:'+ip,
             '-keyout',str(BASE/'tls/server.key'),'-out',str(BASE/'tls/server.crt')],timeout=45)
        os.chmod(BASE/'tls/server.key',0o600)
    atomic(BASE/'vsftpd.conf',server_config(ip).encode())
    atomic(BASE/'openssl.cnf',openssl_config().encode())
    atomic(PAM,('auth required pam_userdb.so db='+str(BASE/'login')+' crypt=crypt\naccount required pam_permit.so\n').encode(),0o644)
    logs=Path('/var/log/storypulse-ftp');logs.mkdir(exist_ok=True,mode=0o750)
    atomic(Path('/etc/logrotate.d/storypulse-ftp'),b'/var/log/storypulse-ftp/*.log {\n weekly\n rotate 4\n compress\n missingok\n notifempty\n copytruncate\n}\n',0o644)
    atomic(UNIT,unit_config().encode(),0o644);write_auth(config)
    linux.ftp_selinux(run,BASE,SPOOL,logs)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',SERVICE])
    if service_state()!='active':raise ServiceError('FTP no quedó activo. Revisá el registro y completá la instalación.')
    wait_ready()
    if payload['open_firewall']:open_ports(repair_monitor)
    config['installed']=True;config['installed_at']=now();atomic(CONFIG,(canonical(config)+'\n').encode())
    return {'ok':True,'action':'install'}

def removal(payload,applying=False,repair_monitor=None):
    if any(user.get('game') for user in load()['users']):raise ServiceError('FTP está asociado a un juego. Eliminá primero ese juego para revocar su cuenta antes de quitar el servicio compartido.')
    import storypulse_uninstall as remover
    from types import SimpleNamespace
    try:
        module=SimpleNamespace(**globals())
        return remover.apply('ftp',module,payload,repair_monitor) if applying else remover.plan('ftp',module,payload)
    except remover.RemovalError as exc:raise ServiceError(str(exc)) from exc

def install(payload,repair_monitor):
    import storypulse_uninstall as remover
    try:
        with remover.package_lock():return _install(payload,repair_monitor)
    except remover.RemovalError as exc:raise ServiceError(str(exc)) from exc

def certificate_ready():
    """An interrupted OpenSSL run may leave a key without its matching certificate."""
    key=BASE/'tls/server.key';cert=BASE/'tls/server.crt'
    if not key.is_file() or not cert.is_file():return False
    valid=run(['openssl','x509','-in',str(cert),'-noout','-checkend','604800'],check=False)
    if valid.returncode:return False
    public_key=run(['openssl','pkey','-in',str(key),'-pubout'],check=False)
    public_cert=run(['openssl','x509','-in',str(cert),'-pubkey','-noout'],check=False)
    return not public_key.returncode and not public_cert.returncode and bool(public_key.stdout) and public_key.stdout==public_cert.stdout


def change(payload,repair_monitor):
    if payload.get('action')=='uninstall':return removal(payload,True,repair_monitor)
    if payload.get('confirm') is not True:raise ServiceError('Falta confirmar el cambio de servicio.')
    proposal=plan(payload);config=load();action=proposal['action']
    if payload.get('revision')!=proposal['revision']:raise ServiceError('La configuración cambió. Revisá nuevamente la vista previa.')
    if action=='upgrade':return versions.upgrade('ftp',__import__('types').SimpleNamespace(**globals()),payload)
    if action=='install':return install(payload,repair_monitor)
    if action in ('start','stop','restart'):
        run(['systemctl',action,SERVICE])
        if action!='stop':wait_ready()
        return {'ok':True,'action':action}
    name=username(payload.get('username'));users=[dict(u) for u in config['users']];existing=next((u for u in users if u['username']==name),None)
    if action=='create-user':
        item={**proposal['user'],'password_hash':hash_password(payload.get('password')),'created_at':now()}
    else:
        item=dict(existing)
        if action=='update-user':
            item['permissions']=proposal['user']['permissions']
            if payload.get('password'):item['password_hash']=hash_password(payload['password'])
        if action in ('enable-user','disable-user'):item['enabled']=action=='enable-user'
    # Backups contain hashes only; user data directories are never deleted or moved.
    directory=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(4).hex())
    directory.mkdir(parents=True,mode=0o700);os.chmod(BACKUPS,0o700);atomic(directory/'state.json',(canonical(config)+'\n').encode())
    active_before=service_state()=='active'
    try:
        if action=='create-user':make_root(item)
        users=[u for u in users if u['username']!=name]
        if action!='delete-user':users.append(item)
        updated={**config,'users':sorted(users,key=lambda u:u['username'])}
        write_auth(updated);atomic(CONFIG,(canonical(updated)+'\n').encode())
        if active_before:
            run(['systemctl','restart',SERVICE]);wait_ready()
    except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        try:
            write_auth(config);atomic(CONFIG,(canonical(config)+'\n').encode())
            if active_before:
                run(['systemctl','restart',SERVICE]);wait_ready()
        except (RuntimeError,OSError,subprocess.TimeoutExpired) as recovery:raise ServiceError('No se pudo completar la recuperación FTP. Revisá el servicio.') from recovery
        raise ServiceError('No se aplicó el cambio; se recuperó la configuración FTP anterior.') from exc
    return {'ok':True,'action':action,'username':name,'backup':str(directory)}

def status():
    config=load();fingerprint=''
    cert=BASE/'tls/server.crt'
    if cert.exists():fingerprint=run(['openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256']).stdout.strip().partition('=')[2]
    return {'ok':True,'service':'ftp','installed_version':versions.installed('ftp',__import__('types').SimpleNamespace(**globals())),'installed':config['installed'],'managed':CONFIG.exists(),'state':service_state(),
      'revision':revision(config),'timestamp':int(dt.datetime.now(dt.timezone.utc).timestamp()),'host':network(),
      'port':21,'passive_ports':list(PASSIVE),'base_directory':str(SPOOL),'certificate_sha256':fingerprint,
      'users':[{k:v for k,v in u.items() if k!='password_hash'} for u in config['users']],
      'notice':'FTP con TLS explícito obligatorio. Certificado propio: verificá la huella antes de confiar. Las cuentas no permiten SSH y quedan aisladas en su raíz. Los archivos se conservan al eliminar usuarios.'}
