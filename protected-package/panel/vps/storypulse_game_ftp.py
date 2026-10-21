"""SA-MP account in the existing explicit-TLS FTP service; fixed chroot only."""
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import re
import ssl
import stat
import storypulse_services as ftp
import storypulse_platform as linux
import storypulse_uninstall as removal

ROOT=Path('/opt/server-monitor/games/samp')
SYSTEM_USER='sm-samp-ftp'
ROOT_NAME='game-samp'
LOCK=Path('/run/lock/storypulse-ftp.lock')
PROTECTED={'samp03svr','samp-npc','announce','sm_panel_stats.amx'}


def options(value):
    if not isinstance(value,dict) or set(value)!={'enabled','username'} or type(value['enabled']) is not bool:
        raise ftp.ServiceError('Configuración FTP del juego no válida.')
    if value['enabled']:
        ftp.username(value['username'])
        if value['username'] in ('sm-samp',SYSTEM_USER):raise ftp.ServiceError('Elegí un nombre de usuario FTP independiente.')
    elif value['username']!='':raise ftp.ServiceError('La cuenta FTP desactivada no necesita usuario.')
    return dict(value)


def preflight(name):
    ftp.configure_platform()
    ftp.username(name)
    config=ftp.load()
    if any(u['username']==name or u['root']==ROOT_NAME or u.get('game')=='samp' for u in config['users']):
        raise ftp.ServiceError('El usuario o la cuenta FTP de SA-MP ya existe. Elegí otro nombre o revisá la instalación anterior.')
    if len(config['users'])>=ftp.MAX_USERS:raise ftp.ServiceError('Se alcanzó el límite de cuentas FTP.')
    try:pwd.getpwnam(SYSTEM_USER)
    except KeyError:pass
    else:raise ftp.ServiceError('La identidad FTP reservada ya existe sin pertenecer a este juego.')
    if not config['installed'] and not ftp.CONFIG.exists() and (ftp.BASE.exists() or linux.installed(ftp.run,ftp.distribution(),'vsftpd')):
        raise ftp.ServiceError('Existe una instalación FTP ajena al panel; se conserva su configuración.')
    ftp.collision();ftp.firewall_preflight()
    return config


def user_config(item):
    if item.get('game')!='samp' or item['root']!=ROOT_NAME:raise ftp.ServiceError('Raíz FTP del juego no válida.')
    return '\n'.join(['local_root='+str(ROOT),'guest_username='+SYSTEM_USER,'write_enable=YES',
        'download_enable=YES','dirlist_enable=YES','allow_writeable_chroot=YES',
        'cmds_denied=PORT,EPRT,SITE',
        'deny_file={samp03svr,samp-npc,announce,sm_panel_stats.amx,server_monitor_players_*.dat}',
        'hide_file={sm_panel_stats.amx,server_monitor_players_*.dat}',''])


def trusted(info,record,owner=0):
    if info.st_mode&0o002:return False
    value=(record or {}).get('ftp') or {}
    if not value.get('permissions_ready'):return info.st_uid==owner and not info.st_mode&0o022
    owners={owner,value.get('uid')}
    return info.st_uid in owners and info.st_gid==record.get('gid')


def trusted_root(info,record):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o002:return False
    if not info.st_mode&0o020:return True
    value=(record or {}).get('ftp') or {}
    return value.get('permissions_ready') is True and info.st_gid==record.get('gid')


def writable_files(record):
    removal.safe_path(ROOT)
    if not trusted_root(ROOT.stat(),record):raise ftp.ServiceError('La raíz del juego tiene permisos o propietario no válidos.')
    for directory,dirs,files in os.walk(ROOT,followlinks=False):
        current=Path(directory)
        for name in dirs+files:
            path=current/name;info=path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ftp.ServiceError('El juego contiene enlaces o archivos especiales. No se habilitó FTP.')
            os.chown(path,info.st_uid,record['gid'],follow_symlinks=False)
            if path.is_dir():os.chmod(path,0o2770)
            elif path.name in PROTECTED or re.fullmatch(r'server_monitor_players_[01]\.dat',path.name):os.chmod(path,0o750 if path.name in ('samp03svr','samp-npc','announce') else 0o640)
            else:os.chmod(path,0o660)
    # Share the package root with this game's private group, including FTP.
    # The setgid bit keeps new folders/files in that group; no world-write permission.
    os.chown(ROOT,0,record['gid'],follow_symlinks=False)
    os.chmod(ROOT,0o2770)
    if linux.selinux_active(ftp.run):
        # Keep executable game binaries under their existing executable context.
        expression=re.escape(str(ROOT))
        if ftp.run(['semanage','fcontext','-a','-t','public_content_rw_t',expression],check=False).returncode:
            ftp.run(['semanage','fcontext','-m','-t','public_content_rw_t',expression])
        ftp.run(['restorecon',str(ROOT)])
        for name in ('gamemodes','filterscripts','plugins','npcmodes','scriptfiles'):
            if (ROOT/name).is_dir():linux.label_path(ftp.run,'public_content_rw_t',ROOT/name)
        linux.label_path(ftp.run,'public_content_rw_t',ROOT/'server.cfg')


def _ensure_service():
    config=ftp.load()
    if not config['installed']:
        with removal.package_lock():ftp._install({'open_firewall':False},lambda family:None,repository_current=True)
        config=ftp.load()
    required={'ssl_enable':'YES','force_local_logins_ssl':'YES','force_local_data_ssl':'YES',
        'chroot_local_user':'YES','anonymous_enable':'NO','guest_enable':'YES','allow_writeable_chroot':'NO'}
    values=dict(line.split('=',1) for line in (ftp.BASE/'vsftpd.conf').read_text().splitlines() if '=' in line and not line.startswith('#'))
    if any(values.get(key)!=value for key,value in required.items()):raise ftp.ServiceError('La configuración FTP perdió su protección TLS o de aislamiento. Revisala antes de agregar el juego.')
    return config


def create(request,secret,record,save):
    options(request)
    if not isinstance(secret,dict) or set(secret)!={'id','password'} or not re.fullmatch('[a-f0-9]{32}',str(secret['id'])) or not re.fullmatch('[A-Za-z0-9_-]{32,128}',str(secret['password'])):
        raise ftp.ServiceError('Falta una credencial FTP generada por el panel protegido.')
    with LOCK.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        preflight(request['username'])
        config=_ensure_service()
        ftp.run(['useradd','--system','--no-create-home','--gid',str(record['gid']),'--home-dir',str(ROOT),'--shell',linux.executable('nologin'),SYSTEM_USER])
        account=pwd.getpwnam(SYSTEM_USER)
        record['ftp']=dict(id=secret['id'],username=request['username'],uid=account.pw_uid,permissions_ready=True)
        save()
        try:
            writable_files(record)
            item=dict(username=request['username'],root=ROOT_NAME,game='samp',permissions={key:True for key in ftp.PERMISSIONS},enabled=True,
                password_hash=ftp.hash_password(secret['password']),created_at=ftp.now())
            updated={**config,'users':config['users']+[item]}
            ftp.write_auth(updated);ftp.atomic(ftp.CONFIG,(ftp.canonical(updated)+'\n').encode())
            ftp.atomic(ftp.UNIT,ftp.unit_config().encode(),0o644)
            ftp.run(['systemctl','daemon-reload']);ftp.run(['systemctl','enable',ftp.SERVICE]);ftp.run(['systemctl','restart',ftp.SERVICE]);ftp.wait_ready()
            # The game controller already holds the shared firewall lock.
            for port in ('21','50000:50019'):
                ftp.run(['ufw','allow','in','proto','tcp','from','0.0.0.0/0','to','0.0.0.0/0','port',port,'comment','StoryPulse FTP'])
            record['ftp']['host']=ftp.network();save()
        except Exception:
            ftp.write_auth(config);ftp.atomic(ftp.CONFIG,(ftp.canonical(config)+'\n').encode())
            ftp.run(['systemctl','restart',ftp.SERVICE],check=False)
            ftp.run(['userdel',SYSTEM_USER],check=False)
            raise


def remove(record):
    value=record.get('ftp')
    if not value:return
    with LOCK.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        config=ftp.load()
        users=[u for u in config['users'] if not (u.get('game')=='samp' and u['username']==value['username'])]
        if len(users)!=len(config['users']):
            updated={**config,'users':users}
            ftp.write_auth(updated);ftp.atomic(ftp.CONFIG,(ftp.canonical(updated)+'\n').encode())
            if ftp.service_state()=='active':ftp.run(['systemctl','restart',ftp.SERVICE]);ftp.wait_ready()
        try:
            account=pwd.getpwnam(SYSTEM_USER)
            if account.pw_uid!=value['uid'] or account.pw_dir!=str(ROOT):raise ftp.ServiceError('La identidad FTP del juego cambió; no se eliminó otra cuenta.')
            ftp.run(['userdel',SYSTEM_USER])
        except KeyError:pass


def status(record):
    value=(record or {}).get('ftp')
    if not value:return dict(enabled=False)
    config=ftp.load()
    active=any(u.get('game')=='samp' and u['username']==value['username'] and u['enabled'] for u in config['users'])
    cert=ftp.BASE/'tls/server.crt'
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper() if cert.is_file() else ''
    return dict(enabled=active,id=value['id'],username=value['username'],host=value.get('host',''),port=21,
        passive_ports=list(ftp.PASSIVE),protocol='FTP con TLS explícito (FTPS)',directory=str(ROOT),certificate_sha256=fingerprint)
