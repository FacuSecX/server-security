# Server Security Monitor v3.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

PACKAGE_LOCK=Path('/run/lock/storypulse-service-packages.lock')
FIREWALL_LOCK=Path('/run/lock/storypulse-securityctl.lock')

class RemovalError(RuntimeError):
    pass


@contextlib.contextmanager
def package_lock():
    import fcntl
    descriptor=os.open(PACKAGE_LOCK,os.O_CREAT|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(descriptor,'w') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RemovalError('Hay otra instalación o desinstalación en curso.') from None
        yield


def scope(kind,module):
    if kind=='ftp':
        return dict(marker=module.CONFIG,service=module.SERVICE,
                    paths=[Path('/var/lib/storypulse-security/service-versions/ftp.json'),Path('/var/lib/storypulse-security/service-versions/archives/ftp'),Path('/var/backups/storypulse-service-upgrades/ftp'),module.SPOOL,module.BACKUPS,Path('/var/log/storypulse-ftp'),module.PAM,module.UNIT,
                           Path('/etc/logrotate.d/storypulse-ftp'),module.BASE],
                    comment='StoryPulse FTP',spans={((21,21),),((50000,50019),)})
    if kind=='mysql':
        return dict(marker=module.STATE,service=module.SERVICE,
                    paths=[Path('/var/lib/storypulse-security/service-versions/mysql.json'),Path('/var/lib/storypulse-security/service-versions/archives/mysql'),Path('/var/backups/storypulse-service-upgrades/mysql'),Path('/var/lib/mysql'),Path('/var/lib/mysql-files'),Path('/var/log/mysql'),
                           module.BACKUPS,module.TLS,module.CNF,
                           Path('/etc/apt/sources.list.d/storypulse-mysql.list'),
                           Path('/usr/share/keyrings/storypulse-mysql.gpg'),module.BASE],
                    comment='StoryPulse MySQL',spans={((3306,3306),)})
    raise RemovalError('Servicio no permitido.')


def safe_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts)<3:
        raise RemovalError('Ruta de desinstalación insegura.')
    for parent in [path,*path.parents]:
        if not parent.exists() and not parent.is_symlink():continue
        info=parent.lstat()
        if stat.S_ISLNK(info.st_mode):raise RemovalError('Una ruta del servicio usa un enlace simbólico. No se borró nada.')
        if parent!=path and (info.st_uid!=0 or info.st_mode&0o022):
            raise RemovalError('Una carpeta del servicio tiene permisos inseguros.')
    if path.exists() and not (path.is_dir() or path.is_file()):raise RemovalError('Se encontró un archivo especial en una ruta del servicio.')
    return path


def mounts():
    def decode(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
    return [Path(decode(line.split()[4])) for line in Path('/proc/self/mountinfo').read_text().splitlines() if len(line.split())>4]


def validate_paths(paths):
    current=mounts()
    for raw in paths:
        path=safe_path(raw)
        if any(m==path or path in m.parents for m in current):
            raise RemovalError('Una carpeta del servicio contiene un montaje. Desmontalo antes de desinstalar.')
    if not getattr(shutil.rmtree,'avoids_symlink_attacks',False):
        raise RemovalError('La eliminación segura de carpetas requiere el componente Linux actualizado.')


def package_names(kind,module):
    profile=module.distribution();run=module.run
    if profile['family']=='apt':
        output=run(['dpkg-query','-W','-f=${Package}\t${db:Status-Status}\n','vsftpd','mysql*','mariadb*'],check=False).stdout
        names=[row.split('\t')[0].split(':')[0] for row in output.splitlines() if row.endswith('\tinstalled')]
    elif profile['family']=='rpm':names=run(['rpm','-qa','--qf','%{NAME}\n']).stdout.splitlines()
    else:names=run(['pacman','-Qq']).stdout.splitlines()
    if kind=='ftp':allowed=lambda name:name=='vsftpd'
    else:
        engine=getattr(module,'ENGINE','mariadb' if profile['family']=='arch' else 'mysql')
        patterns=(r'mariadb-server(?:-core)?(?:-[0-9]+(?:\.[0-9]+){1,2})?',r'mariadb-plugin-provider-(?:bzip2|lz4|lzma|lzo|snappy)') if engine=='mariadb' else (
            r'mysql(?:8\.4)?(?:-community)?-server(?:-core)?(?:-[0-9]+(?:\.[0-9]+){1,2})?',r'mysql(?:8\.4)?-selinux')
        allowed=lambda name:any(re.fullmatch(pattern,name) for pattern in patterns) or engine=='mariadb' and profile['family']=='arch' and name=='mariadb'
    return sorted({name for name in names if allowed(name)})


def removal_commands(family,packages):
    if not packages:return [],[]
    if any(not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,95}',name) for name in packages):raise RemovalError('Paquete no permitido.')
    if family=='apt':
        return ['apt-get','--simulate','-o','APT::Get::AutomaticRemove=false','purge',*packages],['dpkg','--purge',*packages]
    if family=='rpm':return ['rpm','-e','--test',*packages],['rpm','-e',*packages]
    if family=='arch':return ['pacman','-R','--print','--print-format','%n',*packages],['pacman','-R','--nosave','--noconfirm',*packages]
    raise RemovalError('Distribución no compatible.')


def mysql_client_scope(module,packages):
    engine=getattr(module,'ENGINE','mysql')
    has_server=any(re.fullmatch(r'(?:mysql(?:-community)?|mariadb)-server(?:-core)?(?:-[0-9]+(?:\.[0-9]+){1,2})?',name) for name in packages)
    client=r'mariadb-client(?:-core)?(?:-[0-9]+(?:\.[0-9]+){1,2})?' if engine=='mariadb' else r'mysql(?:-community)?-client(?:-core|-plugins)?(?:-[0-9]+(?:\.[0-9]+){1,2})?'
    return lambda name:has_server and (bool(re.fullmatch(client,name)) or name=='dbconfig-mysql')


def apt_removal_scope(module,packages,output):
    operations=re.findall(r'^(Remv|Purg|Inst|Conf)\s+(\S+)',output,re.M)
    names={name.split(':')[0] for action,name in operations}
    changes=sorted({name for action,name in operations if action not in ('Remv','Purg')})
    if changes:
        raise RemovalError('El gestor propone instalar o configurar paquetes adicionales: '+', '.join(changes[:8])+'. No se continuará.')
    if not set(packages).issubset(names):raise RemovalError('No se pudo validar el alcance de los paquetes a eliminar.')
    allowed=mysql_client_scope(module,packages)
    unexpected=sorted(name for name in names-set(packages) if not allowed(name))
    if unexpected:raise RemovalError('El gestor propone cambiar paquetes ajenos al servicio: '+', '.join(unexpected[:8])+'. No se continuará.')
    return sorted(set(packages)|names)


def package_preflight(module,packages):
    family=module.distribution()['family'];check,command=removal_commands(family,packages)
    if not check:return command
    result=module.run(check,timeout=120,check=False)
    if result.returncode:raise RemovalError('La desinstalación afectaría dependencias o el gestor de paquetes no está disponible. No se detuvo el servicio.')
    if family=='apt':
        if re.search(r'^(?:Inst|Conf)\s+',result.stdout,re.M):
            allowed=mysql_client_scope(module,packages)
            inventory=module.run(['dpkg-query','-W','-f=${Package}\t${db:Status-Status}\n','mysql*','mariadb*','dbconfig-mysql'],check=False).stdout
            clients={row.split('\t')[0].split(':')[0] for row in inventory.splitlines() if row.endswith('\tinstalled')}
            targets=sorted(set(packages)|{name for name in clients if allowed(name)})
            if targets!=sorted(packages):
                check,command=removal_commands(family,targets)
                result=module.run(check,timeout=120,check=False)
                if result.returncode:raise RemovalError('No se pudo resolver la desinstalación sin modificar dependencias compartidas.')
                packages=targets
        expanded=apt_removal_scope(module,packages,result.stdout)
        if expanded!=sorted(packages):
            check,command=removal_commands(family,expanded)
            verified=module.run(check,timeout=120,check=False)
            if verified.returncode or apt_removal_scope(module,expanded,verified.stdout)!=expanded:
                raise RemovalError('Cambió el alcance de la desinstalación. Revisá nuevamente antes de continuar.')
        exact=module.run(['dpkg','--no-act','--purge',*expanded],timeout=120,check=False)
        if exact.returncode:raise RemovalError('Quedan dependencias compartidas que requieren estos paquetes. No se detuvo el servicio ni se borraron datos.')
    if family=='arch' and set(result.stdout.splitlines())!=set(packages):
        raise RemovalError('El gestor propone eliminar otros paquetes. No se continuará.')
    return command


def ftp_identity(module):
    import pwd,grp
    try:identity=pwd.getpwnam(module.GUEST)
    except KeyError:return None,None
    if identity.pw_uid==0 or identity.pw_dir!=str(module.SPOOL/'disabled') or identity.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/usr/bin/nologin'):
        raise RemovalError('El usuario interno FTP tiene una configuración ajena al panel.')
    try:group=grp.getgrnam(module.GUEST)
    except KeyError:group=None
    if group and (group.gr_gid!=identity.pw_gid or group.gr_mem or any(p.pw_name!=module.GUEST and p.pw_gid==group.gr_gid for p in pwd.getpwall())):
        raise RemovalError('El grupo interno FTP se está utilizando fuera del servicio.')
    return identity,group


def owned_rules(module,definition):
    import storypulse_ports as ports
    snapshot=ports.read_snapshot()
    return [r for r in snapshot['rules'] if r['comment']==definition['comment'] and tuple(r['spans']) in definition['spans']
            and r['protocol']=='tcp' and r['direction']=='IN' and r['family']==4 and r['action']=='ALLOW' and not r['interface']]


def validate_request(payload,applying=False):
    allowed={'action','erase_data'}|({'confirm','revision'} if applying else set())
    if not isinstance(payload,dict) or set(payload)!=allowed or payload.get('action')!='uninstall' or payload.get('erase_data') is not True:
        raise RemovalError('La eliminación completa requiere confirmar el borrado de datos.')
    if applying and (payload.get('confirm') is not True or not isinstance(payload.get('revision'),str) or not re.fullmatch('[a-f0-9]{64}',payload['revision'])):
        raise RemovalError('Revisá y confirmá la desinstalación antes de continuar.')


def plan(kind,module,payload,applying=False):
    validate_request(payload,applying)
    definition=scope(kind,module);marker=safe_path(definition['marker'])
    if not marker.is_file():raise RemovalError('El servicio no está administrado por el panel. No se desinstalará una instalación ajena.')
    info=marker.stat()
    if info.st_uid!=0 or info.st_mode&0o077:raise RemovalError('La marca de instalación del servicio tiene permisos inseguros.')
    config=module.load();validate_paths(definition['paths'])
    if kind=='ftp':ftp_identity(module)
    else:
        if module.CNF.exists() and module.TLS.as_posix() not in module.CNF.read_text() and config['installed']:
            raise RemovalError('La configuración del motor fue reemplazada fuera del panel. Revisala antes de desinstalar.')
        repo=Path('/etc/apt/sources.list.d/storypulse-mysql.list')
        if repo.exists() and ('https://repo.mysql.com/apt/debian/' not in repo.read_text() or 'signed-by=/usr/share/keyrings/storypulse-mysql.gpg' not in repo.read_text()):
            raise RemovalError('El repositorio MySQL tiene contenido ajeno al panel.')
        if config['installed'] and module.active()=='active':
            with module.connect() as conn:rows=module.query(conn,'SELECT @@datadir AS directory')
            if not rows or str(rows[0]['directory']).rstrip('/')!='/var/lib/mysql':
                raise RemovalError('MySQL utiliza una carpeta de datos no administrada por el panel.')
    packages=package_names(kind,module);command=package_preflight(module,packages)
    if module.distribution()['family']=='apt' and command:packages=command[2:]
    rules=owned_rules(module,definition)
    import storypulse_versions as versions
    current=versions.installed(kind,module)
    material={'installed_version':current,'kind':kind,'config':config,'packages':packages,'rules':rules,'state':module.service_state() if kind=='ftp' else module.active(),
              'artifacts':[(str(p),hashlib.sha256(p.read_bytes()).hexdigest()) for p in (marker,module.PAM,module.UNIT) if p.is_file()] if kind=='ftp' else
                          [(str(p),hashlib.sha256(p.read_bytes()).hexdigest()) for p in (marker,module.CNF) if p.is_file()]}
    revision=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    detail='todos los usuarios FTP, sus archivos subidos, certificados y respaldos' if kind=='ftp' else 'todas las bases y usuarios de esta instalación, sus datos, certificados y respaldos'
    return dict(ok=True,action='uninstall',installed_version=current,revision=revision,erase_data=True,service='FTP' if kind=='ftp' else 'MySQL / MariaDB',
                packages=packages,paths=[str(p) for p in definition['paths']],users=len(config['users']),
                databases=len(config.get('databases',[])),firewall_rules=len(rules),
                notice='BORRADO PERMANENTE: se eliminarán '+detail+'. Se desinstalan los paquetes del servidor y sólo sus reglas de firewall. '
                       'Se incluyen los clientes dependientes y su selector dbconfig-mysql si queda sin usuarios externos. '
                       'No se puede deshacer. Las dependencias compartidas del sistema y las reglas ajenas se conservan.')


def remove_path(path):
    path=safe_path(path)
    if path.is_dir():shutil.rmtree(path)
    elif path.exists():path.unlink()


def apply(kind,module,payload,repair_monitor):
    with package_lock():
        proposal=plan(kind,module,payload,True)
        if proposal['revision']!=payload['revision']:raise RemovalError('El servicio cambió desde la vista previa. Revisá nuevamente antes de eliminarlo.')
        definition=scope(kind,module);run=module.run;identity,group=ftp_identity(module) if kind=='ftp' else (None,None)
        command=package_preflight(module,proposal['packages'])
        if module.distribution()['family']=='apt' and command and command[2:]!=proposal['packages']:
            raise RemovalError('Cambió el alcance de la desinstalación. Revisá nuevamente antes de continuar.')
        import fcntl
        with FIREWALL_LOCK.open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            for rule in sorted(owned_rules(module,definition),key=lambda r:r['number'],reverse=True):run(['ufw','--force','delete',str(rule['number'])])
            repair_monitor(4)
        if run(['systemctl','is-active',definition['service']],check=False).stdout.strip() in ('active','activating','reloading'):
            run(['systemctl','stop',definition['service']],timeout=180)
        if run(['systemctl','is-active',definition['service']],check=False).stdout.strip() in ('active','activating','reloading','deactivating'):
            raise RemovalError('El servicio no se detuvo. No se borraron sus datos.')
        run(['systemctl','disable',definition['service']],check=False)
        if command:run(command,timeout=720)
        if package_names(kind,module):raise RemovalError('Quedan paquetes del servicio sin eliminar. Los datos se conservaron para reintentar.')
        validate_paths(definition['paths'])
        import storypulse_platform as linux
        if linux.selinux_active(run):
            unique=[module.BASE,module.SPOOL] if kind=='ftp' else [module.CNF,module.TLS]
            for path in unique:
                result=run(['semanage','fcontext','-l','-C']).stdout
                expression=re.escape(str(path))+'(/.*)?'
                if any(line.split()[0]==expression for line in result.splitlines() if line.split()):run(['semanage','fcontext','-d',expression])
        if kind=='ftp' and identity:
            run(['userdel',module.GUEST])
            if group:
                import grp
                try:remaining=grp.getgrnam(module.GUEST)
                except KeyError:remaining=None
                if remaining:run(['groupdel',module.GUEST])
        for path in definition['paths']:remove_path(path)
        if kind=='ftp':
            mask=Path('/etc/systemd/system/vsftpd.service')
            if mask.is_symlink() and os.readlink(mask)=='/dev/null':run(['systemctl','unmask','vsftpd.service'])
        run(['systemctl','daemon-reload'])
        return dict(ok=True,action='uninstall',service=kind,removed_packages=proposal['packages'],removed_paths=proposal['paths'])
