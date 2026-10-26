"""Signed-repository service versions. Package names, paths and commands are fixed locally."""
import datetime as dt
from functools import cmp_to_key,lru_cache
import hashlib,json,os,re,shutil,stat,tempfile,time
from pathlib import Path
import storypulse_platform as linux
import storypulse_archives as archives

CACHE=Path('/var/lib/storypulse-security/service-versions')
BACKUPS=Path('/var/backups/storypulse-service-upgrades')
TTL=1800
DATA_DIR=Path('/var/lib/mysql')
class VersionError(RuntimeError):pass

def valid_version(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~^_-]{0,159}',value):
        raise VersionError('Versión de paquete no válida.')
    return value

def primary(kind,module):
    if kind=='ftp':return 'vsftpd'
    if kind!='mysql':raise VersionError('Servicio no permitido.')
    layout=getattr(module,'LAYOUT',None) or linux.database_layout(module.distribution())
    package=layout['packages'][0]
    if module.distribution()['family']=='apt' and package in ('mysql-server','mariadb-server'):
        cached=getattr(module,'_version_primary',None)
        if cached:return cached
        output=module.run(['apt-cache','depends',package],check=False).stdout
        variants=set(re.findall(r'^\s*(?:Pre)?Depends:\s*((?:mysql|mariadb)-server-[0-9]{1,2}\.[0-9]{1,2})\s*$',output,re.M))
        if len(variants)>1:raise VersionError('No se pudo determinar el paquete real del servidor.')
        if variants:package=variants.pop()
        module._version_primary=package
    return package

def package_version(run,profile,package):
    if profile['family']=='apt':
        r=run(['dpkg-query','-W','-f=${db:Status-Status}\t${Version}\n',package],check=False)
        rows=[line.split('\t',1)[1] for line in r.stdout.splitlines() if line.startswith('installed\t')]
        value=rows[0] if r.returncode==0 and rows else ''
    elif profile['family']=='rpm':
        r=run(['rpm','-q','--qf','%{EPOCHNUM}:%{VERSION}-%{RELEASE}',package],check=False)
        value=r.stdout.strip() if r.returncode==0 else ''
    else:
        r=run(['pacman','-Q',package],check=False);parts=r.stdout.strip().split()
        value=parts[1] if r.returncode==0 and len(parts)==2 and parts[0]==package else ''
    return valid_version(value) if value else ''

def installed(kind,module):
    current=package_version(module.run,module.distribution(),primary(kind,module))
    if not current and kind=='mysql' and module.load().get('installed'):
        names=('mariadb-server-10.5','mariadb-server-10.6','mariadb-server','mariadb') if module.ENGINE=='mariadb' else ('mysql-server-8.0','mysql-server-8.4','mysql8.4-server','mysql-community-server','mysql-server')
        for name in names:
            if name==primary(kind,module):continue
            current=package_version(module.run,module.distribution(),name)
            if current:break
    return current

def compare(run,profile,a,b):
    valid_version(a);valid_version(b)
    if a==b:return 0
    if profile['family']=='apt':
        if run(['dpkg','--compare-versions',a,'gt',b],check=False).returncode==0:return 1
        if run(['dpkg','--compare-versions',a,'lt',b],check=False).returncode==0:return -1
        return 0
    if profile['family']=='rpm':
        output=run(['rpm','--eval','%{lua:print(rpm.vercmp("'+a+'","'+b+'"))}']).stdout.strip()
    else:output=run(['vercmp',a,b]).stdout.strip()
    if not re.fullmatch('-?[0-9]+',output):raise VersionError('No se pudieron comparar las versiones del sistema.')
    return (int(output)>0)-(int(output)<0)

def line(version):
    m=re.match(r'(?:[0-9]+:)?([0-9]+)\.([0-9]+)',version)
    if not m:raise VersionError('No se reconoce la rama del servicio.')
    return tuple(map(int,m.groups()))

def available(kind,module):
    profile=module.distribution();package=primary(kind,module);run=module.run;rows=[]
    if profile['family']=='apt':
        text=run(['apt-cache','madison',package]).stdout
        for raw in text.splitlines():
            parts=[part.strip() for part in raw.split('|')]
            if len(parts)==3 and parts[0]==package:rows.append({'version':valid_version(parts[1]),'architecture':'','repository':'Repositorios APT configurados'})
    elif profile['family']=='rpm':
        text=run(['dnf','-q','--showduplicates','list','--available',package],timeout=120).stdout
        for raw in text.splitlines():
            parts=raw.split()
            if len(parts)==3 and parts[0].rsplit('.',1)[0]==package:
                arch=parts[0].rsplit('.',1)[1]
                if arch in (profile.get('architecture'),'noarch'):
                    version=parts[1] if ':' in parts[1] else '0:'+parts[1]
                    rows.append({'version':valid_version(version),'architecture':arch,'repository':parts[2][:100]})
    else:
        text=run(['pacman','-Si',package],timeout=30).stdout
        values={m[1]:m[2].strip() for m in re.finditer(r'^(Repository|Name|Version|Architecture)\s*:\s*(.+)$',text,re.M)}
        if values.get('Name')==package and values.get('Architecture') in (profile.get('architecture'),'any'):
            rows.append({'version':valid_version(values['Version']),'architecture':values['Architecture'],'repository':values.get('Repository','')[:80]})
    unique={row['version']:row for row in rows}
    if len(unique)>80:raise VersionError('El repositorio ofrece demasiadas versiones; revisá sus fuentes.')
    native=lru_cache(maxsize=256)(lambda a,b:compare(run,profile,a,b))
    rows=sorted(unique.values(),key=cmp_to_key(lambda a,b:native(a['version'],b['version'])),reverse=True)
    for row in rows:
        row['package']=package
        row['id']=hashlib.sha256(json.dumps([kind,profile['id'],profile['version'],package,row['version'],row['architecture']],separators=(',',':')).encode()).hexdigest()
    return rows

def read_cache(kind):
    if kind not in ('ftp','mysql'):raise VersionError('Servicio no permitido.')
    path=CACHE/(kind+'.json')
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:raise VersionError('Actualizá primero el catálogo de versiones.') from None
    with os.fdopen(fd,'r',encoding='utf-8') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>131072:raise VersionError('El catálogo tiene permisos o tamaño no válidos.')
        data=json.load(handle)
    if type(data.get('created_at')) is not int or not 0<=time.time()-data['created_at']<=TTL:raise VersionError('El catálogo venció. Volvé a actualizar los repositorios.')
    return data

def refresh(kind,module):
    import storypulse_uninstall as removal
    with removal.package_lock():return refresh_locked(kind,module)

def refresh_locked(kind,module):
    # Only internal callers holding the package lock may use this function.
    profile=module.distribution()
    if kind=='mysql':module.repository()
    if profile['family']=='apt' and not (kind=='mysql' and getattr(module,'LAYOUT',{}).get('oracle')):module.run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=240)
    elif profile['family']=='rpm':module.run(['dnf','-q','makecache','--refresh'],timeout=240)
    elif profile['family']=='arch':module.run(['pacman','-Sy','--noconfirm'],timeout=240)
    current=installed(kind,module);native=available(kind,module)
    historical,warnings=archives.discover(kind,module,native)
    unique={}
    for row in historical:unique.setdefault(row['version'],row)
    # An active signed repository is preferred when the same version remains available.
    unique.update({r['version']:r for r in native})
    rank=lru_cache(maxsize=256)(lambda a,b:compare(module.run,profile,a,b))
    rows=sorted(unique.values(),key=cmp_to_key(lambda a,b:rank(a['version'],b['version'])),reverse=True)[:archives.LIMIT]
    for row in rows:
        row['id']=hashlib.sha256(json.dumps([kind,profile['id'],profile['version'],row['package'],row['version'],row['architecture'],row.get('source')],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        row['archived']=bool(row.get('source'))
    for row in rows:
        row['upgrade_compatible']=not current or line(row['version'])==line(current)
    eligible=[row for row in rows if row['upgrade_compatible'] and (not current or compare(module.run,profile,row['version'],current)>=0)]
    data=dict(ok=True,service=kind,distribution=profile['name'],profile={k:profile[k] for k in ('id','version','family')},backend=getattr(module,'ENGINE','vsftpd'),created_at=int(time.time()),installed_version=current,versions=rows,upgrade_available=bool(current and eligible and compare(module.run,profile,eligible[0]['version'],current)>0),latest_id=eligible[0]['id'] if eligible else '',catalog_limit=archives.LIMIT,archive_warnings=warnings,notice='Se encontraron '+str(len(rows))+' versiones/revisiones distintas, de más reciente a más antigua, en repositorios activos y archivos oficiales. '+('Se muestran todas las encontradas; el origen no conserva diez versiones para este sistema. ' if len(rows)<archives.LIMIT else '')+'Las históricas se verifican antes de instalar: firma, arquitectura y dependencias. Una versión antigua puede no ser compatible o haber perdido su descarga. '+('Las actualizaciones de Arch permanecen en el repositorio vigente; no se fuerza una mezcla de bibliotecas antiguas. ' if profile["family"]=="arch" else '')+'Las actualizaciones conservan datos y no cambian de rama. '+(' '.join(warnings)))
    CACHE.mkdir(parents=True,exist_ok=True,mode=0o700)
    if CACHE.is_symlink() or CACHE.stat().st_uid!=0 or CACHE.stat().st_mode&0o077:raise VersionError('La carpeta del catálogo tiene permisos inseguros.')
    from storypulse_services import atomic
    atomic(CACHE/(kind+'.json'),json.dumps(data,ensure_ascii=True).encode())
    return data

def select(kind,module,selection,upgrade=False,check_available=False):
    if not isinstance(selection,str) or not re.fullmatch('[a-f0-9]{64}',selection):raise VersionError('Elegí una versión del catálogo actualizado.')
    data=read_cache(kind);profile=module.distribution()
    if data.get('profile')!={k:profile[k] for k in ('id','version','family')}:raise VersionError('Cambió la distribución; actualizá el catálogo.')
    row=next((row for row in data['versions'] if row['id']==selection),None)
    if not row or row['package']!=primary(kind,module):raise VersionError('La versión no pertenece al servicio o ya no está disponible.')
    valid_version(row['version']);current=installed(kind,module)
    if upgrade:
        if not current:raise VersionError('No se detectó el paquete instalado.')
        eligible=[r for r in data['versions'] if line(r['version'])==line(current)]
        if not eligible or eligible[0]['id']!=selection:raise VersionError('Elegí la versión más reciente compatible con la instalación.')
        if compare(module.run,profile,row['version'],current)<=0:raise VersionError('Ya está instalada la versión más reciente compatible.')
    if check_available and not row.get('source') and not any(r['version']==row['version'] and r['package']==row['package'] for r in available(kind,module)):raise VersionError('La versión elegida dejó de estar disponible. Actualizá el catálogo.')
    return row

def apt_targets(kind,module,row):
    targets={row['package']:row['version']}
    cohort={'mysql-community-server','mysql-community-server-core','mysql-community-client','mysql-community-client-core','mysql-community-client-plugins','mysql-common','mysql-client','mysql-server','mariadb-server','mariadb-server-core','mariadb-client','mariadb-client-core','mariadb-common'} if kind=='mysql' else {'vsftpd'}
    if kind=='mysql':
        core=row['package'].replace('-server','-server-core',1)
        if core==row['package']:raise VersionError('No se reconoce el paquete del servidor.')
        check=module.run(['apt-cache','show',core+'='+row['version']],check=False)
        if check.returncode!=0 or not re.search(r'^Version: '+re.escape(row['version'])+r'$',check.stdout,re.M):raise VersionError('No está disponible la versión exacta del núcleo del servidor.')
        targets[core]=row['version'];cohort.add(core)
    pending=list(targets)
    while pending:
        package=pending.pop();text=module.run(['apt-cache','show',package+'='+targets[package]],timeout=30).stdout
        dependencies='\n'.join(re.findall(r'^(?:Pre-Depends|Depends):[^\n]*(?:\n[ \t][^\n]*)*',text,re.M))
        for name,version in re.findall(r'\b([a-z0-9][a-z0-9+.-]*)\s*\(=\s*([^\s)]+)\)',dependencies):
            if name not in cohort and not re.fullmatch(r'(?:mysql(?:-community)?|mariadb)-(?:server|client)(?:-core|-plugins)?(?:-[0-9]{1,2}\.[0-9]{1,2})?',name):continue
            valid_version(version)
            if name in targets and targets[name]!=version:raise VersionError('Las dependencias exactas no son compatibles.')
            if name not in targets:targets[name]=version;pending.append(name)
        if len(targets)>20:raise VersionError('Demasiadas dependencias exactas.')
    return [name+'='+version for name,version in sorted(targets.items())]

def commands(kind,module,row):
    if row.get('source'):
        try:return archives.commands(kind,module,row,CACHE)
        except (archives.ArchiveError,OSError,ValueError,RuntimeError,archives.tarfile.TarError) as exc:raise VersionError('No se pudo preparar la versión histórica; no se forzará la instalación. '+str(exc)[:300]) from exc
    profile=module.distribution();family=profile['family'];package=row['package'];version=valid_version(row['version'])
    if package!=primary(kind,module):raise VersionError('Paquete no permitido.')
    if family=='apt':
        options=['-o','DPkg::Lock::Timeout=120','-o','Dpkg::Options::=--force-confold','--no-remove','--no-install-recommends']
        targets=apt_targets(kind,module,row)
        return ['apt-get','--simulate',*options,'install',*targets],['apt-get','-y',*options,'install',*targets]
    if family=='rpm':
        arch=row['architecture']
        if arch not in (profile.get('architecture'),'noarch'):raise VersionError('Arquitectura no compatible.')
        target=package+'-'+version+'.'+arch
        options=['-y','--setopt=install_weak_deps=False','--setopt=gpgcheck=True','--setopt=*.gpgcheck=True']
        return ['dnf',*options,'--setopt=tsflags=test','install',target],['dnf',*options,'install',target]
    target=package+'='+version
    return ['pacman','-Syu','--print','--print-format','%n %v',target],['pacman','-Syu','--needed','--noconfirm',target]

def install_selected(kind,module,selection):
    row=select(kind,module,selection,check_available=True);check,execute=commands(kind,module,row)
    module.run(check,timeout=900);module.run(execute,timeout=900)
    actual=installed(kind,module)
    if actual!=row['version']:raise VersionError('No se confirmó la versión elegida después de la instalación. Revisá el estado del servicio.')
    return actual

def upgrade_plan(kind,module,payload):
    if not isinstance(payload,dict) or payload.get('action')!='upgrade' or set(payload)-{'action','selection','confirm','revision'}:raise VersionError('Solicitud de actualización no válida.')
    config=module.load()
    if not config['installed']:raise VersionError('Instalá primero el servicio desde el panel.')
    if kind=='mysql' and module.active()!='active':raise VersionError('Iniciá MySQL para verificar su almacenamiento antes de actualizarlo.')
    row=select(kind,module,payload.get('selection'),upgrade=True)
    current=installed(kind,module)
    revision=hashlib.sha256((module.revision(config)+payload['selection']+current).encode()).hexdigest()
    return dict(ok=True,action='upgrade',revision=revision,installed_version=current,target_version=row['version'],notice='Se actualizarán los paquetes a '+row['version']+'. Se conservarán usuarios, permisos, configuración y datos. Se hará una copia privada antes de cambiar el servicio; habrá una interrupción temporal. '+('En Arch se actualizará todo el sistema para evitar una actualización parcial.' if module.distribution()['family']=='arch' else 'No se purgará la instalación ni se harán migraciones entre ramas.'))

def copy_owned(source,destination):
    descriptor=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as origin:
        info=os.fstat(origin.fileno())
        if not stat.S_ISREG(info.st_mode):raise VersionError('El respaldo contiene un archivo especial.')
        with open(destination,'xb') as target:
            shutil.copyfileobj(origin,target,1024*1024)
            os.fchmod(target.fileno(),stat.S_IMODE(info.st_mode));os.fchown(target.fileno(),info.st_uid,info.st_gid)
        os.utime(destination,ns=(info.st_atime_ns,info.st_mtime_ns),follow_symlinks=False)
    return destination

def copy_private(source,destination):
    source=Path(source)
    if not source.exists():return
    from storypulse_uninstall import safe_path,validate_paths
    safe_path(source)
    if source.is_dir():
        validate_paths([source])
        for root,dirs,files in os.walk(source,followlinks=False):
            for name in dirs+files:
                path=Path(root)/name
                if path.is_symlink() or not (path.is_dir() or path.is_file()):raise VersionError('El respaldo contiene enlaces o archivos especiales. No se actualizará.')
        shutil.copytree(source,destination,copy_function=copy_owned)
        for root,dirs,files in os.walk(source,followlinks=False):
            origin=Path(root);info=origin.stat();os.chown(Path(destination)/origin.relative_to(source),info.st_uid,info.st_gid,follow_symlinks=False)
    else:copy_owned(source,destination)

def upgrade(kind,module,payload):
    import storypulse_uninstall as removal
    with removal.package_lock():
        proposal=upgrade_plan(kind,module,payload)
        if payload.get('confirm') is not True or payload.get('revision')!=proposal['revision']:raise VersionError('Revisá y confirmá nuevamente la actualización.')
        row=select(kind,module,payload['selection'],True,True);check,execute=commands(kind,module,row)
        module.run(check,timeout=900)
        active=(module.service_state() if kind=='ftp' else module.active())=='active'
        removal.safe_path(BACKUPS);removal.safe_path(BACKUPS/kind)
        for folder in (BACKUPS,BACKUPS/kind):
            if folder.exists() and (folder.stat().st_uid!=0 or folder.stat().st_mode&0o077):raise VersionError('La carpeta de respaldos tiene permisos inseguros.')
        backup=BACKUPS/kind/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(4).hex())
        backup.mkdir(parents=True,mode=0o700);os.chmod(BACKUPS,0o700);os.chmod(BACKUPS/kind,0o700)
        paths=[module.BASE]+([module.PAM,module.UNIT] if kind=='ftp' else [])
        if kind=='mysql':
            data_dir=removal.database_directory(module)
            with module.connect() as conn:rows=module.query(conn,'SELECT @@datadir AS directory')
            if not rows or str(rows[0]['directory']).rstrip('/')!=str(data_dir):raise VersionError('La base usa un almacenamiento ajeno al panel.')
            paths.extend([data_dir,module.CNF,module.TLS])
            size=sum(p.stat().st_size for root,dirs,files in os.walk(data_dir,followlinks=False) for p in (Path(root)/name for name in files) if p.is_file() and not p.is_symlink())
            if shutil.disk_usage(backup).free<size+512*1024**2:raise VersionError('No hay espacio para el respaldo completo de la base. No se detuvo el servicio.')
        try:
            module.run(['systemctl','stop',module.SERVICE],timeout=180)
            state=(module.service_state() if kind=='ftp' else module.active())
            if state in ('active','activating','reloading','deactivating'):raise VersionError('No se pudo detener el servicio para respaldarlo.')
            if kind=='mysql':module.run(['systemctl','mask',module.SERVICE])
            for number,path in enumerate(paths):copy_private(path,backup/(str(number)+'-'+path.name))
            from storypulse_services import atomic
            atomic(backup/'manifest.json',json.dumps({'service':kind,'installed_version':proposal['installed_version'],'target_version':row['version'],'paths':[(str(path),str(number)+'-'+path.name) for number,path in enumerate(paths)],'complete':True}).encode())
            module.run(execute,timeout=900)
            actual=installed(kind,module)
            if actual!=row['version']:raise VersionError('El gestor no confirmó la versión seleccionada.')
            if kind=='mysql':module.run(['systemctl','unmask',module.SERVICE])
            if active:
                module.run(['systemctl','start',module.SERVICE]);module.wait_ready()
            return dict(ok=True,action='upgrade',installed_version=actual,backup=str(backup))
        except Exception as error:
            try:
                if kind=='mysql':module.run(['systemctl','unmask',module.SERVICE],check=False)
                if active:module.run(['systemctl','start',module.SERVICE],check=False)
            except Exception:pass
            raise VersionError('La actualización no se completó. Los datos no se borraron. Revisá el servicio y el respaldo privado: '+str(backup)) from error
