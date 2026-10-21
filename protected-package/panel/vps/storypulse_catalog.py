"""Bounded, fixed-action native service catalog with signed package transactions."""
import datetime as dt,hashlib,json,os,re,shutil,stat,subprocess,time
from functools import cmp_to_key,lru_cache
from pathlib import Path
from types import SimpleNamespace
import storypulse_platform as linux
import storypulse_versions as versions
import storypulse_uninstall as removal
import storypulse_catalog_archives as history
import storypulse_webapps as webapps
import sys
import storypulse_service_flow as flow
from storypulse_catalog_recipes import SERVICES,recipe

STATE=Path('/var/lib/storypulse-security/catalog-services')
CACHE=Path('/var/cache/storypulse-security/catalog-services')
CONFIG=Path('/etc/server-monitor-services')
TTL=1800
class CatalogError(RuntimeError):pass

def run(args,input=None,timeout=45,check=True):
 result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout,env={**os.environ,'PATH':linux.SAFE_PATH,'LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'},stdin=subprocess.DEVNULL if input is None else None)
 if len(result.stdout)+len(result.stderr)>4*1024**2:raise CatalogError('La respuesta del gestor supera el límite permitido.')
 if check and result.returncode:raise CatalogError(('Falló '+args[0]+': '+(result.stderr or result.stdout))[-2400:])
 return result

def distribution():return linux.detect()
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def strict(body,allowed):
 if not isinstance(body,dict) or set(body)-set(allowed):raise CatalogError('Parámetros no permitidos.')

def service(body):
 kind=body.get('service')
 if not isinstance(kind,str) or kind not in SERVICES:raise CatalogError('Servicio no permitido.')
 return kind

def private_dir(path):
 removal.safe_path(path);path.mkdir(mode=0o700,parents=True,exist_ok=True)
 if path.stat().st_uid!=0:raise CatalogError('Directorio de catálogo inseguro.')
 path.chmod(0o700)

def read(path,missing=None):
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:return missing
 with os.fdopen(fd,'r',encoding='utf-8') as handle:
  info=os.fstat(handle.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>256*1024:raise CatalogError('Archivo de servicio inseguro.')
  return json.load(handle)

def write(path,value):
 private_dir(path.parent);removal.safe_path(path)
 temp=path.with_name(path.name+'.tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as handle:
  json.dump(value,handle,ensure_ascii=False);handle.flush();os.fsync(handle.fileno())
 os.chmod(temp,0o600);os.replace(temp,path)

def manifest(kind):return read(STATE/(kind+'.json'))
def recorded_unit(r,owned):
 if r['id']=='certbot' and owned and 'unit' in owned:
  unit=owned['unit']
  if not isinstance(unit,str) or unit not in ('','certbot.timer','certbot-renew.timer'):raise CatalogError('Unidad de renovación Certbot no permitida.')
  r['unit']=unit
 return r

def definition(kind,p):
 owned=manifest(kind)
 return recorded_unit(recipe(kind,p,run,owned.get('primary') if owned else None),owned)
def version(p,package):return versions.package_version(run,p,package)

def adapter(r,p):return SimpleNamespace(recipe=r,CACHE=CACHE,run=run,distribution=lambda:p,apt_targets=apt_targets,native_commands=native_commands)

def native_rows(r,p):
 package=r['package'];rows=[]
 if p['family']=='apt':
  output=run(['apt-cache','madison',package],check=False).stdout
  for line in output.splitlines():
   parts=[x.strip() for x in line.split('|')]
   if len(parts)==3 and parts[0]==package:rows.append(dict(package=package,version=versions.valid_version(parts[1]),architecture=history.old.arch(p),repository='APT · repositorios firmados'))
 elif p['family']=='rpm':
  output=run(['dnf','-q','--showduplicates','list','--available',package],timeout=120,check=False).stdout
  for line in output.splitlines():
   parts=line.split()
   if len(parts)==3 and parts[0].rsplit('.',1)[0]==package and parts[0].rsplit('.',1)[1] in (p['architecture'],'noarch'):
    rows.append(dict(package=package,version=versions.valid_version(parts[1] if ':' in parts[1] else '0:'+parts[1]),architecture=parts[0].rsplit('.',1)[1],repository='DNF · '+parts[2][:80]))
 else:
  output=run(['pacman','-Si',package],check=False).stdout
  values=dict(re.findall(r'^(Repository|Name|Version|Architecture)\s*:\s*(.+)$',output,re.M))
  if values.get('Name')==package and values.get('Architecture') in (p['architecture'],'any'):
   rows.append(dict(package=package,version=versions.valid_version(values['Version']),architecture=values['Architecture'],repository='Arch · '+values.get('Repository','')))
 return rows

def remember_repository(kind,paths):
 write(CACHE/('repository-'+kind+'.json'),{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
def cleanup_repository(kind):
 if kind not in ('docker','redis'):return
 marker=CACHE/('repository-'+kind+'.json');owned=read(marker,{})
 allowed={'/etc/yum.repos.d/server-monitor-'+kind+'.repo','/etc/pki/rpm-gpg/SERVER-MONITOR-'+kind.upper()}
 if set(owned)-allowed:raise CatalogError('Manifiesto de repositorio inválido.')
 for raw,expected in owned.items():
  path=Path(raw);removal.safe_path(path)
  if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==expected:path.unlink()
 if marker.exists():marker.unlink()

def repository(r,p):
 if p['family']=='rpm' and r['id'] in ('certbot','fail2ban','wireguard','phpmyadmin') and not linux.installed(run,p,'epel-release'):
  run(['dnf','-y','--setopt=gpgcheck=True','install','epel-release'],timeout=300)
 if p['family']=='rpm' and r['id']=='redis':
  major=p['version'].split('.')[0]
  if major not in ('9','10'):raise CatalogError('Redis RPM no está definido para esta edición.')
  path=Path('/etc/yum.repos.d/server-monitor-redis.repo');removal.safe_path(path)
  if not path.exists():
   key=Path('/etc/pki/rpm-gpg/SERVER-MONITOR-REDIS');removal.safe_path(key)
   content=history.old.fetch('https://packages.redis.io/gpg',32768)
   private_dir(CACHE);temp=CACHE/'redis.asc';temp.write_bytes(content);temp.chmod(0o600)
   text=run(['gpg','--batch','--show-keys','--with-colons',str(temp)]).stdout
   fingerprints=[line.split(':')[9] for line in text.splitlines() if line.startswith('fpr:')]
   if not fingerprints or fingerprints[0]!='54318FA4052D1E61A6B6F7BB5F4349D6BF53AA0C':raise CatalogError('La clave Redis no coincide con la oficial.')
   key.write_bytes(content);key.chmod(0o644);run(['rpm','--import',str(key)])
   path.write_text('[server-monitor-redis]\nname=Redis official EL '+major+'\nbaseurl=https://packages.redis.io/rpm/rockylinux'+major+'\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/SERVER-MONITOR-REDIS\n',encoding='utf-8');path.chmod(0o644);temp.unlink();remember_repository(r['id'],[path,key])
  elif path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise CatalogError('Repositorio Redis inseguro.')
 if p['family']=='rpm' and r['id']=='docker':
  path=Path('/etc/yum.repos.d/server-monitor-docker.repo')
  if not path.exists():
   removal.safe_path(path)
   key=Path('/etc/pki/rpm-gpg/SERVER-MONITOR-DOCKER');removal.safe_path(key)
   content=history.old.fetch('https://download.docker.com/linux/centos/gpg',32768)
   private_dir(CACHE);temp=CACHE/'docker.asc';temp.write_bytes(content);temp.chmod(0o600)
   text=run(['gpg','--batch','--show-keys','--with-colons',str(temp)]).stdout
   if '060A61C51B558A7F742B77AAC52FEB6B621E9F35' not in [line.split(':')[9] for line in text.splitlines() if line.startswith('fpr:')]:raise CatalogError('La clave Docker no coincide con la oficial.')
   key.write_bytes(content);key.chmod(0o644);run(['rpm','--import',str(key)])
   path.write_text('[server-monitor-docker]\nname=Docker CE official\nbaseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/SERVER-MONITOR-DOCKER\n',encoding='utf-8');path.chmod(0o644);temp.unlink();remember_repository(r['id'],[path,key])
  elif path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise CatalogError('Repositorio Docker inseguro.')


def refresh(body):
 if isinstance(body,dict) and body.get('service')=='wordpress':return webapps.refresh(sys.modules[__name__],body)
 strict(body,{'service'});kind=service(body)
 with removal.package_lock():
  p=distribution();r=definition(kind,p);repository(r,p)
  if p['family']=='apt':run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=300)
  elif p['family']=='rpm':run(['dnf','-q','makecache','--refresh'],timeout=300)
  else:run(['pacman','-Sy','--noconfirm'],timeout=300)
  # Metadata can resolve a versioned PHP/PostgreSQL package only after the refresh.
  r=definition(kind,p);native=list({x['version']:x for x in native_rows(r,p)}.values())
  native.sort(key=cmp_to_key(lambda a,b:versions.compare(run,p,a['version'],b['version'])),reverse=True)
  historic,warnings=history.discover(adapter(r,p),native) if len(native)<5 else ([],[])
  unique={}
  for row in historic:unique.setdefault(row['version'],row)
  unique.update({x['version']:x for x in native})
  compare=lru_cache(maxsize=512)(lambda a,b:versions.compare(run,p,a,b))
  rows=sorted(unique.values(),key=cmp_to_key(lambda a,b:compare(a['version'],b['version'])),reverse=True)[:5]
  installed=version(p,r['package']);owned=webapps.own(sys.modules[__name__],kind) if kind=='phpmyadmin' else manifest(kind)
  for row in rows:
   row['id']=digest([kind,p['id'],p['version'],row]);row['archived']=bool(row.get('source'))
   row['upgrade_compatible']=not installed or branch(kind,row['version'])==branch(kind,installed)
  notice='Versiones/revisiones reales del sistema detectado, ordenadas de más reciente a más antigua. Se comprueban firma y dependencias antes de instalar. '
  if len(rows)<5:notice+='El origen conserva '+str(len(rows))+' opciones; no se sustituyen por paquetes de otra distribución. '
  if kind=='redis' and p['id']=='arch':notice+='Este sistema puede ofrecer Valkey en lugar de Redis; no se cambia de producto automáticamente. '
  eligible=[x for x in rows if x['upgrade_compatible'] and (not installed or compare(x['version'],installed)>0)]
  result=dict(ok=True,service=kind,label=r['label'],created_at=int(time.time()),profile={k:p[k] for k in ('id','version','family','architecture')},versions=rows,installed_version=installed,managed=bool(owned),notice=notice+' '.join(warnings),latest_id=eligible[0]['id'] if eligible else '',note=r['note'])
  write(CACHE/(kind+'.json'),result);return result

def branch(kind,value):
 numbers=re.match(r'(?:[0-9]+:)?([0-9]+)(?:\.([0-9]+))?',value)
 if not numbers:raise CatalogError('Rama de servicio no reconocida.')
 return numbers[1] if kind=='postgresql' else numbers[1]+'.'+str(numbers[2] or '0')

def select(kind,p,identity):
 if not isinstance(identity,str) or not re.fullmatch('[a-f0-9]{64}',identity):raise CatalogError('Identificador de versión inválido.')
 data=read(CACHE/(kind+'.json'))
 if not data or type(data.get('created_at')) is not int or not 0<=time.time()-data['created_at']<=TTL:raise CatalogError('Actualizá el catálogo: venció su validez de 30 minutos.')
 if data.get('profile')!={k:p[k] for k in ('id','version','family','architecture')}:raise CatalogError('El catálogo corresponde a otro sistema.')
 row=next((x for x in data['versions'] if x['id']==identity),None)
 if not row:raise CatalogError('La versión no pertenece al catálogo vigente.')
 return row

def apt_targets(module,row):
 r=module.recipe;targets={row['package']:versions.valid_version(row['version'])};pending=list(targets)
 while pending:
  package=pending.pop();output=module.run(['apt-cache','show',package+'='+targets[package]],check=False).stdout
  if not output:raise CatalogError('El paquete histórico ya no está disponible: '+package)
  for field in re.findall(r'^(?:Pre-Depends|Depends): (.+)$',output,re.M):
   for name,exact in re.findall(r'(?:^|,)\s*([a-z0-9][a-z0-9+.-]*)(?:\:[a-z0-9]+)?\s*\(=\s*([^) ]+)\)',field):
    if not re.fullmatch(r['cohort'],name):continue
    versions.valid_version(exact)
    if name in targets and targets[name]!=exact:raise CatalogError('Dependencias exactas incompatibles.')
    if name not in targets:targets[name]=exact;pending.append(name)
  if len(targets)>24:raise CatalogError('El conjunto del servicio supera el límite.')
 return [name+'='+value for name,value in sorted(targets.items())]

def native_commands(module,row):
 p=module.distribution();r=module.recipe
 if row['package']!=r['package']:raise CatalogError('Paquete principal incompatible.')
 v=versions.valid_version(row['version']);package=row['package']
 if p['family']=='apt':
  targets=apt_targets(module,row)
  if r['id']=='docker':targets.append('docker-cli')
  options=['-o','DPkg::Lock::Timeout=120','-o','Dpkg::Options::=--force-confold','--no-remove','--no-install-recommends']
  return ['apt-get','--simulate',*options,'install',*targets],['apt-get','-y',*options,'install',*targets]
 if p['family']=='rpm':
  options=['-y','--setopt=gpgcheck=True','--setopt=*.gpgcheck=True','--setopt=localpkg_gpgcheck=True','--setopt=install_weak_deps=False']
  target=package+'-'+v+'.'+row['architecture']
  return ['dnf',*options,'--setopt=tsflags=test','install',target],['dnf',*options,'install',target]
 current=native_rows(r,p)
 if not any(x['version']==v for x in current):raise CatalogError('La versión Arch requiere el archivo firmado.')
 return ['pacman','-Sp','--print-format','%n %v',package],['pacman','-Syu','--needed','--noconfirm',package]

def package_inventory(p,dependencies=None):
 if p['family']=='apt':
  fields='${Package}\t${db:Status-Status}\t${Version}'+('\t${Depends}' if dependencies is not None else '')+'\n'
  output=run(['dpkg-query','-W','-f='+fields],check=False).stdout
  inventory={}
  for line in output.splitlines():
   parts=line.split('\t')
   if len(parts) not in (3,4) or parts[1]!='installed':continue
   inventory[parts[0]]=parts[2]
   if dependencies is not None and len(parts)==4:dependencies[parts[0]]=parts[3]
  return inventory
 if p['family']=='rpm':
  output=run(['rpm','-qa','--qf','%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']).stdout
 else:
  output=run(['pacman','-Q']).stdout
 return {parts[0]:parts[1] for line in output.splitlines() if len(parts:=line.split())==2}

def status(body):
 strict(body,set());p=distribution();rows=[];package_dependencies={};inventory=package_inventory(p,package_dependencies);states={}
 def unit_active(unit):
  if unit not in states:states[unit]=run(['systemctl','is-active',unit],check=False).stdout.strip()=='active'
  return states[unit]
 dependencies=webapps.dependency_info(sys.modules[__name__],p,inventory,unit_active)
 for kind in SERVICES:
  if kind in webapps.APPS:continue
  owned=manifest(kind);selected=owned.get('primary') if owned else None
  if not selected and p['family']=='apt' and kind in ('php','postgresql'):
   pattern=r'php[0-9]{1,2}\.[0-9]{1,2}-fpm' if kind=='php' else r'postgresql-[0-9]{1,2}'
   meta='php-fpm' if kind=='php' else 'postgresql'
   candidates=[name for name in inventory if re.fullmatch(pattern,name)]
   candidates.sort(key=lambda name:tuple(map(int,re.findall(r'[0-9]+',name))),reverse=True)
   depends=set(re.findall(r'(?<![A-Za-z0-9+.-])('+pattern+r')(?=[^A-Za-z0-9+.-]|$)',package_dependencies.get(meta,'')))
   preferred=[name for name in candidates if name in depends]
   selected=(dependencies['php_package'] if kind=='php' and dependencies['php_package'] else next(iter(preferred or candidates),None))
  r=recorded_unit(recipe(kind,p,run,selected,resolve_default=False),owned)
  installed=inventory.get(r['package'],'')
  if not installed and owned:installed=next((inventory.get(x,'') for x in owned.get('packages',[]) if x==owned.get('primary')), '')
  units=[r['unit']] if r['unit'] else []
  if kind=='php' and dependencies['php_package']==r['package']:units.append('server-monitor-webphp.service')
  if kind=='nginx' and dependencies['front_kind']=='nginx' and dependencies['front_unit']=='server-monitor-webnginx.service':units.append(dependencies['front_unit'])
  active_units=[unit for unit in dict.fromkeys(units) if installed and unit_active(unit)];active=bool(active_units)
  used_by=dependencies['apps'] if (kind=='php' and dependencies['php_package']==r['package']) or kind==dependencies['front_kind'] else []
  row=dict({k:r[k] for k in ('id','label','description','category','icon','note')},installed=bool(installed),installed_version=installed,managed=bool(owned),phase=owned.get('phase','') if owned else '',active=active,state='Activo' if active else 'Herramientas instaladas' if installed and kind in ('certbot','wireguard') else 'Instalado, detenido' if installed else 'Sin instalar',used_by=used_by,active_units=active_units)
  if kind=='php':row['components']=dependencies['components']
  rows.append(row)
 rows.extend(webapps.status(sys.modules[__name__],p,inventory,dependencies))
 return dict(ok=True,distribution=p['name'],services=rows)

def removal_commands(r,p,packages):
 if not packages:return [],[]
 if any(not re.fullmatch(r['cohort'],x) for x in packages):raise CatalogError('El manifiesto contiene paquetes ajenos al servicio.')
 if p['family']=='apt':return ['apt-get','--simulate','-o','APT::Get::AutomaticRemove=false','purge',*packages],['dpkg','--purge',*packages]
 if p['family']=='rpm':return ['rpm','-e','--test',*packages],['rpm','-e',*packages]
 return ['pacman','-R','--print','--print-format','%n',*packages],['pacman','-R','--nosave','--noconfirm',*packages]

def apt_removal_set(r,packages,output):
 operations=re.findall(r'^(Remv|Purg|Inst|Conf)\s+(\S+)',output,re.M)
 if any(action in ('Inst','Conf') for action,name in operations):raise CatalogError('La resolución intenta instalar o configurar otros paquetes.')
 changed={name.split(':')[0] for action,name in operations}
 if not set(packages).issubset(changed):raise CatalogError('No se confirmó el conjunto de paquetes a eliminar.')
 for name in changed-set(packages):
  if not re.fullmatch(r['cohort'],name):raise CatalogError('La eliminación afectaría paquetes ajenos: '+name+'.')
  if r['id']=='php':
   prefix=re.match(r'php[0-9]+\.[0-9]+',r['package'])
   if prefix and re.match(r'php[0-9]+\.[0-9]+',name) and not name.startswith(prefix[0]+'-'):raise CatalogError('Otra versión PHP requiere una dependencia compartida.')
  if r['id']=='postgresql':
   major=re.search(r'-([0-9]+)$',r['package']);other=re.search(r'-([0-9]+)(?:-|$)',name)
   if major and other and major[1]!=other[1]:raise CatalogError('Otro servidor PostgreSQL requiere una dependencia compartida.')
 return sorted(changed)


def validate_removal(r,p,packages):
 packages=sorted(set(packages));check,apply=removal_commands(r,p,packages)
 if not check:return apply
 output=run(check,timeout=120).stdout
 if p['family']=='apt':
  try:expanded=apt_removal_set(r,packages,output)
  except CatalogError:
   if r['package'] not in packages or packages==[r['package']]:raise
   packages=[r['package']];check,apply=removal_commands(r,p,packages)
   output=run(check,timeout=120).stdout;expanded=apt_removal_set(r,packages,output)
  if expanded!=packages:
   check,apply=removal_commands(r,p,expanded)
   verified=apt_removal_set(r,expanded,run(check,timeout=120).stdout)
   if verified!=expanded:raise CatalogError('Cambió la resolución de dependencias. Revisá nuevamente antes de eliminar.')
  run(['dpkg','--no-act','--purge',*expanded],timeout=120)
 elif p['family']=='arch' and set(output.split())!=set(packages):raise CatalogError('El gestor propone eliminar paquetes ajenos.')
 return apply



def apache_dependency_configuration(path,p):
 # Installing PHP-FPM creates Apache integration files before Apache is installed.
 # Accept only files owned by installed PHP-FPM packages, never an existing site.
 expected='/etc/apache2' if p['family']=='apt' else '/etc/httpd'
 if str(path)!=expected or path.is_symlink() or not path.is_dir():return False
 entries=list(path.rglob('*'))
 if any(item.is_symlink() for item in entries):return False
 files=[item for item in entries if not item.is_dir()]
 if not files:return True
 for item in files:
  if item.is_symlink() or not item.is_file():return False
  if p['family']=='apt':
   result=run(['dpkg-query','-S',str(item)],check=False)
   owners=[line.rsplit(': ',1)[0].split(':',1)[0] for line in result.stdout.splitlines() if ': ' in line]
   if result.returncode or not owners or any(not re.fullmatch(r'php[0-9]+\.[0-9]+-fpm',owner) for owner in owners):return False
  else:
   command=['rpm','-qf','--qf','%{NAME}',str(item)] if p['family']=='rpm' else ['pacman','-Qoq',str(item)]
   result=run(command,check=False)
   if result.returncode or result.stdout.strip()!='php-fpm':return False
 return True


def check_existing(r,p,owned,action):
 current=version(p,r['package'])
 if action=='install':
  if owned and owned.get('phase')=='error' and owned.get('profile')=={k:p[k] for k in ('id','version','family','architecture')}:return current
  if current or owned:raise CatalogError('El servicio ya existe. Usá actualizar o eliminar su instalación administrada.')
  conflicts=[str(Path(x)) for x in r['paths'] if Path(x).exists() or Path(x).is_symlink()]
  if r['id']=='apache':conflicts=[raw for raw in conflicts if not apache_dependency_configuration(Path(raw),p)]
  if conflicts:raise CatalogError('Hay configuración o datos previos ajenos al panel: '+', '.join(conflicts[:4])+'. No se reemplazarán.')
  if r['id']=='redis' and any(name.startswith('valkey') for name in package_inventory(p)):raise CatalogError('Valkey ya está instalado. No se reemplaza automáticamente por Redis.')
  if r['id']=='postfix':
   inventory=package_inventory(p)
   if any(re.match(r'^(?:exim4?-|sendmail)',name) for name in inventory):raise CatalogError('Existe otro servidor de correo. No se reemplazará automáticamente.')
  port={'nginx':80,'apache':80,'postgresql':5432,'redis':6379,'postfix':25}.get(r['id'])
  if port and run(['ss','-H','-ltn','sport = :'+str(port)]).stdout.strip():raise CatalogError('El puerto local '+str(port)+' ya está ocupado por otro proceso. No se reemplazará.')
  for unit in [r['unit'],*r['extra_units']]:
   if unit and run(['systemctl','is-enabled',unit],check=False).stdout.strip()=='masked':raise CatalogError('El servicio está enmascarado por el administrador.')
 else:
  if not owned:raise CatalogError('Servicio ajeno al panel: no se permite actualizarlo ni borrarlo.')
  if owned.get('profile')!={k:p[k] for k in ('id','version','family','architecture')}:raise CatalogError('La instalación pertenece a otro perfil de sistema.')
 return current


CONTROL_ACTIONS=('start','stop','restart')

def control_plan(body):
 strict(body,{'service','action'});kind=service(body);action=body.get('action')
 if action not in CONTROL_ACTIONS:raise CatalogError('Acción de servicio no permitida.')
 p=distribution();inventory=package_inventory(p);deps=webapps.dependency_info(sys.modules[__name__],p,inventory)
 row=next(item for item in status({})['services'] if item['id']==kind)
 if not row['installed']:raise CatalogError('El servicio no está instalado.')
 if kind in webapps.APPS:
  if not row['managed']:raise CatalogError('La aplicación no pertenece al panel.')
  units=['server-monitor-webphp.service',deps['front_unit']]
 elif kind=='docker':units=['docker.socket',definition(kind,p)['unit']]
 elif kind=='nginx' and deps['front_unit']=='server-monitor-webnginx.service':units=[deps['front_unit']]
 elif kind=='php' and deps['php_package']==definition(kind,p)['package']:
  units=[definition(kind,p)['unit'],'server-monitor-webphp.service']
 else:units=[definition(kind,p)['unit']]
 units=list(dict.fromkeys(unit for unit in units if unit))
 if not units:raise CatalogError('Este componente instala herramientas y no tiene un servicio que iniciar o detener.')
 active={unit:run(['systemctl','is-active',unit],check=False).stdout.strip() for unit in units}
 warning='Se '+{'start':'iniciará','stop':'detendrá','restart':'reiniciará'}[action]+' el servicio.'
 if kind in webapps.APPS or row.get('used_by'):warning+=' El servidor web y PHP pueden estar compartidos por WordPress y phpMyAdmin.'
 result=dict(ok=True,service=kind,label=SERVICES[kind][0],action=action,installed_version=row['installed_version'],distribution=p['name'],units=units,warning=warning)
 result['revision']=digest([result,active]);return result

def control_apply(body):
 strict(body,{'service','action','revision','confirm'})
 if body.get('confirm') is not True or not isinstance(body.get('revision'),str) or not re.fullmatch('[a-f0-9]{64}',body['revision']):raise CatalogError('Revisá y confirmá el cambio.')
 with removal.package_lock():
  reviewed=control_plan({key:value for key,value in body.items() if key not in ('revision','confirm')})
  if reviewed['revision']!=body['revision']:raise CatalogError('El estado cambió. Revisá la operación nuevamente.')
  kind=body['service'];action=body['action'];units=reviewed['units']
  if action!='stop' and (kind in ('nginx','apache') or kind in webapps.APPS):flow.open_web_ports()
  if action!='stop' and kind in webapps.APPS:
   from storypulse_wordpress_db import ensure_database
   ensure_database(sys.modules[__name__],distribution())
  for unit in (list(reversed(units)) if action=='stop' else units):
   if action!='stop':run(['systemctl','reset-failed',unit],check=False)
   if action=='start':run(['systemctl','enable','--now',unit],timeout=120)
   else:run(['systemctl',action,unit],timeout=120)
   if action=='stop':
    if run(['systemctl','is-active',unit],check=False).stdout.strip()=='active':raise CatalogError('No se pudo detener '+unit+'.')
   else:flow.wait_service(run,unit)
  if action!='stop':
   if kind in webapps.APPS:
    context=sys.modules[__name__];p=distribution();stack=webapps.front(context,p,package_inventory(p))
    apps={app for app in webapps.APPS if webapps.own(context,app)}
    webapps.publish(context,p,stack,apps,stack['frontuser']);webapps.verify(context,kind,stack)
   else:wait_ready(definition(kind,distribution()))
  return dict(ok=True,service=kind,action=action,message=SERVICES[kind][0]+': '+{'start':'iniciado','stop':'detenido','restart':'reiniciado'}[action]+'.')


def plan(body):
 if isinstance(body,dict) and body.get('action') in CONTROL_ACTIONS:return control_plan(body)
 if isinstance(body,dict) and isinstance(body.get('service'),str) and body.get('service') in webapps.APPS:return webapps.plan(sys.modules[__name__],body)
 strict(body,{'service','action','selection','erase_data'});kind=service(body);action=body.get('action')
 if action not in ('install','upgrade','uninstall'):raise CatalogError('Acción no permitida.')
 p=distribution();r=definition(kind,p);owned=manifest(kind);current=check_existing(r,p,owned,action)
 if action=='uninstall' and kind=='nginx':
  import storypulse_cloudflare as cloudflare
  if cloudflare.enabled():raise CatalogError('Desactivá primero la protección Cloudflare desde Gestionar servicios → Nginx.')
 if action=='uninstall' and kind in ('nginx','apache','php') and any(webapps.own(sys.modules[__name__],app) for app in webapps.APPS):raise CatalogError('Primero eliminá phpMyAdmin y WordPress: comparten el servidor web y PHP.')
 result=dict(ok=True,service=kind,label=r['label'],action=action,installed_version=current,distribution=p['name'],note=r['note'])
 if action=='uninstall':
  if body.get('erase_data') is not True or 'selection' in body:raise CatalogError('Confirmá el borrado permanente de sus datos.')
  paths=owned.get('paths',[])
  if not isinstance(paths,list) or any(x not in r['paths'] for x in paths):raise CatalogError('Rutas de instalación inválidas.')
  removal.validate_paths([Path(x) for x in paths]);inventory=package_inventory(p)
  packages=sorted(x for x in owned.get('packages',[]) if x in inventory)
  command=validate_removal(r,p,packages)
  if p['family']=='apt' and command:packages=command[2:]
  result.update(packages=packages,paths=paths,version=current,warning='Elimina permanentemente los datos y la configuración propios del servicio. Conserva dependencias compartidas y servicios externos.')
 else:
  if 'erase_data' in body:raise CatalogError('Parámetros no permitidos.')
  row=select(kind,p,body.get('selection'));r['package']=row['package']
  if definition(kind,p)['package']!=row['package']:raise CatalogError('El paquete del catálogo ya no coincide con el sistema.')
  if action=='upgrade' and (not current or branch(kind,current)!=branch(kind,row['version']) or versions.compare(run,p,row['version'],current)<=0):raise CatalogError('La actualización debe ser más reciente y de la misma rama; no se borran datos para actualizar.')
  if kind in ('nginx','apache'):flow.web_preflight()
  if owned and owned.get('phase')=='error' and row['version']!=owned.get('selected_version'):raise CatalogError('Elegí la misma versión para reparar la instalación incompleta.')
  commands=history.commands(adapter(r,p),row);output=run(commands[0],timeout=600).stdout
  if p['family']=='apt' and re.search(r'^(?:Remv|Purg)\s',output,re.M):raise CatalogError('La instalación eliminaría paquetes existentes.')
  result.update(selection=row['id'],version=row['version'],package=row['package'],warning=('Se habilitarán TCP 80 y 443 en UFW y se iniciará el servidor web para acceso mediante la IP. HTTPS requiere un certificado. ' if kind in ('nginx','apache') else '')+'Paquetes firmados y dependencias comprobadas; el servicio se habilita para el arranque y se verifica su funcionamiento.')
 if kind=='docker' and action!='uninstall' and p['family']=='apt':result['packages']=[r['package'],'docker-cli']
 result['revision']=digest([result,owned]);return result


def put(path,text,mode=0o640):
 path=Path(path);removal.safe_path(path);path.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'w',encoding='utf-8') as handle:handle.write(text)
 path.chmod(mode)

def override(r,text):
 unit=r['unit'];put('/etc/systemd/system/'+unit+'.d/90-server-monitor.conf','[Service]\n'+text)

def configure(r,p):
 kind=r['id'];base=CONFIG/kind;private_dir(base);base.chmod(0o755);f=p['family'];apt=f=='apt';rpm=f=='rpm'
 if kind=='nginx':
  import storypulse_cloudflare as cloudflare
  if cloudflare.enabled():
   front=cloudflare.discover();run(['nginx','-t','-c',front['main']]);return
  root=r['site'];put(root+'/index.html','<!doctype html><title>Nginx</title><p>Nginx instalado.</p>',0o644)
  worker='www-data' if apt else 'nginx' if rpm else 'http'
  config=r['config'];put(config,'user '+worker+';\nworker_processes auto;\nerror_log /var/log/nginx/error.log;\npid /run/nginx.pid;\nevents { worker_connections 512; }\nhttp { access_log /var/log/nginx/access.log; server { listen 80; server_name localhost; root '+root+'; } }\n')
  nginx='/usr/bin/nginx' if f=='arch' else '/usr/sbin/nginx'
  run(['nginx','-t','-c',config]);override(r,'Type=simple\nExecStartPre=\nExecStart=\nExecStart='+nginx+' -c '+config+' -g "daemon off;"\nExecReload=\nExecReload=/bin/kill -HUP $MAINPID\n')
 elif kind=='apache':
  modules='/usr/lib/apache2/modules' if apt else '/usr/lib64/httpd/modules' if rpm else '/usr/lib/httpd/modules';binary='/usr/sbin/apache2' if apt else '/usr/sbin/httpd' if rpm else '/usr/bin/httpd'
  root=r['site'];put(root+'/index.html','<!doctype html><title>Apache</title><p>Apache instalado.</p>',0o644)
  user='www-data' if apt else 'apache' if rpm else 'http';serverroot='/etc/apache2' if apt else '/etc/httpd';config=r['config']
  text='ServerRoot '+serverroot+'\nServerName localhost\nListen 80\nPidFile /run/'+r['runtime']+'/httpd.pid\n'
  for name in ('mpm_event','authz_core','unixd','dir'):text+='<IfModule !'+name+'_module>\nLoadModule '+name+'_module '+modules+'/mod_'+name+'.so\n</IfModule>\n'
  text+='User '+user+'\nGroup '+user+'\nErrorLog '+r['log']+'\nDocumentRoot '+root+'\nDirectoryIndex index.html\n<Directory '+root+'>\n Require all granted\n</Directory>\n'
  put(config,text);Path(r['log']).parent.mkdir(parents=True,exist_ok=True)
  run([binary,'-t','-f',config]);override(r,'Type=simple\nRuntimeDirectory=\nRuntimeDirectory='+r['runtime']+'\nExecStartPre=\nExecStart=\nExecStart='+binary+' -f '+config+' -DFOREGROUND\nExecReload=\nExecReload=/bin/kill -USR1 $MAINPID\nExecStop=\nExecStop=/bin/kill -WINCH $MAINPID\n')
 elif kind=='php':
  phpver=re.search(r'php(\d+\.\d+)-fpm',r['package']);binary='/usr/sbin/php-fpm'+phpver[1] if phpver else '/usr/sbin/php-fpm' if rpm else '/usr/bin/php-fpm'
  user='www-data' if apt else 'apache' if rpm else 'http';config=r['config']
  runtime=r['runtime'];Path('/run/'+runtime).mkdir(parents=True,exist_ok=True)
  put(config,'[global]\ndaemonize=no\nerror_log=syslog\nsyslog.ident=server-monitor-php\n[www]\nuser='+user+'\ngroup='+user+'\nlisten=/run/'+runtime+'/php.sock\nlisten.mode=0660\nlisten.owner='+user+'\nlisten.group='+user+'\npm=ondemand\npm.max_children=4\npm.process_idle_timeout=10s\nphp_admin_value[memory_limit]=128M\n')
  run([binary,'-t','--fpm-config',config]);override(r,'Type=simple\nRuntimeDirectory=\nRuntimeDirectory='+runtime+'\nExecStart=\nExecStart='+binary+' --nodaemonize --fpm-config '+config+'\nExecStartPost=\nExecReload=\nExecReload=/bin/kill -USR2 $MAINPID\n')
 elif kind=='docker':
  config=r['config'];put(config,json.dumps({'iptables':False,'ip6tables':False,'bridge':'none','userland-proxy':False,'live-restore':False,'log-driver':'local','log-opts':{'max-size':'10m','max-file':'3'}}))
  run(['dockerd','--validate','--config-file',config]);override(r,'ExecStart=\nExecStart='+linux.executable('dockerd')+' --config-file='+config+' -H fd:// --containerd=/run/containerd/containerd.sock\n')
 elif kind=='redis':
  config=r['config'];put(config,'bind 127.0.0.1 ::1\nprotected-mode yes\nport 6379\ndaemonize no\nsupervised no\ndir /var/lib/redis\nlogfile ""\nmaxmemory 128mb\nmaxmemory-policy noeviction\n')
  Path('/var/lib/redis').mkdir(parents=True,exist_ok=True);run(['chown','redis:redis','/var/lib/redis']);run(['chown','root:redis',config])
  override(r,'Type=simple\nExecStart=\nExecStart=/usr/bin/redis-server '+config+'\nReadWritePaths=/var/lib/redis\n')
 elif kind=='postgresql':
  if apt:
   major=re.search(r'postgresql-(\d+)',r['package'])
   if not major:raise CatalogError('No se reconoce el servidor PostgreSQL versionado.')
   run(['pg_conftool',major[1],'main','set','listen_addresses','localhost']);run(['pg_conftool',major[1],'main','set','max_connections','40'])
  else:
   data='/var/lib/pgsql/data' if rpm else '/var/lib/postgres/data'
   if not Path(data,'PG_VERSION').exists():
    if rpm:run(['postgresql-setup','--initdb'],timeout=120)
    else:run(['runuser','-u','postgres','--','initdb','-D',data,'--auth-local=peer','--auth-host=scram-sha-256'],timeout=120)
   config=Path(data)/'postgresql.conf'
   # The database service owns this directory: write as postgres, never follow a user-controlled link as root.
   settings="\nlisten_addresses = 'localhost'\nmax_connections = 40\nshared_buffers = '64MB'\n"
   program="import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW);os.write(fd,"+repr(settings.encode())+");os.close(fd)"
   run(['runuser','-u','postgres','--','python3','-I','-c',program,str(config)])
 elif kind=='postfix':
  for value in ('inet_interfaces=loopback-only','mynetworks=127.0.0.0/8 [::1]/128','mydestination=localhost','relay_domains=','smtpd_relay_restrictions=permit_mynetworks,reject_unauth_destination'):
   run(['postconf','-e',value])
  run(['postfix','check'])
 elif kind=='fail2ban':
  put('/etc/fail2ban/jail.d/99-server-monitor.local','[DEFAULT]\nbackend=systemd\n[sshd]\nenabled=false\n')
  run(['fail2ban-client','-t'],timeout=30)
 # Certbot is a client/timer; WireGuard tools do not start an unconfigured tunnel.
 if rpm and linux.selinux_active(run):
  # Native directories retain the distribution's existing SELinux policy.
  targets=[r.get('config'),r.get('site'),'/run/'+r['runtime'] if r.get('runtime') else None]
  for target in targets:
   if target and Path(target).exists():run(['restorecon','-RF',target])
 run(['systemctl','daemon-reload'])

def wait_ready(r):
 kind=r['id']
 commands={
  'nginx':['curl','-f','--connect-timeout','2','--max-time','3','--silent','--output','/dev/null','http://127.0.0.1:80/'],
  'apache':['curl','-f','--connect-timeout','2','--max-time','3','--silent','--output','/dev/null','http://127.0.0.1:80/'],
  'redis':['redis-cli','-h','127.0.0.1','-p','6379','ping'],
  'postgresql':['pg_isready','-h','127.0.0.1','-p','5432','-t','2'],
  'docker':['docker','-H','unix:///run/docker.sock','info','--format','{{.ServerVersion}}'],
  'fail2ban':['fail2ban-client','ping'],'certbot':['certbot','--version'],
  'wireguard':['wg','--version'],'postfix':['postfix','status']}
 if kind=='nginx':
  import storypulse_cloudflare as cloudflare
  if cloudflare.enabled():commands['nginx']=['curl','--noproxy','*','-f','--connect-timeout','2','--max-time','5','--silent','--output','/dev/null',*cloudflare.health_args('/'+cloudflare.read_policy()['challenge'])]
 command=commands.get(kind)
 if not command:return
 for attempt in range(10):
  result=run(command,check=False,timeout=10)
  success=result.returncode==0
  if kind=='redis':success=success and result.stdout.strip()=='PONG'
  if kind=='docker':success=success and bool(re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9.+_-]*)',result.stdout.strip()))
  if kind=='fail2ban':success=success and 'pong' in result.stdout.lower()
  if success:return
  if attempt<9:time.sleep(.5)
 raise CatalogError('El servicio no respondió a su comprobación funcional. Se conservan datos y manifiesto para revisar el error.')

def owned_paths(r):return [x for x in r['paths'] if Path(x).exists() or Path(x).is_symlink()]

def apply(body):
 if isinstance(body,dict) and body.get('action') in CONTROL_ACTIONS:return control_apply(body)
 if isinstance(body,dict) and isinstance(body.get('service'),str) and body.get('service') in webapps.APPS:return webapps.apply(sys.modules[__name__],body)
 strict(body,{'service','action','selection','erase_data','revision','confirm'})
 if body.get('confirm') is not True or not isinstance(body.get('revision'),str) or not re.fullmatch('[a-f0-9]{64}',body['revision']):raise CatalogError('Falta confirmación válida.')
 request={k:v for k,v in body.items() if k not in ('revision','confirm')}
 with removal.package_lock():
  reviewed=plan(request)
  if reviewed['revision']!=body['revision']:raise CatalogError('La instalación cambió desde la revisión; volvé a revisar.')
  kind=service(body);p=distribution();r=definition(kind,p);owned=manifest(kind)
  if body['action']=='uninstall':
   paths=[Path(x) for x in reviewed['paths']];removal.validate_paths(paths)
   command=validate_removal(r,p,reviewed['packages'])
   if p['family']=='apt' and command and command[2:]!=reviewed['packages']:raise CatalogError('Cambió el alcance de la eliminación. Revisá nuevamente antes de continuar.')
   units=[r['unit'],*(x for x in r['extra_units'] if '@.' not in x)]
   if kind=='postfix' and p['family']=='apt':units+=['postfix@-.service']
   if kind=='postgresql' and p['family']=='apt':
    units+=['postgresql@'+re.search(r'postgresql-(\d+)',owned['primary'])[1]+'-main.service']
   if kind=='wireguard' and run(['wg','show','interfaces'],check=False).stdout.strip():raise CatalogError('Hay túneles WireGuard activos. Detenelos antes de eliminar sus herramientas.')
   for unit in units:
    if not unit:continue
    run(['systemctl','disable','--now',unit],check=False,timeout=90)
    if run(['systemctl','is-active',unit],check=False).stdout.strip()=='active':raise CatalogError('No se pudo detener '+unit)
   if command:run(command,timeout=600)
   inventory=package_inventory(p)
   if any(x in inventory for x in reviewed['packages']):raise CatalogError('Quedan paquetes del servicio. Se conservan sus datos para reintentar.')
   removal.validate_paths(paths)
   for path in paths:
    if path.is_dir():shutil.rmtree(path)
    elif path.exists():path.unlink()
   cleanup_repository(kind)
   for path in [STATE/(kind+'.json'),CACHE/(kind+'.json')]:
    removal.safe_path(path)
    if path.exists():path.unlink()
   backups=STATE/'backups'/kind;removal.validate_paths([backups])
   if backups.exists():shutil.rmtree(backups)
   cached=CACHE/'packages'/kind;removal.validate_paths([cached])
   if cached.exists():shutil.rmtree(cached)
   run(['systemctl','daemon-reload']);return dict(ok=True,service=kind,action='uninstall',message=r['label']+' eliminado. Dependencias compartidas conservadas.')
  row=select(kind,p,body['selection']);commands=history.commands(adapter(r,p),row);before=package_inventory(p)
  if kind=='postfix' and p['family']=='apt':run(['debconf-set-selections'],input='postfix postfix/main_mailer_type select Local only\npostfix postfix/mailname string localhost\n')
  info=owned or dict(service=kind,profile={k:p[k] for k in ('id','version','family','architecture')},primary=r['package'],packages=[],paths=[])
  info.update(phase='installing',selected_version=row['version']);write(STATE/(kind+'.json'),info)
  masked=[]
  try:
   if kind in ('nginx','apache'):flow.open_web_ports()
   if kind=='docker':run(['systemctl','stop','docker.service','docker.socket'],check=False,timeout=90)
   for unit in [r['unit'],*r['extra_units']]:
    if not unit or kind=='certbot':continue
    run(['systemctl','mask','--runtime',unit]);masked.append(unit)
   if body['action']=='upgrade':
    if r['unit']:run(['systemctl','stop',r['unit']],timeout=90)
    paths=[Path(x) for x in info.get('paths',[]) if not x.startswith('/run/')];removal.validate_paths(paths)
    size=0
    for path in paths:
     if path.is_dir():
      for parent,dirs,files in os.walk(path,followlinks=False):
       for name in files:
        item=Path(parent)/name
        if not item.is_symlink() and item.is_file():size+=item.stat().st_size
     elif path.is_file() and not path.is_symlink():size+=path.stat().st_size
    backup=STATE/'backups'/kind/str(time.time_ns());private_dir(backup)
    if shutil.disk_usage(backup).free<size*1.2+256*1024**2:raise CatalogError('No hay espacio suficiente para respaldar antes de actualizar.')
    for index,path in enumerate(paths):
     if path.is_symlink():raise CatalogError('No se respaldan rutas simbólicas como raíz.')
     if path.is_dir():shutil.copytree(path,backup/str(index),symlinks=True,ignore=lambda parent,names:[name for name in names if not (lambda mode:stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode))((Path(parent)/name).lstat().st_mode)])
     elif path.is_file():shutil.copy2(path,backup/str(index))
    write(backup/'manifest.json',dict(complete=True,paths=[x for x in info.get('paths',[]) if not x.startswith('/run/')],installed_version=info.get('installed_version','')))
    info['last_backup']=str(backup)
   run(commands[1],timeout=1200)
   actual=version(p,r['package'])
   if actual!=row['version']:raise CatalogError('La versión instalada no coincide: '+actual+'; esperada '+row['version'])
   if body['action']=='install':configure(r,p)
   else:run(['systemctl','daemon-reload'])
   for unit in masked:run(['systemctl','unmask','--runtime',unit])
   masked=[];run(['systemctl','daemon-reload'])
   if kind=='certbot' and not r['unit']:r['unit']=recipe(kind,p,run,r['package'])['unit']
   if r['unit']:
    # Certbot packages may use the alternate renewal timer name.
    if kind=='certbot' and run(['systemctl','cat',r['unit']],check=False).returncode:
     alternate='certbot-renew.timer' if r['unit']=='certbot.timer' else 'certbot.timer'
     if run(['systemctl','cat',alternate],check=False).returncode==0:r['unit']=alternate
     else:r['unit']=''
    if r['unit']:
     for reset in [r['unit'],*r['extra_units']]:
      if reset and '@.' not in reset:run(['systemctl','reset-failed',reset],check=False)
     run(['systemctl','enable','--now',r['unit']],timeout=120)
   if r['unit'] and run(['systemctl','is-active',r['unit']],check=False).stdout.strip()!='active':raise CatalogError('El paquete se instaló, pero el servicio no inició. Revisá su registro antes de reintentar.')
   wait_ready(r)
   info.update(phase='installed',installed_version=actual,unit=r['unit'])
  except (RuntimeError,OSError,subprocess.SubprocessError) as error:
   recovery=''
   if body['action']=='upgrade':
    try:
     for unit in masked:run(['systemctl','unmask','--runtime',unit],check=False)
     masked=[];run(['systemctl','daemon-reload'],check=False)
     if r['unit'] and version(p,r['package'])==reviewed['installed_version']:
      run(['systemctl','start',r['unit']],check=False,timeout=90)
      if run(['systemctl','is-active',r['unit']],check=False).stdout.strip()=='active':recovery=' Se volvió a iniciar la versión anterior.'
    except (RuntimeError,OSError,subprocess.SubprocessError):recovery=' Revisá el estado del servicio antes de reintentar.'
   message=str(error)+recovery+(' Respaldo: '+info['last_backup'] if info.get('last_backup') else '')
   info.update(phase='error',error=message[:1400]);raise CatalogError(message) from error
  finally:
   for unit in masked:run(['systemctl','unmask','--runtime',unit],check=False)
   after=package_inventory(p)
   info['packages']=sorted(set(info['packages'])|{name for name in after if name not in before and re.fullmatch(r['cohort'],name)}|({r['package']} if r['package'] in after and (r['package'] not in before or owned) else set()))
   info['paths']=sorted(set(info['paths'])|set(owned_paths(r)));write(STATE/(kind+'.json'),info)
  return dict(ok=True,service=kind,action=body['action'],installed_version=actual,message=r['label']+' '+actual+' instalado. '+r['note'])
