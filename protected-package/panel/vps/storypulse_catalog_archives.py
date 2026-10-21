"""Official package history for the fixed service catalog; signatures remain mandatory."""
import concurrent.futures,datetime as dt,hashlib,html,json,os,re,shutil,stat,time,urllib.parse,urllib.request,xmlrpc.client
from pathlib import Path
from types import SimpleNamespace
import storypulse_archives as old
import storypulse_versions as versions

LIMIT=5
# These are fixed upstream distribution build services, not URLs supplied by the browser.
old.HOSTS.update({'koji.fedoraproject.org','kojipkgs.fedoraproject.org','download.docker.com','mirror.stream.centos.org','packages.redis.io'})

def rpc(hub,method,*args):
 if hub not in ('https://kojihub.stream.centos.org/kojihub','https://koji.fedoraproject.org/kojihub') or method not in ('getPackage','listBuilds','listRPMs','queryRPMSigs'):raise RuntimeError('Archivo no permitido.')
 request=urllib.request.Request(hub,data=xmlrpc.client.dumps(args,method,allow_none=True).encode(),headers={'Content-Type':'text/xml','User-Agent':'ServerSecurityMonitor/2.0'})
 with urllib.request.build_opener(old.Redirect()).open(request,timeout=18) as response:
  old.safe_url(response.url);body=response.read(4*1024**2+1)
 if len(body)>4*1024**2 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise RuntimeError('Respuesta de archivo inválida.')
 return xmlrpc.client.loads(body)[0][0]

def koji(module,native):
 p=module.distribution();r=module.recipe;epel=r['id'] in ('certbot','fail2ban','phpmyadmin');hub='https://koji.fedoraproject.org/kojihub' if epel else 'https://kojihub.stream.centos.org/kojihub'
 source=r['source'];info=rpc(hub,'getPackage',source)
 if not isinstance(info,dict) or type(info.get('id')) is not int:return []
 builds=rpc(hub,'listBuilds',{'__starstar':True,'packageID':info['id'],'state':1,'queryOpts':{'limit':160,'order':'-creation_time'}})
 major=p['version'].split('.')[0];chosen=[];seen=set();architecture=p['architecture']
 for b in builds:
  release=b.get('release','');version=b.get('version','')
  if b.get('draft') or type(b.get('build_id')) is not int or not re.fullmatch(r'[0-9A-Za-z.+~^_-]+',release) or not re.search(r'(?:\.|_)el'+major+r'(?:[+_.]|$)',release):continue
  identity=version+'-'+release
  if identity in seen:continue
  seen.add(identity);chosen.append(b)
  if len(chosen)>=12:break
 def describe(b):
  rpms=rpc(hub,'listRPMs',{'__starstar':True,'buildID':b['build_id'],'arches':[architecture,'noarch']})
  main=next((x for x in rpms if x.get('name')==r['package'] and x.get('arch') in (architecture,'noarch') and not x.get('draft')),None)
  if not main:return None
  artifacts=[]
  for x in rpms:
   if not re.fullmatch(r['cohort'],x.get('name','')) or x.get('arch') not in (architecture,'noarch') or x.get('metadata_only'):continue
   signatures=rpc(hub,'queryRPMSigs',x['id']);keys=sorted(s.get('sigkey','') for s in signatures if re.fullmatch('[a-f0-9]{8,16}',s.get('sigkey','')))
   if keys:artifacts.append({**{k:x[k] for k in ('name','version','release','arch','epoch')},'key':keys[-1]})
  if not any(x['name']==r['package'] for x in artifacts):return None
  return old.row(r['package'],str(main.get('epoch') or 0)+':'+main['version']+'-'+main['release'],main['arch'],'catalog-koji',{'hub':'epel' if epel else 'centos','source_package':source,'artifacts':artifacts},'EPEL / Fedora Koji' if epel else 'CentOS Stream Koji')
 result=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for value in pool.map(describe,chosen):
   if value:result.append(value)
 return result

def debian(module,native):
 p=module.distribution();package=module.recipe['package'];maximum=native[0]['version'] if native else '999999.0';architecture=old.arch(p)
 data=json.loads(old.fetch('https://snapshot.debian.org/mr/binary/'+package+'/'));candidates=[]
 for item in data.get('result',[]):
  v=item.get('binary_version','')
  if re.fullmatch(r'[0-9][A-Za-z0-9.+:~^_-]{0,159}',v) and versions.compare(module.run,p,v,maximum)<=0 and not any(v==x['version'] for x in native):candidates.append(v)
 candidates=list(dict.fromkeys(candidates))[:18]
 def describe(v):
  data=json.loads(old.fetch('https://snapshot.debian.org/mr/binary/'+package+'/'+urllib.parse.quote(v,safe='')+'/binfiles?fileinfo=1'))
  candidates=[x for x in data.get('result',[]) if x.get('architecture') in (architecture,'all')]
  for item in candidates:
   for info in data.get('fileinfo',{}).get(item['hash'],[]):
    archive=info.get('archive_name');stamp=info.get('first_seen','')
    if archive not in ('debian','debian-security') or not re.fullmatch(r'\d{8}T\d{6}Z',stamp):continue
    if archive=='debian-security' and not re.search(r'deb'+re.escape(p['version'])+r'(?:u[0-9]+)?',v):continue
    stamp=(dt.datetime.strptime(stamp,'%Y%m%dT%H%M%SZ')+dt.timedelta(hours=6)).strftime('%Y%m%dT%H%M%SZ')
    return old.row(package,v,item['architecture'],'debian',{'timestamp':stamp,'archive':archive},'Debian Snapshot · '+archive)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:out=[x for x in pool.map(describe,candidates) if x]
 return out[:max(0,5-len(native))]

def archlinux(module):
 p=module.distribution();package=module.recipe['package'];base='https://archive.archlinux.org/packages/'+package[0]+'/'+package+'/';out=[]
 for raw in old.links(base):
  name=urllib.parse.unquote(raw);match=re.fullmatch(re.escape(package)+r'-([0-9][A-Za-z0-9.+:~^_-]*-[0-9]+)-(x86_64|aarch64|any)\.pkg\.tar\.(zst|xz)',name)
  if match and match[2] in (p['architecture'],'any'):out.append(old.row(package,match[1],match[2],'arch',{'filename':raw},'Arch Linux Archive'))
 return out

def centos_pool(module,native):
 p=module.distribution();r=module.recipe;major=p['version'].split('.')[0];base='https://mirror.stream.centos.org/'+major+'-stream/AppStream/'+p['architecture']+'/os/Packages/'
 names=[html.unescape(x) for x in re.findall(r'''href=['"]([^'"]+)''',old.fetch(base,16*1024**2).decode('utf-8'),re.I)];out=[];epoch=native[0]['version'].split(':',1)[0] if native and ':' in native[0]['version'] else '0'
 for name in names:
  match=re.fullmatch(re.escape(r['package'])+r'-([0-9][A-Za-z0-9.+~^_-]*)\.'+re.escape(p['architecture'])+r'\.rpm',name)
  if not match:continue
  value=match[1]
  if not re.search(r'\.el'+major+r'(?:[+_.]|$)',value):continue
  files=[]
  for candidate in names:
   m=re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)-'+re.escape(value)+r'\.('+re.escape(p['architecture'])+r'|noarch)\.rpm',candidate)
   if m and re.fullmatch(r['cohort'],m[1]):files.append(candidate)
  out.append(old.row(r['package'],epoch+':'+value,p['architecture'],'catalog-centos-pool',{'files':files},'CentOS Stream · paquetes oficiales firmados'))
 return out

def discover(module,native):
 p=module.distribution();warnings=[]
 if p['id']=='centos':
  out=[]
  for provider in ((koji,) if module.recipe['id']=='phpmyadmin' else (koji,centos_pool)):
   try:out.extend(provider(module,native))
   except (OSError,RuntimeError,ValueError,KeyError,xmlrpc.client.Error) as error:warnings.append('Archivo '+provider.__name__+': '+type(error).__name__)
  return out,warnings
 try:
  if p['id']=='arch':return archlinux(module),[]
  if p['id']=='debian':return debian(module,native),[]
  seed=native or [dict(package=module.recipe['package'],version='999999.0',architecture=p['architecture'])]
  return old.ubuntu(module.recipe['id'],module,seed),[]
 except (OSError,RuntimeError,ValueError,KeyError,xmlrpc.client.Error) as error:
  return [],['Archivo oficial no disponible ('+type(error).__name__+'); se conserva el repositorio activo.']

def workspace(module,row):
 import storypulse_uninstall as removal
 root=module.CACHE/'packages'/module.recipe['id']/row['id'];removal.safe_path(root)
 root.mkdir(parents=True,exist_ok=True,mode=0o700)
 for path in (module.CACHE,module.CACHE/'packages',root.parent,root):
  if path.is_symlink() or path.stat().st_uid!=0:raise RuntimeError('Caché de paquetes insegura.')
  path.chmod(0o700)
 return root

def apt_proxy(module,row,root):
 p=module.distribution();source=row['source'];stamp=source.get('timestamp','')
 if not re.fullmatch(r'\d{8}T\d{6}Z',stamp):raise RuntimeError('Fecha histórica inválida.')
 if source['provider']=='debian':
  archive=source.get('archive','debian')
  if p['id']!='debian' or archive not in ('debian','debian-security'):raise RuntimeError('Archivo incompatible.')
  url='https://snapshot.debian.org/archive/'+archive+'/'+stamp+'/';suite=p['codename']+'-security' if archive=='debian-security' else 'sid';key='/usr/share/keyrings/debian-archive-keyring.gpg';components='main'
 else:
  suite=source.get('suite','')
  if p['id']!='ubuntu' or suite not in (p['codename'],p['codename']+'-updates',p['codename']+'-security'):raise RuntimeError('Edición de Ubuntu incompatible.')
  url='https://snapshot.ubuntu.com/ubuntu/'+stamp+'/';key='/usr/share/keyrings/ubuntu-archive-keyring.gpg';components='main universe restricted multiverse'
 sources=root/'sources';sources.mkdir(exist_ok=True,mode=0o700)
 for oldfile in sources.iterdir():
  if oldfile.is_file() or oldfile.is_symlink():oldfile.unlink()
  else:raise RuntimeError('Estructura de repositorio inválida.')
 for path in [Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*')]:
  if path.is_file() and not path.is_symlink() and path.suffix in ('.list','.sources'):shutil.copyfile(path,sources/path.name)
 (sources/'zz-history.list').write_text('deb [arch='+old.arch(p)+' signed-by='+key+' check-valid-until=no] '+url+' '+suite+' '+components+'\n',encoding='utf-8')
 pref=root/'preferences';pref.write_text('Package: *\nPin: origin '+urllib.parse.urlsplit(url).hostname+'\nPin-Priority: -1\n\nPackage: '+row['package']+'\nPin: version '+row['version']+'\nPin-Priority: 990\n',encoding='utf-8')
 lists=root/'lists';lists.mkdir(exist_ok=True,mode=0o700);(lists/'partial').mkdir(exist_ok=True,mode=0o700)
 options=old.apt_options(root)
 def run(args,**kw):return module.run([args[0],*options,*args[1:]] if args[0] in ('apt-get','apt-cache') else args,**kw)
 proxy=SimpleNamespace(**{**vars(module),'run':run});run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=300)
 targets=module.apt_targets(proxy,row);text=pref.read_text(encoding='utf-8')
 for target in targets:
  package,version=target.split('=',1)
  if package!=row['package']:text+='\nPackage: '+package+'\nPin: version '+version+'\nPin-Priority: 990\n'
 # Ranged dependencies such as Certbot/acme also need access to their own signed source.
 siblings=set()
 for target in targets:
  metadata=proxy.run(['apt-cache','show',target],check=False).stdout
  for field in re.findall(r'^(?:Pre-Depends|Depends): (.+)$',metadata,re.M):
   for name in re.findall(r'(?:^|,|\|)\s*([a-z0-9][a-z0-9+.-]*)',field):
    if re.fullmatch(module.recipe['cohort'],name):siblings.add(name)
 if len(siblings)>24:raise RuntimeError('Demasiados paquetes compañeros.')
 for name in sorted(siblings):text+='\nPackage: '+name+'\nPin: origin '+urllib.parse.urlsplit(url).hostname+'\nPin-Priority: 990\n'
 pref.write_text(text,encoding='utf-8');return proxy,options

def arch_files(module,row,root):
 r=module.recipe;p=module.distribution();name=r['package'];architecture=row['architecture'];version=versions.valid_version(row['version']);files=[]
 if architecture not in (p['architecture'],'any'):raise RuntimeError('Arquitectura histórica incompatible.')
 base='https://archive.archlinux.org/packages/'+name[0]+'/'+name+'/'
 filename=urllib.parse.unquote(row['source'].get('filename',''))
 if not re.fullmatch(re.escape(name)+'-'+re.escape(version)+'-'+re.escape(architecture)+r'\.pkg\.tar\.(?:zst|xz)',filename):raise RuntimeError('Archivo Arch inválido.')
 # Split PHP packages must have identical versions. Other shared libraries are never downgraded.
 names=[name]+(['php'] if r['id']=='php' else [])
 for package in names:
  url='https://archive.archlinux.org/packages/'+package[0]+'/'+package+'/'
  choices=[filename] if package==name else [urllib.parse.unquote(x) for x in old.links(url) if re.fullmatch(re.escape(package)+'-'+re.escape(version)+'-'+re.escape(architecture)+r'\.pkg\.tar\.(?:zst|xz)',urllib.parse.unquote(x))]
  if not choices:raise RuntimeError('Falta un paquete compañero de la misma versión.')
  target=root/choices[0];old.download(url+urllib.parse.quote(target.name),target,1024**3);old.download(url+urllib.parse.quote(target.name)+'.sig',Path(str(target)+'.sig'),32768)
  module.run(['pacman-key','--verify',str(target)+'.sig',str(target)],timeout=60)
  meta=module.run(['pacman','-Qp',str(target)]).stdout.strip()
  if meta!=package+' '+version:raise RuntimeError('El paquete Arch no coincide con el catálogo.')
  files.append(str(target))
 return files

def rpm_files(module,row,root):
 p=module.distribution();r=module.recipe;s=row['source'];files=[]
 if p['id']!='centos' or s.get('hub') not in ('epel','centos') or s.get('source_package')!=r['source']:raise RuntimeError('Archivo RPM incompatible.')
 base='https://kojipkgs.fedoraproject.org/packages/' if s['hub']=='epel' else 'https://kojihub.stream.centos.org/kojifiles/packages/'
 for item in s.get('artifacts',[]):
  name=item.get('name','');version=item.get('version','');release=item.get('release','');architecture=item.get('arch','');key=item.get('key','')
  if not re.fullmatch(r['cohort'],name) or not re.fullmatch('[a-f0-9]{8,16}',key) or architecture not in (p['architecture'],'noarch') or not all(re.fullmatch('[0-9A-Za-z.+~^_-]+',v) for v in (version,release)):raise RuntimeError('RPM histórico inválido.')
  full=str(item.get('epoch') or 0)+':'+version+'-'+release
  if not re.search(r'(?:\.|_)el'+p['version'].split('.')[0]+r'(?:[+_.]|$)',release):raise RuntimeError('El RPM pertenece a otra distribución.')
  filename=name+'-'+version+'-'+release+'.'+architecture+'.rpm'
  url=base+r['source']+'/'+version+'/'+release+'/data/signed/'+key+'/'+architecture+'/'+filename
  target=root/filename;old.download(url,target,1024**3)
  verification=module.run(['rpmkeys','--checksig','--verbose',str(target)]).stdout
  if re.search(r'NOT OK|NOKEY|BAD|NOTTRUSTED',verification,re.I) or not re.search(r'(?:Signature|signatures).*\bOK\b',verification,re.I):raise RuntimeError('Firma RPM no válida o clave no confiable.')
  if module.run(['rpm','-qp','--qf','%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}',str(target)]).stdout.strip()!=name+'|'+full+'|'+architecture:raise RuntimeError('Contenido RPM distinto del catálogo.')
  files.append(str(target))
 if not any(Path(f).name.startswith(r['package']+'-') for f in files):raise RuntimeError('Falta el paquete principal.')
 return files

def _commands(module,row):
 p=module.distribution();provider=row.get('source',{}).get('provider')
 if not provider:return module.native_commands(module,row)
 root=workspace(module,row)
 if provider in ('debian','ubuntu'):
  proxy,options=apt_proxy(module,row,root);check,apply=module.native_commands(proxy,row)
  return [check[0],*options,*check[1:]],[apply[0],*options,*apply[1:]]
 if provider=='arch':
  files=arch_files(module,row,root)
  return ['pacman','-U','--print','--print-format','%n %v',*files],['pacman','-U','--needed','--noconfirm',*files]
 if provider=='catalog-centos-pool':
  if p['id']!='centos':raise RuntimeError('Distribución incompatible.')
  base='https://mirror.stream.centos.org/'+p['version'].split('.')[0]+'-stream/AppStream/'+p['architecture']+'/os/Packages/';files=[];r=module.recipe
  for filename in row['source'].get('files',[]):
   match=re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)-'+re.escape(row['version'].split(':',1)[-1])+r'\.('+re.escape(p['architecture'])+r'|noarch)\.rpm',filename)
   if not match or not re.fullmatch(r['cohort'],match[1]):raise RuntimeError('Archivo RPM fuera de la receta.')
   target=root/filename;old.download(base+filename,target,1024**3)
   verification=module.run(['rpmkeys','--checksig','--verbose',str(target)]).stdout
   if re.search(r'NOT OK|NOKEY|BAD|NOTTRUSTED',verification,re.I) or not re.search(r'(?:Signature|signatures).*\bOK\b',verification,re.I):raise RuntimeError('Firma RPM no válida.')
   expected=match[1]+'|'+row['version']+'|'+match[2]
   if module.run(['rpm','-qp','--qf','%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}',str(target)]).stdout.strip()!=expected:raise RuntimeError('RPM distinto de la selección.')
   files.append(str(target))
  if not any(Path(f).name.startswith(r['package']+'-') for f in files):raise RuntimeError('Falta el paquete principal.')
  opts=['-y','--setopt=gpgcheck=True','--setopt=localpkg_gpgcheck=True','--setopt=*.gpgcheck=True','--setopt=install_weak_deps=False']
  return ['dnf',*opts,'--setopt=tsflags=test','install',*files],['dnf',*opts,'install',*files]
 if provider=='catalog-koji':
  files=rpm_files(module,row,root);opts=['-y','--setopt=gpgcheck=True','--setopt=localpkg_gpgcheck=True','--setopt=*.gpgcheck=True','--setopt=install_weak_deps=False']
  return ['dnf',*opts,'--setopt=tsflags=test','install',*files],['dnf',*opts,'install',*files]
 raise RuntimeError('Origen de paquete no permitido.')

def commands(module,row):
 if not row.get('source'):return module.native_commands(module,row)
 root=workspace(module,row);marker=root/'prepared.json';saved=None
 try:
  fd=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'r',encoding='utf-8') as handle:
   info=os.fstat(handle.fileno())
   if stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077 and info.st_size<65536:saved=json.load(handle)
 except (FileNotFoundError,ValueError):pass
 def sha(path):
  value=hashlib.sha256()
  with path.open('rb') as handle:
   for block in iter(lambda:handle.read(1024*1024),b''):value.update(block)
  return value.hexdigest()
 if saved and saved.get('id')==row['id'] and 0<=time.time()-saved.get('time',0)<=300:
  valid=True
  for name,expected in saved.get('files',{}).items():
   path=root/name
   if path.parent!=root or path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or sha(path)!=expected:valid=False;break
  if valid and len(saved.get('commands',[]))==2:return saved['commands']
 check,execute=_commands(module,row)
 files={path.name:sha(path) for path in root.iterdir() if path.is_file() and not path.is_symlink() and (path.suffix in ('.rpm','.deb','.zst','.xz'))}
 temp=marker.with_suffix('.tmp');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as handle:json.dump(dict(id=row['id'],time=time.time(),files=files,commands=[check,execute]),handle)
 temp.chmod(0o600);os.replace(temp,marker)
 return check,execute
