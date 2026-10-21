"""Official historical catalogs and scoped, authenticated package transactions."""
import concurrent.futures,datetime as dt,hashlib,html,json,os,re,shutil,stat,tarfile,tempfile,urllib.parse,urllib.request,urllib.error,xmlrpc.client
from pathlib import Path
from types import SimpleNamespace

LIMIT=10
HOSTS={'snapshot.debian.org','api.launchpad.net','snapshot.ubuntu.com','archive.archlinux.org','repo.mysql.com','cdn.mysql.com','composes.stream.centos.org','kojihub.stream.centos.org'}
class ArchiveError(RuntimeError):pass
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  safe_url(newurl)
  return super().redirect_request(req,fp,code,msg,headers,newurl)
def safe_url(url):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='https' or p.hostname not in HOSTS or p.username or p.password or p.port not in (None,443) or p.fragment:raise ArchiveError('Origen histórico no permitido.')
 return url
def fetch(url,limit=4*1024**2):
 safe_url(url)
 with urllib.request.build_opener(Redirect()).open(urllib.request.Request(url,headers={'User-Agent':'ServerSecurityMonitor/2.0'}),timeout=18) as r:
  safe_url(r.url);data=r.read(limit+1)
 if len(data)>limit:raise ArchiveError('El índice histórico supera el tamaño permitido.')
 return data
def links(url):return [html.unescape(s) for s in re.findall(r'href=[\'"]([^\'"]+)',fetch(url).decode('utf-8'),re.I)]
def arch(profile):return {'x86_64':'amd64','AMD64':'amd64','aarch64':'arm64'}.get(profile['architecture'],profile['architecture'])
def row(package,version,architecture,provider,source,repository):
 from storypulse_versions import valid_version
 return dict(package=package,version=valid_version(version),architecture=architecture,repository=repository,archived=True,source={'provider':provider,**source})
def oracle(kind,module,native):
 if kind!='mysql' or not getattr(module,'LAYOUT',{}).get('oracle'):return []
 p=module.distribution();architecture=arch(p);out=[]
 if architecture!='amd64' or not re.fullmatch(r'\d{1,2}',p['version']):return []
 for branch in ('mysql-8.4-lts','mysql-9.7-lts','mysql-innovation'):
  base='https://repo.mysql.com/apt/debian/pool/'+branch+'/m/mysql-community/'
  for name in links(base):
   match=re.fullmatch(r'mysql-community-server_((?:8\.4|9\.[0-9]+)\.[0-9]+-[0-9]+debian'+p['version']+r')_amd64\.deb',name)
   if match:out.append(row('mysql-community-server',match[1],'amd64','oracle',{'branch':branch},'Archivo oficial Oracle · '+branch))
 return out

def debian(kind,module,native):
 p=module.distribution();package=native[0]['package'];maximum=native[0]['version'];architecture=arch(p)
 from storypulse_versions import compare
 data=json.loads(fetch('https://snapshot.debian.org/mr/binary/'+package+'/'))
 candidates=[]
 for item in data.get('result',[]):
  version=item.get('binary_version','')
  if re.fullmatch(r'[0-9][A-Za-z0-9.+:~^_-]{0,159}',version) and compare(module.run,p,version,maximum)<=0 and not any(version==r['version'] for r in native):candidates.append(version)
 # The API orders versions natively, newest first. Never substitute another distribution.
 candidates=list(dict.fromkeys(candidates))[:LIMIT*2];out=[]
 def describe(version):
  data=json.loads(fetch('https://snapshot.debian.org/mr/binary/'+package+'/'+urllib.parse.quote(version,safe='')+'/binfiles?fileinfo=1'))
  hashes={r['hash'] for r in data.get('result',[]) if r.get('architecture')==architecture}
  for identity in hashes:
   for info in data.get('fileinfo',{}).get(identity,[]):
    stamp=info.get('first_seen','')
    if info.get('archive_name')=='debian' and re.fullmatch(r'\d{8}T\d{6}Z',stamp):
     stamp=(dt.datetime.strptime(stamp,'%Y%m%dT%H%M%SZ')+dt.timedelta(hours=6)).strftime('%Y%m%dT%H%M%SZ')
     return row(package,version,architecture,'debian',{'timestamp':stamp},'Debian Snapshot · '+stamp[:8])
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for result in pool.map(describe,candidates):
   if result:out.append(result)
 return out[:max(0,LIMIT-len(native))]

def ubuntu(kind,module,native):
 p=module.distribution();package=native[0]['package'];architecture=arch(p);series=p['codename']
 if not re.fullmatch('[a-z]+',series):raise ArchiveError('Edición de Ubuntu no válida.')
 params={'ws.op':'getPublishedBinaries','binary_name':package,'exact_match':'true','distro_arch_series':'https://api.launchpad.net/1.0/ubuntu/'+series+'/'+architecture,'ws.size':'300'}
 url='https://api.launchpad.net/1.0/ubuntu/+archive/primary?'+urllib.parse.urlencode(params)
 out={}
 for _ in range(3):
  data=json.loads(fetch(url,8*1024**2))
  for entry in data.get('entries',[]):
   version=entry.get('binary_package_version');date=entry.get('date_published');pocket=entry.get('pocket')
   if not date or pocket not in ('Release','Updates','Security') or entry.get('status') not in ('Published','Superseded') or entry.get('distro_arch_series_link')!=params['distro_arch_series']:continue
   stamp=dt.datetime.fromisoformat(date).astimezone(dt.timezone.utc)+dt.timedelta(minutes=30)
   if stamp<dt.datetime(2023,3,1,tzinfo=dt.timezone.utc):continue
   out.setdefault(version,row(package,version,architecture,'ubuntu',{'timestamp':stamp.strftime('%Y%m%dT%H%M%SZ'),'suite':series+{'Release':'','Updates':'-updates','Security':'-security'}[pocket]},'Ubuntu Snapshot · '+series))
  if len(out)>=LIMIT or not data.get('next_collection_link'):break
  url=data['next_collection_link'];safe_url(url)
 return list(out.values())

def archlinux(kind,module,native):
 p=module.distribution();package=native[0]['package'];architecture=p['architecture'];base='https://archive.archlinux.org/packages/'+package[0]+'/'+package+'/'
 out=[]
 for name in links(base):
  match=re.fullmatch(re.escape(package)+r'-([0-9][A-Za-z0-9.+:~^_-]*-[0-9]+)-'+re.escape(architecture)+r'\.pkg\.tar\.(zst|xz)',name)
  if match:out.append(row(package,match[1],architecture,'arch',{'filename':name},'Arch Linux Archive'))
 return out

def centos_composes(kind,module,native):
 p=module.distribution();major=p['version'].split('.')[0];architecture=p['architecture'];package=native[0]['package']
 base='https://composes.stream.centos.org/stream-'+major+'/production/'
 composes=[s for s in links(base) if re.fullmatch('CentOS-Stream-'+major+r'-\d{8}\.\d+/',s)]
 out=[]
 def describe(compose):
  source=base+compose+'compose/AppStream/'+architecture+'/os/'
  entries=[]
  try:names=links(source+'Packages/')
  except (OSError,ArchiveError):return []
  for name in names:
   match=re.fullmatch(re.escape(package)+r'-([0-9][A-Za-z0-9.+~^_-]*)\.'+re.escape(architecture)+r'\.rpm',name)
   if match:entries.append(row(package,'0:'+match[1],architecture,'centos',{'compose':compose.rstrip('/')},'CentOS Stream '+major+' · '+compose.rstrip('/')))
  return entries
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for entries in pool.map(describe,sorted(composes,reverse=True)[:16]):out.extend(entries)
 return out

def koji_rpc(method,*args):
 if method not in ('getPackage','listBuilds','listRPMs','queryRPMSigs'):raise ArchiveError('Método de archivo no permitido.')
 data=xmlrpc.client.dumps(args,method,allow_none=True).encode()
 request=urllib.request.Request('https://kojihub.stream.centos.org/kojihub',data=data,headers={'Content-Type':'text/xml','User-Agent':'ServerSecurityMonitor/2.0'})
 with urllib.request.build_opener(Redirect()).open(request,timeout=18) as response:
  safe_url(response.url);body=response.read(4*1024**2+1)
 if len(body)>4*1024**2 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ArchiveError('Respuesta histórica inválida.')
 return xmlrpc.client.loads(body)[0][0]

def centos_koji(kind,module,native):
 p=module.distribution();major=p['version'].split('.')[0];package=native[0]['package'];architecture=p['architecture']
 source='vsftpd' if kind=='ftp' else 'mysql8.4' if major=='10' else 'mysql'
 info=koji_rpc('getPackage',source)
 if not isinstance(info,dict) or type(info.get('id')) is not int:raise ArchiveError('No se encontró el paquete oficial en Koji.')
 builds=koji_rpc('listBuilds',{'__starstar':True,'packageID':info['id'],'state':1,'queryOpts':{'limit':120,'order':'-creation_time'}})
 chosen=[];seen=set()
 for build in builds:
  release=build.get('release','');version=build.get('version','')
  if build.get('draft') or type(build.get('build_id')) is not int or not re.fullmatch(r'[0-9A-Za-z.+~^_-]+',release) or not re.search(r'(?:\.|_)el'+major+r'(?:[+_.]|$)',release):continue
  identity=version+'-'+release
  if identity in seen:continue
  seen.add(identity);chosen.append(build)
  if len(chosen)>=LIMIT+4:break
 def describe(build):
  rpms=koji_rpc('listRPMs',{'__starstar':True,'buildID':build['build_id'],'arches':[architecture,'noarch']})
  main=next((r for r in rpms if r.get('name')==package and r.get('arch')==architecture and not r.get('draft') and not r.get('metadata_only')),None)
  if not main:return None
  allowed={package} if kind=='ftp' else {package,source,source+'-common',source+'-errmsg',source+'-libs'}
  artifacts=[]
  for rpm in rpms:
   if rpm.get('name') not in allowed or rpm.get('arch') not in (architecture,'noarch') or rpm.get('metadata_only'):continue
   signatures=koji_rpc('queryRPMSigs',rpm['id'])
   keys=sorted(x.get('sigkey','') for x in signatures if re.fullmatch(r'[a-f0-9]{8,16}',x.get('sigkey','')))
   if keys:
    artifact={k:rpm[k] for k in ('name','version','release','arch','epoch')};artifact['key']=keys[-1];artifacts.append(artifact)
  if not any(x['name']==package for x in artifacts):return None
  epoch=str(main.get('epoch') or 0);version=epoch+':'+main['version']+'-'+main['release']
  return row(package,version,architecture,'centos-koji',{'build':build['build_id'],'source_package':source,'artifacts':artifacts},'CentOS Koji · compilación oficial firmada')
 out=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for value in pool.map(describe,chosen):
   if value:out.append(value)
 return out

def centos(kind,module,native):
 try:rows=centos_koji(kind,module,native)
 except (OSError,ValueError,ArchiveError,xmlrpc.client.Error):rows=[]
 if len(rows)<LIMIT:rows.extend(centos_composes(kind,module,native))
 return rows

def discover(kind,module,native):
 if not native:return [],['El repositorio activo no ofrece el paquete principal.']
 p=module.distribution();provider=oracle if kind=='mysql' and getattr(module,'LAYOUT',{}).get('oracle') else {'debian':debian,'ubuntu':ubuntu,'centos':centos,'arch':archlinux}[p['id']]
 try:return provider(kind,module,native),[]
 except (OSError,ValueError,KeyError,ArchiveError,RuntimeError) as exc:
  return [],['No se pudo completar el archivo oficial '+p['id']+': '+type(exc).__name__+'. Las versiones del repositorio activo siguen disponibles.']

def workspace(cache,kind,identity):
 from storypulse_uninstall import safe_path
 if not re.fullmatch('[a-f0-9]{64}',identity):raise ArchiveError('Identificador histórico inválido.')
 if kind not in ('ftp','mysql'):raise ArchiveError('Servicio histórico no permitido.')
 root=cache/'archives'/kind/identity;safe_path(root);root.mkdir(parents=True,exist_ok=True,mode=0o700)
 for path in (cache,cache/'archives',cache/'archives'/kind,root):
  os.chmod(path,0o700)
  if path.is_symlink() or path.stat().st_uid!=0:raise ArchiveError('Almacenamiento histórico inseguro.')
 return root

def download(url,path,maximum):
 safe_url(url)
 if path.exists():path.unlink()
 temp=path.with_suffix(path.suffix+'.partial')
 try:
  with urllib.request.build_opener(Redirect()).open(url,timeout=30) as response,open(temp,'xb') as target:
   safe_url(response.url);total=0
   while True:
    block=response.read(1024*1024)
    if not block:break
    total+=len(block)
    if total>maximum:raise ArchiveError('El archivo supera el tamaño permitido.')
    target.write(block)
  os.chmod(temp,0o600);os.replace(temp,path)
 finally:
  if temp.exists():temp.unlink()

def apt_options(root):
 for name in ('cache','logs','preferences.d'):(root/name).mkdir(exist_ok=True,mode=0o700)
 config=root/'apt.conf'
 config.write_text('#clear APT::Update::Post-Invoke;\n#clear APT::Update::Post-Invoke-Success;\n')
 return ['-c',str(config),'-o','Dir::Etc::sourcelist=/dev/null','-o','Dir::Etc::sourceparts='+str(root/'sources'),'-o','Dir::Etc::preferences='+str(root/'preferences'),'-o','Dir::Etc::preferencesparts='+str(root/'preferences.d'),'-o','Dir::State::lists='+str(root/'lists'),'-o','Dir::Cache='+str(root/'cache'),'-o','Dir::Log='+str(root/'logs'),'-o','Acquire::Languages=none']

def scoped_apt(kind,module,row,root):
 p=module.distribution();source=row['source'];stamp=source.get('timestamp','')
 if not re.fullmatch(r'\d{8}T\d{6}Z',stamp):raise ArchiveError('Fecha histórica inválida.')
 architecture=arch(p)
 if source['provider']=='debian':
  if p['id']!='debian':raise ArchiveError('Archivo incompatible con la distribución.')
  url='https://snapshot.debian.org/archive/debian/'+stamp+'/';suite='sid';key='/usr/share/keyrings/debian-archive-keyring.gpg'
 else:
  suite=source.get('suite','')
  if p['id']!='ubuntu' or suite not in (p['codename'],p['codename']+'-updates',p['codename']+'-security'):raise ArchiveError('Edición histórica incompatible.')
  url='https://snapshot.ubuntu.com/ubuntu/'+stamp+'/';key='/usr/share/keyrings/ubuntu-archive-keyring.gpg'
 sources=root/'sources';sources.mkdir(exist_ok=True,mode=0o700)
 for old in sources.iterdir():
  if old.is_file() or old.is_symlink():old.unlink()
  else:raise ArchiveError('El repositorio temporal contiene una estructura inválida.')
 for path in [Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*')]:
  if path.is_file() and not path.is_symlink() and path.suffix in ('.list','.sources'):shutil.copyfile(path,sources/path.name)
 (sources/'zz-history.list').write_text('deb [arch='+architecture+' signed-by='+key+' check-valid-until=no] '+url+' '+suite+' main\n')
 preferences=root/'preferences';host=urllib.parse.urlsplit(url).hostname
 preferences.write_text('Package: *\nPin: origin '+host+'\nPin-Priority: -1\n\nPackage: '+row['package']+'\nPin: version '+row['version']+'\nPin-Priority: 990\n')
 lists=root/'lists';lists.mkdir(exist_ok=True,mode=0o700);(lists/'partial').mkdir(exist_ok=True,mode=0o700)
 options=apt_options(root)
 def run(args,**kwargs):return module.run([args[0],*options,*args[1:]] if args[0] in ('apt-get','apt-cache') else args,**kwargs)
 run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=300)
 return SimpleNamespace(**{**vars(module),'run':run})

def oracle_files(module,row,root):
 from storypulse_versions import valid_version
 p=module.distribution();version=valid_version(row['version']);branch=row['source'].get('branch');series='.'.join(version.split('-',1)[0].split('.')[:2])
 if not getattr(module,'LAYOUT',{}).get('oracle') or branch not in ('mysql-8.4-lts','mysql-9.7-lts','mysql-innovation') or not re.fullmatch(r'(?:8\.4|9\.\d+)\.\d+-\d+debian'+re.escape(p['version']),version):raise ArchiveError('Paquete Oracle incompatible con este sistema.')
 expected='mysql-8.4-lts' if series=='8.4' else 'mysql-9.7-lts' if series=='9.7' else 'mysql-innovation'
 if branch!=expected:raise ArchiveError('La rama no coincide con la versión seleccionada.')
 base='https://cdn.mysql.com/archives/mysql-'+series+'/mysql-server_'+version+'_amd64.deb-bundle.tar'
 bundle=root/'mysql-bundle.tar';signature=root/'mysql-bundle.tar.asc';marker=root/'verified.json'
 if shutil.disk_usage(root).free<3*1024**3:raise ArchiveError('El archivo MySQL requiere al menos 3 GB libres para verificar y preparar sus paquetes.')
 try:download(base+'.asc',signature,32768)
 except urllib.error.HTTPError as error:
  if error.code!=404:raise
  base='https://cdn.mysql.com/Downloads/MySQL-'+series+'/mysql-server_'+version+'_amd64.deb-bundle.tar'
  download(base+'.asc',signature,32768)
 download(base,bundle,1536*1024**2)
 home=root/'gnupg';home.mkdir(exist_ok=True,mode=0o700)
 verification=module.run(['gpg','--batch','--no-options','--homedir',str(home),'--no-default-keyring','--keyring','/usr/share/keyrings/storypulse-mysql.gpg','--no-auto-key-retrieve','--status-fd','1','--verify',str(signature),str(bundle)],timeout=90)
 trusted=getattr(module,'KEY_FINGERPRINT','BCA43417C3B485DD128EC6D4B7B3B788A8D3785C')
 signatures=[line.split() for line in verification.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
 if not any(trusted in (line[2],line[-1]) for line in signatures):raise ArchiveError('La firma MySQL no coincide con la clave oficial esperada.')
 allowed={'mysql-common','mysql-client','mysql-server','mysql-community-server','mysql-community-server-core','mysql-community-client','mysql-community-client-core','mysql-community-client-plugins'};files={};total=0
 with tarfile.open(bundle,'r:') as archive:
  for member in archive:
   match=re.fullmatch(r'([a-z0-9-]+)_'+re.escape(version)+r'_(amd64|all)\.deb',member.name)
   if not match or match[1] not in allowed:continue
   if not member.isfile() or member.issym() or member.islnk() or member.size>1024**3 or match[1] in files:raise ArchiveError('El paquete histórico tiene una estructura inválida.')
   total+=member.size
   if total>2*1024**3:raise ArchiveError('El conjunto histórico es demasiado grande.')
   target=root/member.name
   with archive.extractfile(member) as source,open(target,'wb') as dest:shutil.copyfileobj(source,dest,1024*1024)
   os.chmod(target,0o600)
   meta=module.run(['dpkg-deb','-f',str(target),'Package','Version','Architecture']).stdout
   values=dict(re.findall(r'^(Package|Version|Architecture): (.+)$',meta,re.M))
   if values!={'Package':match[1],'Version':version,'Architecture':match[2]}:raise ArchiveError('El paquete no coincide con la selección.')
   files[match[1]]=str(target)
 if not {'mysql-common','mysql-community-server','mysql-community-server-core','mysql-community-client','mysql-community-client-core'}.issubset(files):raise ArchiveError('El conjunto MySQL histórico está incompleto.')
 bundle.unlink();signature.unlink()
 # Do not downgrade shared client packages left after an earlier removal.
 from storypulse_versions import package_version,compare
 targets=[]
 for package in sorted(files):
  if package=='mysql-server':continue
  if package not in ('mysql-community-server','mysql-community-server-core'):
   current=package_version(module.run,p,package)
   if current and compare(module.run,p,current,version)>=0:continue
  targets.append(files[package])
 return targets

def arch_files(kind,module,row,root):
 p=module.distribution();package=row['package'];version=row['version'];architecture=p['architecture'];names=[package]+(['mariadb-clients','mariadb-libs'] if kind=='mysql' else []);files=[]
 for name in names:
  base='https://archive.archlinux.org/packages/'+name[0]+'/'+name+'/'
  matches=[f for f in links(base) if re.fullmatch(re.escape(name)+'-'+re.escape(version)+'-'+re.escape(architecture)+r'\.pkg\.tar\.(xz|zst)',f)]
  if not matches:
   if name==package:raise ArchiveError('El archivo Arch ya no conserva esa versión.')
   continue
  filename=matches[0];target=root/filename;signature=root/(filename+'.sig')
  download(base+filename+'.sig',signature,32768);download(base+filename,target,1024**3)
  module.run(['pacman-key','--verify',str(signature),str(target)],timeout=90)
  meta=module.run(['pacman','-Qp','--print-format','%n|%v|%a',str(target)]).stdout.strip()
  if meta!=name+'|'+version+'|'+architecture:raise ArchiveError('El paquete Arch no coincide con la selección.')
  files.append(str(target))
 return files

def centos_files(kind,module,row,root):
 from storypulse_versions import package_version,compare,valid_version
 p=module.distribution();major=p['version'].split('.')[0];source=row['source'];package=row['package'];source_package=source.get('source_package')
 expected='vsftpd' if kind=='ftp' else 'mysql8.4' if major=='10' else 'mysql'
 if p['id']!='centos' or source_package!=expected:raise ArchiveError('Compilación incompatible con la distribución.')
 allowed={package} if kind=='ftp' else {package,expected,expected+'-common',expected+'-errmsg',expected+'-libs'};files=[]
 for artifact in source.get('artifacts',[]):
  name=artifact.get('name');version=valid_version(artifact.get('version'));release=valid_version(artifact.get('release'));architecture=artifact.get('arch');key=artifact.get('key','')
  if name not in allowed or architecture not in (p['architecture'],'noarch') or not re.fullmatch('[a-f0-9]{8,16}',key) or not re.search(r'(?:\.|_)el'+major+r'(?:[+_.]|$)',release):raise ArchiveError('Metadatos RPM incompatibles.')
  epoch=artifact.get('epoch') or 0
  if type(epoch) is not int or not 0<=epoch<=100:raise ArchiveError('Versión RPM inválida.')
  full=str(epoch)+':'+version+'-'+release
  if name==package and full!=row['version']:raise ArchiveError('El RPM no corresponde a la selección.')
  if name!=package:
   current=package_version(module.run,p,name)
   if current and compare(module.run,p,current,full)>=0:continue
  filename=name+'-'+version+'-'+release+'.'+architecture+'.rpm'
  url='https://kojihub.stream.centos.org/kojifiles/packages/'+expected+'/'+version+'/'+release+'/data/signed/'+key+'/'+architecture+'/'+filename
  target=root/filename;download(url,target,1024**3)
  verification=module.run(['rpmkeys','--checksig','--verbose',str(target)]).stdout
  if re.search(r'NOT OK|NOKEY|BAD|NOTTRUSTED',verification,re.I) or not re.search(r'(?:Signature|signatures).*\bOK\b',verification,re.I):raise ArchiveError('Firma RPM inválida o no confiable en el servidor.')
  metadata=module.run(['rpm','-qp','--qf','%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}',str(target)]).stdout.strip()
  if metadata!=name+'|'+full+'|'+architecture:raise ArchiveError('El contenido RPM no coincide con el catálogo.')
  files.append(str(target))
 if not any(Path(f).name.startswith(package+'-') for f in files):raise ArchiveError('Falta el RPM del servidor.')
 return files

def commands(kind,module,row,cache):
 from storypulse_versions import commands as native_commands
 p=module.distribution();source=row.get('source',{});provider=source.get('provider');root=workspace(cache,kind,row['id'])
 if provider in ('debian','ubuntu'):
  proxy=scoped_apt(kind,module,row,root);plain={k:v for k,v in row.items() if k not in ('source','archived')}
  check,execute=native_commands(kind,proxy,plain)
  # Carry the scoped repository options to the transaction, without writing global sources.
  options=apt_options(root)
  return [check[0],*options,*check[1:]],[execute[0],*options,*execute[1:]]
 if provider=='oracle':
  files=oracle_files(module,row,root);opts=['-o','DPkg::Lock::Timeout=120','-o','Dpkg::Options::=--force-confold','--no-remove','--no-install-recommends']
  return ['apt-get','--simulate',*opts,'install',*files],['apt-get','-y',*opts,'install',*files]
 if provider=='arch':
  if p['id']!='arch':raise ArchiveError('Archivo incompatible con la distribución.')
  files=arch_files(kind,module,row,root)
  return ['pacman','-U','--print','--print-format','%n %v',*files],['pacman','-U','--needed','--noconfirm',*files]
 if provider=='centos-koji':
  files=centos_files(kind,module,row,root);opts=['-y','--setopt=gpgcheck=True','--setopt=localpkg_gpgcheck=True','--setopt=*.gpgcheck=True','--setopt=install_weak_deps=False']
  return ['dnf',*opts,'--setopt=tsflags=test','install',*files],['dnf',*opts,'install',*files]
 if provider=='centos':
  major=p['version'].split('.')[0];compose=source.get('compose','')
  if p['id']!='centos' or not re.fullmatch('CentOS-Stream-'+major+r'-\d{8}\.\d+',compose):raise ArchiveError('Archivo CentOS incompatible.')
  url='https://composes.stream.centos.org/stream-'+major+'/production/'+compose+'/compose/AppStream/'+p['architecture']+'/os/'
  plain={k:v for k,v in row.items() if k not in ('source','archived')};check,execute=native_commands(kind,module,plain)
  options=['--repofrompath=ssm-history,'+url,'--setopt=ssm-history.gpgcheck=True','--setopt=ssm-history.repo_gpgcheck=False']
  return [check[0],*options,*check[1:]],[execute[0],*options,*execute[1:]]
 raise ArchiveError('Origen histórico no admitido.')
