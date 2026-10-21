"""Fixed upstream web applications with isolated PHP and owned virtual hosts."""
import hashlib,ipaddress,json,os,pwd,re,secrets,shutil,stat,subprocess,tempfile,time,urllib.parse,urllib.request,zipfile
from pathlib import Path,PurePosixPath
import storypulse_uninstall as removal
import storypulse_service_flow as flow

APPS={'phpmyadmin':('phpMyAdmin','Administración de MySQL · /phpmyadmin'),'wordpress':('WordPress','Sitio web · instalador en la raíz')}
BASE=Path('/var/www/server-monitor-webapps')
STATE=Path('/var/lib/storypulse-security/webapps')
CACHE=Path('/var/cache/storypulse-security/webapps')
CONF=Path('/etc/server-monitor-webapps')
UNIT=Path('/etc/systemd/system/server-monitor-webphp.service')
SOCKET='/run/server-monitor-webphp/php.sock'
HOSTS={'api.wordpress.org','downloads.wordpress.org','wordpress.org'}
class WebError(RuntimeError):pass
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  safe_url(newurl);return super().redirect_request(req,fp,code,msg,headers,newurl)
def safe_url(url):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='https' or p.hostname not in HOSTS or p.username or p.password or p.port not in (None,443) or p.fragment:raise WebError('Origen de aplicación no permitido.')
 return url
def fetch(url,limit=4*1024**2):
 safe_url(url)
 with urllib.request.build_opener(Redirect()).open(urllib.request.Request(url,headers={'User-Agent':'ServerSecurityMonitor/2.0'}),timeout=12) as response:
  safe_url(response.url);data=response.read(limit+1)
 if len(data)>limit:raise WebError('La descarga supera el tamaño permitido.')
 return data
def profile(p):return {k:p[k] for k in ('id','version','family','architecture')}
def own(c,kind):return c.read(STATE/(kind+'.json'))
def validate_version(value):
 if not isinstance(value,str) or not re.fullmatch(r'[5-9][0-9]?\.[0-9]+(?:\.[0-9]+){0,2}',value):raise WebError('Versión de aplicación inválida.')
 return value

def available(kind):
 if kind!='wordpress':raise WebError('phpMyAdmin utiliza los repositorios del sistema.')
 data=json.loads(fetch('https://api.wordpress.org/core/version-check/1.7/'))
 offer=next((x for x in data.get('offers',[]) if x.get('response')=='upgrade' and x.get('locale')=='en_US'),None)
 if not offer:raise WebError('WordPress no publicó una versión estable verificable.')
 v=validate_version(offer.get('version'));minimum=offer.get('php_version','7.4')
 if not re.fullmatch(r'[78]\.[0-9]+(?:\.[0-9]+)?',minimum):raise WebError('Requisito PHP no reconocido.')
 return [dict(version=v,php_min=minimum,url='https://downloads.wordpress.org/release/wordpress-'+v+'.zip')]

def refresh(c,body):
 c.strict(body,{'service'})
 if c.service(body)!='wordpress':raise WebError('Catálogo nativo requerido para phpMyAdmin.')
 with removal.package_lock():
  p=c.distribution()
  if p['family']=='apt':c.run(['apt-get','-o','DPkg::Lock::Timeout=120','update'],timeout=300)
  elif p['family']=='rpm':c.run(['dnf','-q','makecache','--refresh'],timeout=300)
  else:c.run(['pacman','-Sy','--noconfirm'],timeout=300)
  rows=available('wordpress');info=own(c,'wordpress');installed=info.get('version','') if info else ''
  for row in rows:
   row.update(package='wordpress',architecture='any',repository='WordPress.org · HTTPS y checksums oficiales',archived=False,upgrade_compatible=True);row['id']=c.digest(['wordpress',profile(p),row])
  result=dict(ok=True,service='wordpress',label='WordPress',created_at=int(time.time()),profile=profile(p),versions=rows,installed_version=installed,managed=bool(info),notice='Sólo la última estable de WordPress.org. Abrí http://IP/ para elegir el nombre del sitio y su administrador; la base local se prepara automáticamente. Se verifican todos los archivos contra los checksums oficiales.',latest_id=rows[0]['id'] if rows[0]['version']!=installed else '',note=APPS['wordpress'][1])
  c.write(CACHE/'wordpress.json',result);return result

def select(c,kind,p,identity):
 if not isinstance(identity,str) or not re.fullmatch('[a-f0-9]{64}',identity):raise WebError('Identificador de versión inválido.')
 data=c.read(CACHE/(kind+'.json'))
 if not data or data.get('profile')!=profile(p) or not 0<=time.time()-data.get('created_at',0)<=1800:raise WebError('Actualizá el catálogo de aplicaciones.')
 row=next((x for x in data['versions'] if x['id']==identity),None)
 if not row:raise WebError('La versión no pertenece al catálogo vigente.')
 return row

def packages(c,p):
 f=p['family'];r=c.recipe('php',p,c.run);package=r['package'];versioned=package[:-4] if f=='apt' else ''
 if f=='apt':names=[package,versioned+'-cli',versioned+'-mysql',versioned+'-mbstring',versioned+'-xml',versioned+'-curl',versioned+'-zip',versioned+'-gd',versioned+'-intl','nginx']
 elif f=='rpm':names=['php-fpm','php-cli','php-mysqlnd','php-mbstring','php-xml','php-gd','php-intl','php-pecl-zip','nginx']
 else:names=['php','php-fpm','php-gd','php-intl','nginx']
 return names,('/usr/sbin/php-fpm'+versioned[3:] if f=='apt' else '/usr/sbin/php-fpm' if f=='rpm' else '/usr/bin/php-fpm')
def dependency_commands(p,names):
 if p['family']=='apt':return ['apt-get','--simulate','--no-remove','install',*names],['apt-get','-y','--no-remove','-o','DPkg::Lock::Timeout=120','install',*names]
 if p['family']=='rpm':return ['dnf','-y','--setopt=gpgcheck=True','--setopt=tsflags=test','install',*names],['dnf','-y','--setopt=gpgcheck=True','install',*names]
 return ['pacman','-Sp','--print-format','%n %v',*names],['pacman','-Syu','--needed','--noconfirm',*names]
def addresses(c):
 data=json.loads(c.run(['ip','-j','address','show']).stdout);values=[]
 for interface in data:
  for row in interface.get('addr_info',[]):
   try:ip=ipaddress.ip_address(row.get('local',''))
   except ValueError:continue
   if not ip.is_loopback and not ip.is_link_local and not ip.is_multicast and not ip.is_unspecified:values.append(str(ip))
 if not values:raise WebError('No se encontró una dirección del servidor para publicar las aplicaciones.')
 return sorted(set(values))
def nginx_blocks(text):
 # Track braces after removing comments and quoted strings; only simple native server blocks qualify.
 clean=re.sub(r'(?m)#.*$','',text);result=[]
 for match in re.finditer(r'\bserver\s*\{',clean):
  depth=1;end=match.end()
  while end<len(clean) and depth:
   if clean[end]=='{':depth+=1
   elif clean[end]=='}':depth-=1
   end+=1
  if depth:raise WebError('Configuración Nginx no reconocida.')
  result.append(clean[match.end():end-1])
 return result
def welcome_root(raw):
 path=Path(raw);removal.safe_path(path)
 if not path.exists():return True
 allowed={'index.html','index.htm','index.nginx-debian.html','50x.html'}
 for child in path.iterdir():
  if child.name not in allowed or child.is_symlink() or not child.is_file() or child.stat().st_size>65536:return False
  text=child.read_text(encoding='utf-8',errors='replace').lower()
  if not any(x in text for x in ('welcome to nginx','apache2 debian default','apache2 ubuntu default','test page for the','nginx error','error occurred')):return False
 return True

def front(c,p,installed):
 existing=c.read(STATE/'stack.json')
 if existing:
  if existing.get('profile')!=profile(p):raise WebError('La configuración web pertenece a otro sistema.')
  if existing.get('mode') not in ('existing','dedicated','apache') or not isinstance(existing.get('ips'),list) or any(str(ipaddress.ip_address(x))!=x for x in existing['ips']):raise WebError('Manifiesto web inválido.')
  path=Path(existing['vhost']);allowed=['/etc/nginx/conf.d/00-server-monitor-webapps.conf','/etc/server-monitor-webapps/nginx.conf','/etc/apache2/conf-enabled/server-monitor-webapps.conf','/etc/httpd/conf.d/server-monitor-webapps.conf','/etc/httpd/conf/extra/server-monitor-webapps.conf']
  if path not in [Path(x) for x in allowed]:raise WebError('Ruta de servidor web inválida.')
  removal.safe_path(path)
  if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=existing['vhost_sha256']:raise WebError('La configuración web cambió fuera del panel. No se sobrescribirá.')
  return existing
 ips=addresses(c);has_nginx=bool(installed.get('nginx')) and (bool(c.manifest('nginx')) or c.run(['systemctl','is-active','nginx.service'],check=False).stdout.strip()=='active');other=bool(installed.get('apache2') or installed.get('httpd') or installed.get('apache'))
 if other and not has_nginx and (c.manifest('apache') or c.run(['ss','-H','-ltn','sport = :80']).stdout.strip()):return apache_front(c,p,ips)
 vhost='/etc/nginx/conf.d/00-server-monitor-webapps.conf' if has_nginx else '/etc/server-monitor-webapps/nginx.conf'
 if Path(vhost).exists() or Path(vhost).is_symlink():raise WebError('Existe una configuración web ajena al panel.')
 if has_nginx:
  native=c.manifest('nginx');main='/etc/nginx/server-monitor.conf' if native else ''
  output=c.run(['nginx','-T',*(['-c',main] if main else [])]).stdout
  if main:
   content=Path(main).read_text(encoding='utf-8')
   if not content.rstrip().endswith('}') or 'http {' not in content:raise WebError('Configuración Nginx administrada no reconocida.')
   return dict(profile=profile(p),mode='existing',vhost=vhost,ips=ips,nginx_main=main,include_line='include '+vhost+';')
  if not re.search(r'\binclude\s+/etc/nginx/conf\.d/\*\.conf\s*;',output):raise WebError('Nginx no carga conf.d; no se cambia su configuración principal automáticamente.')
  for block in nginx_blocks(output):
   names=re.findall(r'\bserver_name\s+([^;]+);',block)
   if any(set(line.split())&set(ips) for line in names):raise WebError('La IP ya tiene un sitio Nginx específico. Se conserva el sitio existente.')
   if re.search(r'\blisten\s+[^;]*\b80\b[^;]*default_server',block):
    roots=re.findall(r'\broot\s+([^;\s]+)\s*;',block)
    if re.search(r'\b(?:proxy_pass|fastcgi_pass|alias|return)\s',block) or len(roots)!=1 or not welcome_root(roots[0]):raise WebError('La raíz HTTP contiene un sitio existente. No se reemplazará con WordPress/phpMyAdmin.')
 else:
  if c.run(['ss','-H','-ltn','sport = :80']).stdout.strip():raise WebError('El puerto 80 está ocupado por un servicio ajeno.')
 return dict(profile=profile(p),mode='existing' if has_nginx else 'dedicated',vhost=vhost,ips=ips)

def apache_front(c,p,ips):
 apt=p['family']=='apt';rpm=p['family']=='rpm';binary='apache2ctl' if apt else 'httpd';unit='apache2.service' if apt else 'httpd.service'
 owned=c.manifest('apache')
 if owned:
  recipe=c.definition('apache',p);main=recipe['config'];vhost='/etc/apache2/conf-enabled/server-monitor-webapps.conf' if apt else '/etc/httpd/conf.d/server-monitor-webapps.conf' if rpm else '/etc/httpd/conf/extra/server-monitor-webapps.conf'
  if Path(vhost).exists() or Path(vhost).is_symlink():raise WebError('Existe una configuración Apache ajena al panel.')
  actual='/usr/sbin/apache2' if apt else '/usr/sbin/httpd' if rpm else '/usr/bin/httpd'
  c.run([actual,'-t','-f',main])
  return dict(profile=profile(p),mode='apache',ips=ips,vhost=vhost,main=main,include_line='IncludeOptional '+vhost,binary=actual,apache_args=['-f',main],unit=unit)
 result=c.run([binary,'-S']);text=result.stdout+'\n'+result.stderr
 matches=re.findall(r'default server [^\n]*?\((/[^:()]+):[0-9]+\)',text)
 if not matches:matches=re.findall(r'\*:80[^\n]*?\((/[^:()]+):[0-9]+\)',text)
 if not matches:raise WebError('No se pudo comprobar el sitio predeterminado de Apache.')
 path=Path(matches[0]).resolve();removal.safe_path(path);content=path.read_text(encoding='utf-8')
 roots=re.findall(r'(?im)^\s*DocumentRoot\s+"?([^"\s]+)',content)
 if len(roots)!=1 or not welcome_root(roots[0]):raise WebError('Apache ya publica otro sitio en la IP; no se reemplazará.')
 if any(ip in text for ip in ips):raise WebError('Apache ya tiene un sitio específico en esta IP.')
 vhost='/etc/apache2/conf-enabled/server-monitor-webapps.conf' if apt else '/etc/httpd/conf.d/server-monitor-webapps.conf' if rpm else '/etc/httpd/conf/extra/server-monitor-webapps.conf'
 main='/etc/apache2/apache2.conf' if apt else '/etc/httpd/conf/httpd.conf';include='' if apt or rpm else 'IncludeOptional '+vhost
 if Path(vhost).exists() or Path(vhost).is_symlink():raise WebError('Existe una configuración Apache ajena al panel.')
 return dict(profile=profile(p),mode='apache',ips=ips,vhost=vhost,main=main,include_line=include,binary=binary,unit=unit)

def apache_vhost(stack,apps):
 root=str(BASE/'wordpress') if 'wordpress' in apps else str(CONF/'empty');pma=str(app_site(stack['profile'],'phpmyadmin'))
 modules='/usr/lib/apache2/modules/' if '/apache2/' in stack['vhost'] else '/usr/lib64/httpd/modules/' if '/conf.d/' in stack['vhost'] else '/usr/lib/httpd/modules/'
 text=''
 for name in ('proxy','proxy_fcgi','alias','authz_core','dir'):
  text+='<IfModule !'+name+'_module>\nLoadModule '+name+'_module '+modules+'mod_'+name+'.so\n</IfModule>\n'
 text+='<VirtualHost *:80>\nServerName '+stack['ips'][0]+'\n'
 for ip in stack['ips'][1:]:text+='ServerAlias '+ip+'\n'
 text+='DocumentRoot '+root+'\n<Directory '+root+'>\nRequire all granted\nOptions -Indexes -FollowSymLinks\nAllowOverride None\nDirectoryIndex index.php\n'
 if 'wordpress' in apps:text+='FallbackResource /index.php\n'
 text+='</Directory>\n<FilesMatch "\\.php$">\nSetHandler "proxy:unix:'+SOCKET+'|fcgi://localhost/"\n</FilesMatch>\n<FilesMatch "^(?:wp-config|config\\.inc)\\.php$|\\.(?:sql|log|ini|bak|sh)$">\nRequire all denied\n</FilesMatch>\n'
 if 'phpmyadmin' in apps:
  text+='RedirectMatch ^/phpmyadmin$ /phpmyadmin/\nAlias /phpmyadmin/ '+pma+'/\n<Directory '+pma+'>\nRequire all granted\nOptions -Indexes -FollowSymLinks\nAllowOverride None\nDirectoryIndex index.php\nFallbackResource disabled\n</Directory>\n'
  text+='<LocationMatch "^/phpmyadmin/(?:setup|test|tests|libraries|vendor|templates|tmp)(?:/|$)">\nRequire all denied\n</LocationMatch>\n'
 text+='<LocationMatch "(?:/\\.|^/wp-content/uploads/.*\\.php$)">\nRequire all denied\n</LocationMatch>\n</VirtualHost>\n'
 return text


def prepare(c,kind,row):
 if kind!='wordpress':raise WebError('phpMyAdmin sólo se instala mediante paquetes del repositorio.')
 folder=CACHE/kind/row['version'];c.private_dir(folder);archive=folder/'release.zip';stamp=folder/'verified.json';cached=c.read(stamp)
 if cached and archive.is_file() and archive.stat().st_size<=64*1024**2 and cached.get('sha256')==hashlib.sha256(archive.read_bytes()).hexdigest():return archive
 blob=fetch(row['url'],64*1024**2);archive.write_bytes(blob);archive.chmod(0o600)
 checks=json.loads(fetch('https://api.wordpress.org/core/checksums/1.0/?version='+row['version']+'&locale=en_US',4*1024**2)).get('checksums')
 if not isinstance(checks,dict) or len(checks)<100:raise WebError('WordPress no entregó checksums completos.')
 with zipfile.ZipFile(archive) as source:
  entries=source.infolist()
  if len(entries)>30000 or sum(x.file_size for x in entries)>256*1024**2:raise WebError('Paquete de WordPress demasiado grande.')
  files={x.filename[10:]:x for x in entries if not x.is_dir() and x.filename.startswith('wordpress/')}
  if set(files)!=set(checks):raise WebError('El paquete de WordPress no coincide con el inventario oficial.')
  for name,entry in files.items():
   if not isinstance(checks[name],str) or not re.fullmatch('[a-f0-9]{32}',checks[name]) or entry.file_size>32*1024**2 or hashlib.md5(source.read(entry)).hexdigest()!=checks[name]:raise WebError('Checksum de WordPress incorrecto.')
 c.write(stamp,dict(sha256=hashlib.sha256(blob).hexdigest()));return archive

def extract(archive,target,kind,version):
 prefix='wordpress/' if kind=='wordpress' else 'phpMyAdmin-'+version+'-all-languages/'
 with zipfile.ZipFile(archive) as source:
  entries=source.infolist()
  if len(entries)>30000 or sum(x.file_size for x in entries)>256*1024**2:raise WebError('Paquete de aplicación demasiado grande.')
  seen=set()
  for entry in entries:
   if not entry.filename.startswith(prefix):raise WebError('Raíz inesperada en el paquete.')
   relative=entry.filename[len(prefix):];parts=PurePosixPath(relative)
   if not relative:continue
   if '\\' in relative or parts.is_absolute() or any(x in ('..','.') for x in relative.split('/') if x) or '\x00' in relative or relative in seen:raise WebError('Ruta insegura en el paquete.')
   seen.add(relative);mode=entry.external_attr>>16
   if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)):raise WebError('Tipo de archivo no permitido.')
   dest=target.joinpath(*parts.parts)
   if entry.is_dir():dest.mkdir(mode=0o755,parents=True,exist_ok=True);continue
   if entry.file_size>32*1024**2:raise WebError('Archivo de aplicación demasiado grande.')
   dest.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
   with dest.open('xb') as stream:stream.write(source.read(entry))
   dest.chmod(0o644)
 if not (target/'index.php').is_file():raise WebError('Falta el punto de entrada de la aplicación.')


def plan(c,body):
 c.strict(body,{'service','action','selection','erase_data'});kind=c.service(body);action=body.get('action')
 if action not in ('install','uninstall','upgrade'):raise WebError('Acción de aplicación no permitida.')
 p=c.distribution();info=own(c,kind);site=app_site(p,kind);inventory=c.package_inventory(p)
 native=c.recipe('phpmyadmin',p,c.run) if kind=='phpmyadmin' else None;current=inventory.get(native['package'],'') if native else info.get('version','') if info else ''
 retry=action=='install' and bool(info) and info.get('phase')=='error' and info.get('site')==str(site) and info.get('profile')==profile(p)
 if action=='install' and not retry and (info or current or site.exists() or site.is_symlink()):raise WebError('Ya existen archivos de esta aplicación; no se sobrescribirán.')
 if action!='install' and (not info or info.get('profile')!=profile(p)):raise WebError('La aplicación no pertenece al panel.')
 removal.validate_paths([site]);stack=front(c,p,inventory) if action!='uninstall' or c.read(STATE/'stack.json') else None
 result=dict(ok=True,service=kind,label=APPS[kind][0],action=action,distribution=p['name'],installed_version=current,note=APPS[kind][1],paths=[str(site)])
 if action=='uninstall':
  if body.get('erase_data') is not True or 'selection' in body:raise WebError('Confirmá el borrado de archivos y contenido de la aplicación.')
  names=[native['package']] if native and current else []
  if native:
   removal.validate_paths([Path(x) for x in pma_paths(p)]);command=c.validate_removal(native,p,names)
   if p['family']=='apt' and command:names=command[2:]
  result.update(version=current,packages=names,warning='Borra los archivos y subidas de esta aplicación. Conserva otras aplicaciones, sitios, PHP, servidor web y bases MySQL/MariaDB.')
 else:
  if 'erase_data' in body:raise WebError('Parámetros no permitidos.')
  if action=='upgrade':raise WebError('WordPress se actualiza desde su propio panel. Para cambiar phpMyAdmin, guardá su configuración, eliminá y reinstalá la aplicación.')
  row=c.select(kind,p,body.get('selection')) if native else select(c,kind,p,body.get('selection'));names,binary=packages(c,p)
  from storypulse_wordpress_db import database_dependencies
  names=list(dict.fromkeys(names+database_dependencies(c,p)))
  if inventory.get('nginx') or stack['mode']=='apache':names=[name for name in names if name!='nginx']
  if retry and info.get('version')!=row['version']:raise WebError('La reparación conserva la versión que falló; elegí esa misma versión.')
  flow.web_preflight()
  check,_=dependency_commands(p,names);output=c.run(check,timeout=300).stdout
  if p['family']=='apt' and re.search(r'^(?:Remv|Purg)\s',output,re.M):raise WebError('Las dependencias eliminarían paquetes existentes.')
  if native:
   if row['package']!=native['package']:raise WebError('El paquete no corresponde al sistema.')
   for raw in pma_paths(p):
    if not retry and (Path(raw).exists() or Path(raw).is_symlink()):raise WebError('Existe configuración previa de phpMyAdmin ajena al panel.')
   commands=c.history.commands(c.adapter(native,p),row);output=c.run(commands[0],timeout=600).stdout
   validate_package_plan(c,p,output,inventory)
   names=[*names,native['package']]
  else:prepare(c,kind,row)
  result.update(version=row['version'],selection=row['id'],packages=names,warning='Se instalará e iniciará MySQL/MariaDB local si falta, junto con el servidor web y PHP con sus extensiones. Se habilitarán TCP 80 y 443 en UFW. WordPress prepara su base y usuario exclusivo; MySQL no se publica en Internet. HTTPS requiere un certificado. Se conservan sitios existentes.')
 result['revision']=c.digest([body,profile(p),info,stack,result]);return result

def text_file(path,text,mode=0o644):
 removal.safe_path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(text);stream.flush();os.fsync(stream.fileno())
 path.chmod(mode)
def runtime(c,p,binary,stack):
 stack['php_package']=php_package_from_binary(p,binary)
 try:user=pwd.getpwnam('server-monitor-web')
 except KeyError:
  c.run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','server-monitor-web']);user=pwd.getpwnam('server-monitor-web')
 if user.pw_uid==0 or user.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false'):raise WebError('La cuenta de aplicaciones web no es segura.')
 frontuser='www-data' if p['family']=='apt' else ('apache' if stack['mode']=='apache' else 'nginx') if p['family']=='rpm' else 'http'
 # Existing Nginx may use a different unprivileged worker from the package default.
 if stack['mode']=='existing':
  match=re.search(r'(?m)^\s*user\s+([a-z_][a-z0-9_-]{0,31})(?:\s+[a-z_][a-z0-9_-]{0,31})?\s*;',c.run(['nginx','-T',*(['-c',stack['nginx_main']] if stack.get('nginx_main') else [])]).stdout)
  if match:frontuser=match[1]
 frontaccount=pwd.getpwnam(frontuser)
 if frontaccount.pw_uid==0:raise WebError('Nginx no puede ejecutar los trabajadores como root.')
 php='[global]\npid=/run/server-monitor-webphp/php.pid\nerror_log=syslog\nsyslog.ident=server-monitor-webphp\ndaemonize=no\n[webapps]\nuser=server-monitor-web\ngroup='+__import__('grp').getgrgid(user.pw_gid).gr_name+'\nlisten='+SOCKET+'\nlisten.owner='+frontuser+'\nlisten.group='+__import__('grp').getgrgid(frontaccount.pw_gid).gr_name+'\nlisten.mode=0660\npm=ondemand\npm.max_children=4\npm.process_idle_timeout=10s\nclear_env=yes\nsecurity.limit_extensions=.php\nphp_admin_value[memory_limit]=192M\nphp_admin_value[upload_max_filesize]=32M\nphp_admin_value[post_max_size]=32M\nphp_admin_flag[expose_php]=off\nphp_admin_value[cgi.fix_pathinfo]=0\n'
 text_file(CONF/'php-fpm.conf',php)
 archflags=(' '+' '.join(flow.php_flags(p))) if flow.php_flags(p) else ''
 text_file(UNIT,'[Unit]\nDescription=Server Monitor web applications PHP\nAfter=network.target\n[Service]\nType=simple\nExecStart='+binary+' -F -y '+str(CONF/'php-fpm.conf')+archflags+'\nRuntimeDirectory=server-monitor-webphp\nRuntimeDirectoryMode=0755\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\n[Install]\nWantedBy=multi-user.target\n')
 flow.runtime_directory('server-monitor-webphp')
 c.run([binary,'-t','-y',str(CONF/'php-fpm.conf'),*flow.php_flags(p)])
 if p['family']=='rpm':
  for path,label in [(str(CONF)+'(/.*)?','httpd_config_t'),('/run/server-monitor-webphp(/.*)?','httpd_var_run_t')]:
   c.run(['semanage','fcontext','-a','-t',label,path],check=False)
  c.run(['restorecon','-RF',str(CONF)],check=False)
  text_file(UNIT,UNIT.read_text(encoding='utf-8').replace('[Service]','[Service]\nExecStartPre=/usr/sbin/restorecon -RF /run/server-monitor-webphp'))
 flow.verify_php_modules(c.run,p,binary)
 c.run(['systemctl','daemon-reload']);c.run(['systemctl','reset-failed','server-monitor-webphp.service'],check=False);c.run(['systemctl','enable','--now','server-monitor-webphp.service'],timeout=90)
 c.run(['systemctl','restart','server-monitor-webphp.service'],timeout=90)
 flow.wait_service(c.run,'server-monitor-webphp.service',socket=SOCKET)
 return user,frontuser

def vhost(stack,apps,frontuser):
 if stack['mode']=='apache':return apache_vhost(stack,apps)
 root=str(BASE/'wordpress');pma=str(app_site(stack['profile'],'phpmyadmin'));fast='fastcgi_pass unix:'+SOCKET+';\nfastcgi_param QUERY_STRING $query_string;\nfastcgi_param REQUEST_METHOD $request_method;\nfastcgi_param CONTENT_TYPE $content_type;\nfastcgi_param CONTENT_LENGTH $content_length;\nfastcgi_param SCRIPT_NAME $fastcgi_script_name;\nfastcgi_param REQUEST_URI $request_uri;\nfastcgi_param DOCUMENT_URI $document_uri;\nfastcgi_param DOCUMENT_ROOT $document_root;\nfastcgi_param SERVER_PROTOCOL $server_protocol;\nfastcgi_param REQUEST_SCHEME $scheme;\nfastcgi_param HTTPS $https if_not_empty;\nfastcgi_param GATEWAY_INTERFACE CGI/1.1;\nfastcgi_param SERVER_SOFTWARE nginx;\nfastcgi_param REMOTE_ADDR $remote_addr;\nfastcgi_param REMOTE_PORT $remote_port;\nfastcgi_param SERVER_ADDR $server_addr;\nfastcgi_param SERVER_PORT $server_port;\nfastcgi_param SERVER_NAME $server_name;\nfastcgi_param REDIRECT_STATUS 200;\n'
 server='server {\ninclude /etc/nginx/mime.types;\nlisten 80;\nserver_name '+' '.join(stack['ips'])+';\nclient_max_body_size 32m;\nadd_header X-Content-Type-Options nosniff always;\n'
 # Wildcard HTTP includes loopback; do not add a duplicate listen socket.
 if any(':' in ip for ip in stack['ips']):server+='listen [::]:80;\n'
 server+='location ~ /\\. { deny all; }\nlocation ~* (?:wp-config\\.php|config\\.inc\\.php|\\.(?:sql|log|ini|bak|sh))$ { deny all; }\n'
 if 'phpmyadmin' in apps:
  server+='location = /phpmyadmin { return 302 /phpmyadmin/; }\nlocation ~ ^/phpmyadmin/(?:setup|test|tests|libraries|vendor|templates|tmp)(?:/|$) { deny all; }\nlocation ~ ^/phpmyadmin/(.+\\.php)$ { alias '+pma+'/$1; if (!-f $request_filename) { return 404; }\nfastcgi_param SCRIPT_FILENAME $request_filename;\n'+fast+'}\nlocation /phpmyadmin/ { alias '+pma+'/; index index.php; }\n'
 else:server+='location /phpmyadmin { return 404; }\n'
 if 'wordpress' in apps:
  server+='root '+root+';\nindex index.php;\nlocation ~* ^/wp-content/uploads/.*\\.php$ { deny all; }\nlocation / { try_files $uri $uri/ /index.php?$args; }\nlocation ~ \\.php$ { try_files $uri =404;\nfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n'+fast+'}\n'
 else:server+='location / { return 404; }\n'
 server+='}\n'
 if stack['mode']=='dedicated':server='user '+frontuser+';\nworker_processes auto;\npid /run/server-monitor-webnginx/nginx.pid;\nevents { worker_connections 256; }\nhttp {\ninclude /etc/nginx/mime.types;\ndefault_type application/octet-stream;\naccess_log off;\n'+server+'}\n'
 return server

def publish(c,p,stack,apps,frontuser):
 (CONF/'empty').mkdir(parents=True,exist_ok=True,mode=0o755)
 path=Path(stack['vhost']);prior=path.read_bytes() if path.exists() else None;main_path=Path(stack['nginx_main']) if stack.get('nginx_main') else Path(stack['main']) if stack['mode']=='apache' and stack.get('include_line') else None;prior_main=main_path.read_bytes() if main_path else None
 import storypulse_cloudflare as cloudflare
 prior_policy=cloudflare.POLICY.read_bytes() if cloudflare.POLICY.exists() else None;main_update=None
 try:
  if stack['mode']!='apache':cloudflare.adopt_webapp(path)
  base_vhost=vhost(stack,apps,frontuser);rendered_vhost=cloudflare.render(str(path),base_vhost) if stack['mode']!='apache' else base_vhost
  text_file(path,rendered_vhost)
  if p['family']=='rpm':
   c.run(['restorecon','-RF',str(BASE),str(CONF),str(path)],check=False)
   c.run(['semanage','fcontext','-a','-t','httpd_sys_rw_content_t',str(BASE/'wordpress')+'(/.*)?'],check=False)
   c.run(['restorecon','-RF',str(BASE)],check=False)
  if stack['mode']=='existing':
   if stack.get('nginx_main'):
    main=Path(stack['nginx_main']);content=cloudflare.source(main)
    if stack['include_line'] not in content:
     at=content.rfind('}');content=content[:at]+'\n'+stack['include_line']+'\n'+content[at:]
     rendered_main=cloudflare.render(str(main),content);text_file(main,rendered_main)
     main_update=(main,content,rendered_main)
   c.run(['nginx','-t',*(['-c',stack['nginx_main']] if stack.get('nginx_main') else [])]);c.run(['systemctl','enable','--now','nginx.service'],timeout=90);c.run(['systemctl','reload','nginx.service'],timeout=60)
  elif stack['mode']=='apache':
   main=Path(stack['main'])
   if stack.get('include_line') and stack['include_line'] not in main.read_text(encoding='utf-8'):text_file(main,main.read_text(encoding='utf-8')+'\n'+stack['include_line']+'\n')
   c.run([stack['binary'],'-t',*stack.get('apache_args',[])]);c.run(['systemctl','enable','--now',stack['unit']],timeout=90);c.run(['systemctl','reload',stack['unit']],timeout=60)
  else:
   nginx='/usr/bin/nginx' if p['family']=='arch' else '/usr/sbin/nginx'
   flow.runtime_directory('server-monitor-webnginx')
   c.run([nginx,'-t','-c',str(path)])
   text_file(Path('/etc/systemd/system/server-monitor-webnginx.service'),'[Unit]\nDescription=Server Monitor web applications HTTP\nAfter=network.target server-monitor-webphp.service\nWants=server-monitor-webphp.service\n[Service]\nType=simple\nExecStart='+nginx+' -g "daemon off;" -c '+str(path)+'\nExecReload=/bin/kill -HUP $MAINPID\nRuntimeDirectory=server-monitor-webnginx\nRuntimeDirectoryMode=0755\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
   c.run(['systemctl','daemon-reload']);c.run(['systemctl','enable','--now','server-monitor-webnginx.service'],timeout=90);c.run(['systemctl','reload','server-monitor-webnginx.service'])
  if main_update:cloudflare.remember(*main_update)
  cloudflare.remember(path,base_vhost,rendered_vhost)
  stack['vhost_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();c.write(STATE/'stack.json',stack)
 except Exception:
  if prior is None:path.unlink(missing_ok=True)
  else:path.write_bytes(prior)
  if main_path is not None:main_path.write_bytes(prior_main)
  if prior_policy is not None:cloudflare.write(cloudflare.POLICY,prior_policy)
  # A failed reload may already have started workers; reload the restored files.
  if stack['mode']!='apache':
   c.run(['nginx','-t',*(['-c',str(path)] if stack['mode']=='dedicated' else ['-c',stack['nginx_main']] if stack.get('nginx_main') else [])],check=False)
   c.run(['systemctl','reload','server-monitor-webnginx.service' if stack['mode']=='dedicated' else 'nginx.service'],check=False)
  raise

def verify_assets(c,body,page,health_host):
 # A successful PHP page can still be blank if nosniff blocks mistyped JS/CSS.
 # Check one of each kind from the actual page, using the same local TLS route.
 from html.parser import HTMLParser
 import storypulse_cloudflare as cloudflare
 class Assets(HTMLParser):
  def __init__(self):super().__init__();self.items={}
  def handle_starttag(self,tag,attrs):
   attrs=dict(attrs)
   kind='script' if tag=='script' and attrs.get('src') else 'style' if tag=='link' and 'stylesheet' in attrs.get('rel','').lower().split() else ''
   if kind and kind not in self.items:
    raw=attrs.get('src') if kind=='script' else attrs.get('href','')
    url=urllib.parse.urlsplit(urllib.parse.urljoin('http://'+health_host+page,raw))
    if url.scheme in ('http','https') and url.netloc==health_host and not url.username and not url.password:
     self.items[kind]=urllib.parse.urlunsplit(('', '',url.path,url.query,''))
 parser=Assets();parser.feed(body)
 for kind,path in parser.items.items():
  response=c.run(['curl','--noproxy','*','--silent','--show-error','--connect-timeout','2','--max-time','5','--max-filesize','4194304','-H','Host: '+health_host,'-o','/dev/null','-w','%{http_code}\n%{content_type}',*cloudflare.health_args(path)],timeout=8,check=False)
  code,_,content_type=response.stdout.strip().partition('\n');mime=content_type.split(';',1)[0].strip().lower()
  allowed={'text/javascript','application/javascript','application/x-javascript','text/ecmascript','application/ecmascript'} if kind=='script' else {'text/css'}
  if response.returncode or code!='200' or mime not in allowed:
   raise WebError('La aplicación respondió, pero no pudo cargar '+('JavaScript' if kind=='script' else 'sus estilos CSS')+' (HTTP '+code+', tipo '+(mime or 'desconocido')+'). Revisá la configuración MIME del servidor web.')

def verify(c,kind,stack):
 # No redirects outside the local server, no credentials, bounded response.
 path='/phpmyadmin/' if kind=='phpmyadmin' else '/wp-admin/install.php' if (BASE/'wordpress/wp-config.php').is_file() else '/wp-admin/setup-config.php'
 import storypulse_cloudflare as cloudflare
 health_host=cloudflare.read_policy().get('domain') if cloudflare.read_policy().get('ssl') else ('['+stack['ips'][0]+']' if ':' in stack['ips'][0] else stack['ips'][0])
 last='';asset_error=None
 for attempt in range(15):
  response=c.run(['curl','--noproxy','*','--silent','--show-error','--connect-timeout','2','--max-time','5','--max-filesize','2097152','-H','Host: '+health_host,'-w','\n%{http_code}',*cloudflare.health_args(path)],timeout=8,check=False).stdout
  body,_,code=response.rpartition('\n');last=code
  if code=='200' and re.search(r'phpMyAdmin' if kind=='phpmyadmin' else r'WordPress|setup-config',body,re.I):
   try:verify_assets(c,body,path,health_host);return
   except WebError as error:asset_error=error
  if attempt<14:time.sleep(.25)
 if asset_error is not None:raise asset_error
 raise WebError('La aplicación no respondió correctamente después de esperar al servidor web (HTTP '+last+'). Revisá el estado de PHP y del servidor web.')



def apply(c,body):
 c.strict(body,{'service','action','selection','erase_data','revision','confirm'})
 if body.get('confirm') is not True or not re.fullmatch('[a-f0-9]{64}',body.get('revision','')):raise WebError('Revisá y confirmá la operación.')
 request={k:v for k,v in body.items() if k not in ('revision','confirm')}
 with removal.package_lock():
  reviewed=plan(c,request)
  if reviewed['revision']!=body['revision']:raise WebError('La instalación cambió. Revisá la operación nuevamente.')
  kind=body['service'];p=c.distribution();site=app_site(p,kind);info=own(c,kind);stack=front(c,p,c.package_inventory(p)) if body['action']!='uninstall' or c.read(STATE/'stack.json') else None;apps={x for x in APPS if own(c,x)};native=c.recipe('phpmyadmin',p,c.run) if kind=='phpmyadmin' else None
  if body['action']=='uninstall':
   command=None
   if native:
    command=c.validate_removal(native,p,reviewed['packages'])
    if p['family']=='apt' and command and command[2:]!=reviewed['packages']:raise WebError('Cambió el alcance de la eliminación. Revisá nuevamente antes de continuar.')
   apps.discard(kind);frontuser=(stack or {}).get('frontuser','www-data' if p['family']=='apt' else 'nginx' if p['family']=='rpm' else 'http')
   if stack:publish(c,p,stack,apps,frontuser)
   if native:
    if p['family']=='apt':pma_preseed(c,remove=True)
    if command:c.run(command,timeout=600)
    if c.version(p,native['package']):raise WebError('El gestor no confirmó la eliminación de phpMyAdmin.')
    for raw in pma_paths(p):
     path=Path(raw);removal.validate_paths([path])
     if path.is_dir():shutil.rmtree(path)
     elif path.is_file():path.unlink()
    for path in (c.CACHE/'packages/phpmyadmin',c.CACHE/'phpmyadmin',c.CACHE/'prepared-phpmyadmin'):
     if path.exists():removal.validate_paths([path]);shutil.rmtree(path)
    (c.CACHE/'phpmyadmin.json').unlink(missing_ok=True)
   else:
    removal.validate_paths([site])
    if site.exists():shutil.rmtree(site)
    if (CACHE/kind).exists():removal.validate_paths([CACHE/kind]);shutil.rmtree(CACHE/kind)
    (CACHE/(kind+'.json')).unlink(missing_ok=True)
   (STATE/(kind+'.json')).unlink()
   if not apps:withdraw(c,stack)
   return dict(ok=True,service=kind,action='uninstall',message=APPS[kind][0]+' eliminado. Servidor web, PHP y bases de datos compartidas conservados.')
  row=c.select(kind,p,body['selection']) if native else select(c,kind,p,body['selection'])
  c.write(STATE/(kind+'.json'),dict(profile=profile(p),version=row['version'],phase='installing',site=str(site)))
  try:
   flow.open_web_ports()
   if native and p['family']=='apt':pma_preseed(c)
   from storypulse_wordpress_db import ensure_database
   ensure_database(c,p)
   names,binary=packages(c,p)
   if c.package_inventory(p).get('nginx') or stack['mode']=='apache':names=[x for x in names if x!='nginx']
   _,command=dependency_commands(p,names);masked=False
   try:
    if stack['mode']=='dedicated':c.run(['systemctl','mask','--runtime','nginx.service']);masked=True
    c.run(command,timeout=1200)
   finally:
    if masked:c.run(['systemctl','unmask','--runtime','nginx.service'],check=False)
   actual=c.run([binary,'-v']).stdout;match=re.search(r'PHP\s+(\d+\.\d+(?:\.\d+)?)',actual);minimum='7.2' if native else row['php_min']
   if not match or tuple(map(int,match[1].split('.'))) < tuple(map(int,minimum.split('.'))):raise WebError('La versión PHP del sistema no cumple el mínimo '+minimum+'.')
   removal.safe_path(BASE);BASE.mkdir(parents=True,exist_ok=True,mode=0o755);user,frontuser=runtime(c,p,binary,stack);stack['frontuser']=frontuser
   if native:
    if p['family']=='apt':pma_preseed(c)
    commands=c.history.commands(c.adapter(native,p),row);c.run(commands[1],timeout=1200)
    installed=c.version(p,native['package'])
    if installed!=row['version']:raise WebError('La versión de phpMyAdmin instalada no coincide con la seleccionada.')
    configure_pma(p,user)
   elif not site.exists():
    archive=prepare(c,kind,row);stage=Path(tempfile.mkdtemp(prefix='.wordpress-',dir=str(BASE)))
    try:
     extract(archive,stage,kind,row['version'])
     for parent,dirs,files in os.walk(stage):
      os.chown(parent,user.pw_uid,user.pw_gid)
      for name in files:os.chown(Path(parent)/name,user.pw_uid,user.pw_gid)
     stage.chmod(0o755);os.rename(stage,site)
    finally:
     if stage.exists():shutil.rmtree(stage)
   if kind=='wordpress':
    from storypulse_wordpress_db import prepare_database
    prepare_database(c,p,site,user)
   apps.add(kind);publish(c,p,stack,apps,frontuser);verify(c,kind,stack)
   c.write(STATE/(kind+'.json'),dict(profile=profile(p),version=row['version'],phase='installed',site=str(site)))
  except Exception:
   c.write(STATE/(kind+'.json'),dict(profile=profile(p),version=row['version'],phase='error',site=str(site)));raise
  return dict(ok=True,service=kind,action='install',installed_version=row['version'],message=APPS[kind][0]+' '+row['version']+' instalado. Abrí http://IP'+('/phpmyadmin/' if native else '/ para completar el asistente de WordPress.'))


def status(c,p,inventory=None,runtime_info=None):
 rows=[];inventory=c.package_inventory(p) if inventory is None else inventory
 runtime_info=dependency_info(c,p,inventory) if runtime_info is None else runtime_info
 ready=runtime_info['php_active'] and runtime_info['front_active'] and runtime_info.get('database_active',False)
 for kind,(label,description) in APPS.items():
  info=own(c,kind);site=app_site(p,kind);version=inventory.get(c.recipe(kind,p,c.run)['package'],'') if kind=='phpmyadmin' else info.get('version','') if info else '';installed=bool(version and site.is_dir())
  if installed and kind=='wordpress':
   path=site/'wp-includes/version.php'
   if path.is_file() and not path.is_symlink() and path.stat().st_size<65536:
    match=re.search(r"\$wp_version\s*=\s*'([0-9.]+)'",path.read_text(encoding='utf-8'))
    if match:version=match[1]
  rows.append(dict(id=kind,label=label,description=description,category='Web',icon=kind,note=description,installed=installed,installed_version=version,managed=bool(info),phase=info.get('phase','') if info else '',active=installed and bool(info) and info.get('phase')=='installed' and ready,state=('Activo' if bool(info) and info.get('phase')=='installed' and ready else 'Base de datos detenida o sin instalar' if runtime_info['php_active'] and runtime_info['front_active'] and not runtime_info.get('database_active',False) else 'Instalado, detenido') if installed else 'Sin instalar',upgrade_supported=False))
 return rows




def pma_paths(p):
 if p['family']=='apt':return ['/usr/share/phpmyadmin','/etc/phpmyadmin','/var/lib/phpmyadmin']
 if p['family']=='rpm':return ['/usr/share/phpMyAdmin','/etc/phpMyAdmin','/var/lib/phpMyAdmin','/etc/httpd/conf.d/phpMyAdmin.conf']
 return ['/usr/share/webapps/phpMyAdmin','/etc/webapps/phpmyadmin']
def app_site(p,kind):return Path(pma_paths(p)[0]) if kind=='phpmyadmin' else BASE/'wordpress'
def pma_preseed(c,remove=False):
 # A purge removes dbconfig's questions but may leave their templates. Debian's
 # set-selections only recreates a question when its template is also absent.
 # Reload only missing questions through Debian's own template loader. REGISTER
 # cannot repair an orphan because debconf implements it through Question->get.
 missing=[]
 for name,kind in (('dbconfig-install','boolean'),('dbconfig-remove','boolean'),('reconfigure-webserver','multiselect')):
  question='phpmyadmin/'+name
  result=c.run(['debconf-communicate','phpmyadmin'],input='GET '+question+'\n',check=False)
  code=result.stdout.partition(' ')[0].strip()
  if code not in ('0','10'):raise WebError('No se pudo preparar la configuración de phpMyAdmin: '+result.stdout[-400:])
  if code=='10':missing.append('Template: '+question+'\nType: '+kind+'\nDescription: Managed phpMyAdmin configuration\n')
 if missing:
  c.run(['perl','-MDebconf::Db','-MDebconf::Template','-e','Debconf::Db->load; Debconf::Template->load(\\*STDIN, "phpmyadmin"); Debconf::Db->save;'],input='\n'.join(missing)+'\n')
 c.run(['debconf-set-selections'],input='phpmyadmin phpmyadmin/dbconfig-install boolean false\nphpmyadmin phpmyadmin/dbconfig-remove boolean false\nphpmyadmin phpmyadmin/reconfigure-webserver multiselect \n')
def configure_pma(p,user):
 folder=Path(pma_paths(p)[1]);removal.safe_path(folder);folder.mkdir(mode=0o750,parents=True,exist_ok=True);os.chown(folder,0,user.pw_gid);folder.chmod(0o750)
 config=folder/'config.inc.php';text_file(config,"<?php\n$cfg['blowfish_secret']='"+secrets.token_hex(16)+"';\n$i=1;\n$cfg['Servers'][$i]['auth_type']='cookie';\n$cfg['Servers'][$i]['host']='localhost';\n$cfg['Servers'][$i]['AllowNoPassword']=false;\n$cfg['AllowArbitraryServer']=false;\n$cfg['TempDir']='/tmp';\n",0o640);os.chown(config,0,user.pw_gid)
 # Only root-managed package links are followed, with an exact fixed destination.
 entry=app_site(p,'phpmyadmin')/'config.inc.php'
 if entry.is_symlink():
  if entry.resolve()!=config:raise WebError('El enlace de configuración del paquete no coincide con la ruta esperada.')
 elif entry!=config:text_file(entry,"<?php require '"+str(config)+"';\n")
def withdraw(c,stack):
 import storypulse_cloudflare as cloudflare
 if cloudflare.enabled():return # Keep the protected front end and its per-VPS policy.
 c.run(['systemctl','disable','--now','server-monitor-webphp.service'],timeout=60,check=False)
 if stack and stack['mode']=='dedicated':
  c.run(['systemctl','disable','--now','server-monitor-webnginx.service'],timeout=60);Path('/etc/systemd/system/server-monitor-webnginx.service').unlink(missing_ok=True)
 if stack:Path(stack['vhost']).unlink(missing_ok=True)
 if stack and stack['mode']=='existing':
  if stack.get('nginx_main'):
   main=Path(stack['nginx_main']);text_file(main,main.read_text(encoding='utf-8').replace(stack['include_line']+'\n',''))
  c.run(['nginx','-t',*(['-c',stack['nginx_main']] if stack.get('nginx_main') else [])]);c.run(['systemctl','reload','nginx.service'])
 elif stack and stack['mode']=='apache':
  if stack.get('include_line'):
   main=Path(stack['main']);text_file(main,main.read_text(encoding='utf-8').replace(stack['include_line']+'\n',''))
  c.run([stack['binary'],'-t',*stack.get('apache_args',[])]);c.run(['systemctl','reload',stack['unit']])
 UNIT.unlink(missing_ok=True);c.run(['systemctl','daemon-reload'])
 if CONF.exists():removal.validate_paths([CONF]);shutil.rmtree(CONF)
 (STATE/'stack.json').unlink(missing_ok=True)


def validate_package_plan(c,p,output,inventory):
 if p['family']!='apt':return
 if re.search(r'^(?:Remv|Purg)\s',output,re.M):raise WebError('La instalación eliminaría paquetes existentes.')
 for name,previous,selected in re.findall(r'^Inst ([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9]+)?(?: \[([^\]]+)\])? \(([^ ]+)',output,re.M):
  existing=inventory.get(name) or previous
  if existing and c.versions.compare(c.run,p,selected,existing)<0:raise WebError('La versión necesita degradar una dependencia compartida ('+name+'). Elegí una revisión compatible con los paquetes instalados.')


def php_package_from_binary(p,binary):
 if p['family']=='apt':
  match=re.fullmatch(r'/usr/sbin/php-fpm([0-9]{1,2}\.[0-9]{1,2})',binary)
  return 'php'+match[1]+'-fpm' if match else ''
 return 'php-fpm' if binary==('/usr/sbin/php-fpm' if p['family']=='rpm' else '/usr/bin/php-fpm') else ''

def dependency_info(c,p,inventory,unit_active=None):
 if unit_active is None:unit_active=lambda unit:c.run(['systemctl','is-active',unit],check=False).stdout.strip()=='active'
 stack=c.read(STATE/'stack.json',{}) or {};apps=[]
 for kind in APPS:
  info=own(c,kind)
  if info and info.get('profile')==profile(p) and info.get('phase')=='installed' and app_site(p,kind).is_dir():apps.append(APPS[kind][0])
 package=stack.get('php_package','')
 allowed=r'php[0-9]{1,2}\.[0-9]{1,2}-fpm' if p['family']=='apt' else r'php-fpm'
 if not isinstance(package,str) or not re.fullmatch(allowed,package) or package not in inventory:package=''
 # Older installations predate package metadata. Read only the fixed, root-owned unit.
 if not package:
  try:fd=os.open(UNIT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError:fd=None
  if fd is not None:
   with os.fdopen(fd,'r',encoding='utf-8') as handle:
    info=os.fstat(handle.fileno())
    if stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_size<16384:
     match=re.search(r'(?m)^ExecStart=(/usr/(?:sbin|bin)/php-fpm[0-9.]*)\s',handle.read())
     if match:
      candidate=php_package_from_binary(p,match[1])
      if candidate in inventory:package=candidate
 php_active=bool(package and unit_active('server-monitor-webphp.service'))
 mode=stack.get('mode');front_kind='apache' if mode=='apache' else 'nginx' if mode in ('existing','dedicated') else ''
 front_unit=('apache2.service' if p['family']=='apt' else 'httpd.service') if mode=='apache' else 'server-monitor-webnginx.service' if mode=='dedicated' else 'nginx.service' if mode=='existing' else ''
 front_active=bool(front_unit and unit_active(front_unit))
 patterns={'apt':r'php[0-9]{1,2}\.[0-9]{1,2}-(?:fpm|cli|common|mysql|mbstring|xml|curl|zip|gd|intl|opcache|readline)',
 'rpm':r'php(?:-(?:fpm|cli|common|mysqlnd|mbstring|xml|gd|intl|pdo|opcache|process|soap|zip|pecl-zip))?',
 'arch':r'php(?:-(?:fpm|gd|intl|pgsql|sqlite|tidy|xsl|snmp|odbc|pspell|sodium))?'}
 components=[dict(package=name,version=value) for name,value in sorted(inventory.items()) if re.fullmatch(patterns[p['family']],name)][:64]
 database_active=any(unit_active(unit) for unit in ('mariadb.service','mysql.service','mysqld.service')) if apps else False
 return dict(php_package=package,php_active=php_active,front_active=front_active,front_kind=front_kind,front_unit=front_unit,apps=apps,components=components,database_active=database_active)
