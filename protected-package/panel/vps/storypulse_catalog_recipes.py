"""Fixed native service recipes; no package, path or shell is accepted from HTTP."""
from pathlib import Path
import re

SERVICES={
 'phpmyadmin':('phpMyAdmin','MySQL desde la web · /phpmyadmin','Web','phpmyadmin'),
 'wordpress':('WordPress','CMS · instalador en la raíz web','Web','wordpress'),
 'nginx':('Nginx','Servidor web y proxy inverso','Web','nginx'),
 'apache':('Apache HTTP Server','Servidor web HTTP','Web','apache'),
 'php':('PHP-FPM','Procesamiento de aplicaciones PHP','Web','php'),
 'certbot':('Certbot / Let’s Encrypt','Cliente de certificados y renovación','Web','certbot'),
 'docker':('Docker Engine','Motor de contenedores','Aplicaciones','docker'),
 'postgresql':('PostgreSQL','Servidor de bases de datos','Datos','postgresql'),
 'redis':('Redis','Almacenamiento en memoria','Datos','redis'),
 'fail2ban':('Fail2ban','Protección ante intentos repetidos','Seguridad','fail2ban'),
 'wireguard':('WireGuard','Herramientas para túneles VPN','Red','wireguard'),
 'postfix':('Postfix','Servidor de correo SMTP','Correo','postfix'),
}

def recipe(kind,p,run,installed_package=None,*,resolve_default=True):
 if kind not in SERVICES:raise RuntimeError('Servicio no permitido.')
 f=p['family'];apt=f=='apt';rpm=f=='rpm';arch=f=='arch'
 package={'phpmyadmin':'phpMyAdmin' if rpm else 'phpmyadmin','nginx':'nginx','apache':'apache2' if apt else 'httpd' if rpm else 'apache',
 'php':'php-fpm','certbot':'certbot','docker':'docker.io' if apt else 'docker-ce' if rpm else 'docker',
 'postgresql':'postgresql-server' if rpm else 'postgresql','redis':'redis-server' if apt else 'redis',
 'fail2ban':'fail2ban-server' if rpm else 'fail2ban','wireguard':'wireguard-tools','postfix':'postfix'}[kind]
 if apt and kind in ('php','postgresql') and resolve_default:
  text=run(['apt-cache','depends',package],check=False).stdout
  pattern=r'php[0-9]{1,2}\.[0-9]{1,2}-fpm' if kind=='php' else r'postgresql-[0-9]{1,2}'
  names=set(re.findall(r'^\s*(?:Pre)?Depends:\s*('+pattern+r')\s*$',text,re.M))
  if len(names)>1:raise RuntimeError('El repositorio ofrece más de un paquete principal para '+kind+'.')
  if names:package=names.pop()
 if installed_package:
  allowed=r'php[0-9]{1,2}\.[0-9]{1,2}-fpm' if apt and kind=='php' else r'postgresql-[0-9]{1,2}' if apt and kind=='postgresql' else re.escape(package)
  if not isinstance(installed_package,str) or not re.fullmatch(allowed,installed_package):raise RuntimeError('Paquete instalado fuera de la receta permitida.')
  package=installed_package
 unit={'phpmyadmin':'','nginx':'nginx.service','apache':'apache2.service' if apt else 'httpd.service',
 'php':package.replace('-fpm','-fpm.service') if apt else 'php-fpm.service',
 'certbot':'certbot.timer' if apt else 'certbot-renew.timer','docker':'docker.service',
 'postgresql':'postgresql.service','redis':'redis-server.service' if apt else 'redis.service',
 'fail2ban':'fail2ban.service','wireguard':'','postfix':'postfix.service'}[kind]
 # Fixed cohorts allow exact dependencies from the same source build, not arbitrary repositories.
 patterns={
 'phpmyadmin':r'phpMyAdmin' if rpm else r'(?:phpmyadmin|php-phpmyadmin-(?:motranslator|shapefile|sql-parser)|php-twig-i18n-extension)' if apt else r'phpmyadmin',
 'nginx':r'nginx(?:-(?:common|core|full|light|extras|filesystem|modules))?',
 'apache':r'apache2(?:-(?:bin|data|utils))?' if apt else r'httpd(?:-(?:core|filesystem|tools))?' if rpm else r'apache',
 'php':r'php(?:[0-9]{1,2}\.[0-9]{1,2})?-(?:fpm|cli|common|opcache|readline|process|pdo|xml)' if not arch else r'php(?:-fpm)?',
 'certbot':r'(?:certbot|python3?-certbot|python3?-acme)',
 'docker':r'docker(?:-ce(?:-cli|-rootless-extras)?|\.io|-cli)?',
 'postgresql':r'(?:postgresql(?:-[0-9]{1,2})?(?:-server|-contrib|-private-libs)?|postgresql-client(?:-[0-9]{1,2})?)',
 'redis':r'redis(?:-server|-tools)?','fail2ban':r'fail2ban(?:-server|-firewalld|-systemd|-sendmail)?',
 'wireguard':r'wireguard-tools','postfix':r'postfix'}
 native_paths={
 'phpmyadmin':['/usr/share/phpmyadmin','/etc/phpmyadmin','/var/lib/phpmyadmin'] if apt else ['/usr/share/phpMyAdmin','/etc/phpMyAdmin','/var/lib/phpMyAdmin','/etc/httpd/conf.d/phpMyAdmin.conf'] if rpm else ['/usr/share/webapps/phpMyAdmin','/etc/webapps/phpmyadmin'],
 'nginx':['/etc/nginx','/var/log/nginx'],
 'apache':['/etc/apache2','/var/log/apache2','/var/lib/apache2'] if apt else ['/etc/httpd','/var/log/httpd'],
 'php':['/etc/php/'+re.sub(r'^php([0-9]+\.[0-9]+)-fpm$',r'\1',package)+'/fpm'] if apt and re.fullmatch(r'php\d+\.\d+-fpm',package) else ['/etc/php-fpm.conf','/etc/php-fpm.d'] if rpm else ['/etc/php/php-fpm.conf','/etc/php/php-fpm.d'],
 'certbot':['/etc/letsencrypt','/var/lib/letsencrypt','/var/log/letsencrypt'],
 'docker':['/etc/docker','/var/lib/docker'],
 'postgresql':['/etc/postgresql','/var/lib/postgresql','/var/log/postgresql'] if apt else ['/var/lib/pgsql'] if rpm else ['/var/lib/postgres'],
 'redis':['/etc/redis','/etc/redis.conf','/var/lib/redis','/var/log/redis'],
 'fail2ban':['/etc/fail2ban','/var/lib/fail2ban','/var/log/fail2ban.log'],
 'wireguard':['/etc/wireguard'],'postfix':['/etc/postfix','/var/spool/postfix','/var/lib/postfix']}
 base='/etc/server-monitor-services/'+kind
 config={'nginx':'/etc/nginx/server-monitor.conf','apache':('/etc/apache2' if apt else '/etc/httpd')+'/server-monitor.conf','php':('/etc/php/'+re.sub(r'^php([0-9]+\.[0-9]+)-fpm$',r'\1',package)+'/fpm/server-monitor.conf' if apt else '/etc/php-fpm.d/server-monitor.config' if rpm else '/etc/php/server-monitor-fpm.conf'),'redis':'/etc/server-monitor-services/redis/redis.conf','docker':'/etc/docker/server-monitor.json'}.get(kind,'')
 runtime=('php' if apt else 'php-fpm')+'/server-monitor' if kind=='php' else ('apache2' if apt else 'httpd')+'/server-monitor' if kind=='apache' else ''
 site='/var/www/server-monitor-'+kind if kind in ('nginx','apache') else ''
 log=('/var/log/apache2' if apt else '/var/log/httpd')+'/server-monitor.log' if kind=='apache' else ''
 paths=[base,*native_paths[kind]]
 if unit:paths.append('/etc/systemd/system/'+unit+'.d/90-server-monitor.conf')
 if kind in ('nginx','apache'):paths+=[site]
 return dict(id=kind,label=SERVICES[kind][0],description=SERVICES[kind][1],category=SERVICES[kind][2],icon=SERVICES[kind][3],
  package=package,unit=unit,config=config,runtime=runtime,site=site,log=log,cohort=patterns[kind],paths=paths,source={'apache':'apache2' if apt else 'httpd','php':'php'+(package[3:6] if apt and re.fullmatch(r'php\d+\.\d+-fpm',package) else ''),'postgresql':package if apt else 'postgresql','fail2ban':'fail2ban'}.get(kind,package),
  extra_units=['docker.socket'] if kind=='docker' else ['postgresql@.service'] if kind=='postgresql' and apt else ['postfix@.service'] if kind=='postfix' and apt else [],
  note={'nginx':'Acceso HTTP mediante la IP; apertura automática de TCP 80/443 y arranque del servicio. HTTPS requiere certificado.','apache':'Acceso HTTP mediante la IP; apertura automática de TCP 80/443 y arranque del servicio. HTTPS requiere certificado.','phpmyadmin':'Paquete firmado del sistema; PHP y servidor web se preparan automáticamente.','certbot':'Instala el cliente y su temporizador; los certificados requieren configurar un dominio.',
  'wireguard':'Instala las herramientas. No crea túneles ni cambia rutas de red.',
  'fail2ban':'Se instala sin cárceles activas para evitar bloqueos administrativos involuntarios.',
  'docker':'Sólo socket local. La red bridge y las reglas automáticas de Docker quedan desactivadas para conservar el firewall.',
  'postfix':'Configuración local: sin escucha pública y sin retransmisión abierta.'}.get(kind,'Acceso inicial local; no abre puertos del firewall.'))
