"""Server Security Monitor v3.0 - ownership-scoped game removal."""
import contextlib,grp,hashlib,json,os,pwd,re,shutil,stat
from pathlib import Path
import storypulse_games as game
import storypulse_zone as zone
import storypulse_mysql as mysql
import storypulse_services as ftp
import storypulse_catalog as catalog
import storypulse_webapps as web
import storypulse_platform as linux
import storypulse_uninstall as removal
ZoneError=game.GameError

def _zone_schema_pattern(pattern, name):
    # mysql.db stores SQL wildcard patterns; a grant to zone% is shared too.
    expression = ''
    escaped = False
    for char in pattern:
        if escaped:
            expression += re.escape(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '%':
            expression += '.*'
        elif char == '_':
            expression += '.'
        else:
            expression += re.escape(char)
    if escaped:
        expression += re.escape('\\')
    return re.fullmatch(expression, name) is not None


def _zone_cleanup_grants(conn, name, user, hosts):
    """Reject other consumers and privileges outside this private database."""
    allowed_hosts = set(hosts)
    for row in mysql.query(conn, 'SELECT User,Host,Db FROM mysql.db'):
        if _zone_schema_pattern(row['Db'], name) and (row['User'] != user or row['Host'] not in allowed_hosts):
            raise ZoneError('Otra cuenta tiene permisos sobre la base Zone. Se conservó la instalación para revisión.')
    for table in ('tables_priv', 'columns_priv', 'procs_priv'):
        for row in mysql.query(conn, 'SELECT DISTINCT User,Host,Db FROM mysql.' + table + ' WHERE Db=%s', (name,)):
            if row['User'] != user or row['Host'] not in allowed_hosts:
                raise ZoneError('Otra cuenta utiliza objetos de la base Zone. Se conservó la instalación para revisión.')
    accepted = set(mysql.PRIVILEGES)
    for host in hosts:
        # Identifier escaping here is for the output grammar, not execution.
        target = '`' + user + '`@`' + host.replace('`', '``') + '`'
        for row in mysql.query(conn, 'SHOW GRANTS FOR %s@%s', (user, host)):
            grant = next(iter(row.values()))
            if not isinstance(grant, str):
                raise ZoneError('No se pudieron verificar los permisos de la cuenta Zone.')
            match = re.fullmatch(r'GRANT ([A-Z_, ]+) ON (.+) TO ' + re.escape(target) + r'(?: (.*))?', grant)
            if not match:
                raise ZoneError('La cuenta Zone tiene roles o permisos ajenos. Se conservó para revisión.')
            privileges = {value.strip() for value in match[1].split(',')}
            scope = match[2]
            suffix = match[3] or ''
            database_scopes = {'`' + name + '`.*', '`' + name.replace('_', r'\_') + '`.*'}
            if (scope == '*.*' and privileges != {'USAGE'}) or (scope != '*.*' and (scope not in database_scopes or not privileges <= accepted)) or 'GRANT OPTION' in suffix:
                raise ZoneError('La cuenta Zone tiene permisos fuera de su instalación. Se conservó para revisión.')


def zone_database_removal_snapshot(record):
    if not isinstance(record, dict) or record.get('db_created') is not True:
        raise ZoneError('No se pudo verificar la propiedad de la base Zone. Se conservó para revisión.')
    public = record.get('public') or {}
    name = mysql.dbname(public.get('database'))
    user = mysql.username(public.get('db_user'))
    progress = record.get('database_cleanup')
    if progress is not None and (not isinstance(progress, dict) or progress.get('database') != name or progress.get('username') != user or progress.get('phase') not in ('prepared', 'user_removed', 'removed')):
        raise ZoneError('El registro de limpieza de la base Zone no es válido.')
    mysql.configure_platform()
    config = mysql.load()
    matches = [entry for entry in config['users'] if entry['username'] == user or entry['database'] == name]
    if any(entry['username'] != user or entry['database'] != name for entry in matches) or len(matches) > 1:
        raise ZoneError('La base o la cuenta Zone se comparte con otra instalación. Se conservó para revisión.')
    if name not in config['databases'] and not progress:
        raise ZoneError('La base Zone dejó de estar administrada por el panel. Se conservó para revisión.')
    with mysql.connect() as conn:
        schemas = mysql.query(conn, 'SELECT SCHEMA_NAME,DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (name,))
        references = mysql.query(conn, 'SELECT TABLE_SCHEMA,TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_SCHEMA=%s AND TABLE_SCHEMA<>%s LIMIT 1', (name, name))
        if references:
            raise ZoneError('Otra base tiene relaciones con Zone. Se conservó la instalación para revisión.')
        accounts = mysql.user_accounts(conn, user)
        if accounts and (not matches or any(account['Host'] not in ['localhost', *matches[0]['ips']] or not mysql.account_owned(account, name) for account in accounts)):
            raise ZoneError('La cuenta Zone contiene accesos ajenos al panel. Se conservó para revisión.')
        if not progress and (not schemas or not accounts or not matches):
            raise ZoneError('Faltan recursos registrados de Zone; se requiere revisar su propiedad antes de eliminarlos.')
        if progress and progress['phase'] in ('user_removed', 'removed') and (accounts or matches):
            raise ZoneError('La cuenta Zone reapareció después de eliminarse. Se conservó para revisión.')
        if progress and progress['phase'] == 'removed' and (schemas or name in config['databases']):
            raise ZoneError('La base Zone reapareció después de eliminarse. Se conservó para revisión.')
        hosts = sorted(account['Host'] for account in accounts)
        _zone_cleanup_grants(conn, name, user, hosts)
        tables = mysql.query(conn, 'SELECT TABLE_NAME,TABLE_TYPE,CREATE_TIME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s ORDER BY TABLE_NAME', (name,)) if schemas else []
    schema_digest = hashlib.sha256(json.dumps([schemas, tables], sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest() if schemas else None
    if progress and schemas and progress.get('schema_digest') != schema_digest:
        raise ZoneError('La estructura de la base Zone cambió durante la limpieza. Se conservó para revisión.')
    account_digest = hashlib.sha256(json.dumps(accounts, sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest() if accounts else None
    if progress and accounts and progress.get('account_digest') != account_digest:
        raise ZoneError('La cuenta Zone cambió durante la limpieza. Se conservó para revisión.')
    return {'database': name, 'username': user, 'schema_exists': bool(schemas), 'account_exists': bool(accounts), 'user_registered': bool(matches), 'schema_digest': schema_digest, 'account_digest': account_digest, 'config_revision': mysql.revision(config)}


def remove_zone_database(record, save_record):
    """Called only by confirmed game uninstall; caller stops game/web first.

    Persisting intent before DCL/DDL lets interrupted cleanup resume. The root
    Zone state must remain until the entire game uninstall has succeeded.
    """
    snapshot = zone_database_removal_snapshot(record)
    if not record.get('database_cleanup'):
        record['database_cleanup'] = {key: snapshot[key] for key in ('database', 'username', 'schema_digest', 'account_digest')}
        record['database_cleanup']['phase'] = 'prepared'
        save_record(record)
    if snapshot['account_exists'] or snapshot['user_registered']:
        request = {'action': 'delete-user', 'username': snapshot['username']}
        proposal = mysql.plan(request)
        mysql.change({**request, 'revision': proposal['revision'], 'confirm': True}, catalog.flow.repair_monitors)
    record['database_cleanup']['phase'] = 'user_removed'
    save_record(record)
    # Recheck ownership/grants after DCL and before irreversible schema removal.
    snapshot = zone_database_removal_snapshot(record)
    if snapshot['schema_exists']:
        with mysql.connect() as conn:
            mysql.execute(conn, 'DROP DATABASE ' + mysql.ident(snapshot['database']))
            conn.commit()
    config = mysql.load()
    config['databases'] = [name for name in config['databases'] if name != snapshot['database']]
    mysql.save(config)
    record['database_cleanup']['phase'] = 'removed'
    save_record(record)


ZONE_BACKUPS=[Path('/var/backups/server-monitor-zone-update'),Path('/var/backups/server-monitor-zone-web'),Path('/var/backups/server-monitor-zone-schema')]
ZONE_UNIT=Path('/etc/systemd/system')/zone.WEB_UNIT
ZONE_RUNTIME=Path('/run/server-monitor-zone')

def _zone_owned():
 row=game.read_json(zone.STATE)
 if not row or not isinstance(row.get('public'),dict):raise ZoneError('Falta el registro de la instalación Zone; se conservó para revisión.')
 return row

def _identity(name,home,uid=None,gid=None):
 try:account=pwd.getpwnam(name)
 except KeyError:return None
 if account.pw_uid<=0 or account.pw_dir!=str(home) or account.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/usr/bin/nologin') or uid is not None and account.pw_uid!=uid or gid is not None and account.pw_gid!=gid:raise ZoneError('La identidad '+name+' tiene cambios ajenos. No se inició la eliminación.')
 return account

def _zone_identity(record):
 saved=record.get('web_identity')
 if saved is not None and (not isinstance(saved,dict) or type(saved.get('uid')) is not int or type(saved.get('gid')) is not int or type(saved.get('created')) is not bool):raise ZoneError('El registro de la identidad web no es válido.')
 if saved is not None and not saved['created']:return None
 account=_identity('sm-zone-web',zone.SITE,saved['uid'] if saved else None,saved['gid'] if saved else None)
 if account:
  group=grp.getgrgid(account.pw_gid)
  if group.gr_name!='sm-zone-web' or any(member!='sm-zone-web' for member in group.gr_mem) or any(p.pw_name!='sm-zone-web' and p.pw_gid==group.gr_gid for p in pwd.getpwall()):raise ZoneError('La identidad web comparte su grupo con otra cuenta. Se conservó para revisión.')
 return account

def _zone_files(record):
 paths=[zone.SITE,zone.CONFIG,zone.CACHE,ZONE_UNIT,*ZONE_BACKUPS]
 removal.validate_paths(paths)
 if ZONE_UNIT.exists():
  info=ZONE_UNIT.stat();text=ZONE_UNIT.read_text()
  if info.st_uid!=0 or info.st_mode&0o022 or 'RuntimeDirectory=server-monitor-zone' not in text or ' -F -y '+str(zone.CONFIG/'php-fpm.conf') not in text:raise ZoneError('La unidad web Zone tiene contenido ajeno. Se conservó para revisión.')
 account=_zone_identity(record)
 runtime=[]
 if ZONE_RUNTIME.exists():
  removal.validate_paths([ZONE_RUNTIME]);info=ZONE_RUNTIME.stat()
  if not ZONE_RUNTIME.is_dir() or info.st_uid!=0 or info.st_mode&0o022:raise ZoneError('El directorio temporal de Zone no es seguro.')
  owners={0,account.pw_uid if account else 0}
  config=zone.CONFIG/'php-fpm.conf'
  if config.exists():
   names=re.findall(r'(?m)^listen.owner=([a-zA-Z_][a-zA-Z0-9_-]{0,31})$',config.read_text())
   if len(names)==1:
    try:owners.add(pwd.getpwnam(names[0]).pw_uid)
    except KeyError:pass
  for path in ZONE_RUNTIME.iterdir():
   info=path.lstat()
   if path.name!='php.sock' or not stat.S_ISSOCK(info.st_mode) or info.st_uid not in owners:raise ZoneError('El directorio temporal Zone contiene archivos ajenos. No se inició la eliminación.')
   runtime.append(dict(name=path.name,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode)))
 return dict(paths=[str(p) for p in paths],identity={'uid':account.pw_uid,'gid':account.pw_gid} if account else None,runtime=runtime,unit_sha256=hashlib.sha256(ZONE_UNIT.read_bytes()).hexdigest() if ZONE_UNIT.exists() else None)

def snapshot(record):
 if not record:raise ZoneError('No hay un juego administrado para eliminar.')
 removal.validate_paths([game.BASE,game.UNIT,game.ROTATE])
 _identity(game.USER,game.BASE,record['uid'],record.get('gid'))
 unit_hash=None
 if game.UNIT.exists():
  info=game.UNIT.stat();text=game.UNIT.read_text()
  if info.st_uid!=0 or info.st_mode&0o022 or 'ExecStart='+str(game.BASE/'samp03svr') not in text or 'User='+game.USER not in text or 'WorkingDirectory='+str(game.BASE) not in text:raise ZoneError('La unidad del juego tiene cambios ajenos. Se conservó para revisión.')
  unit_hash=hashlib.sha256(game.UNIT.read_bytes()).hexdigest()
 ftp_revision=None
 if record.get('ftp'):
  _identity(game.game_ftp.SYSTEM_USER,game.BASE,record['ftp']['uid'],record.get('gid'))
  config=game.game_ftp.ftp.load();value=record['ftp']
  for item in config['users']:
   if item['username']==value['username'] and (item.get('game')!='samp' or item['root']!=game.game_ftp.ROOT_NAME) or item['username']!=value['username'] and (item.get('game')=='samp' or item['root']==game.game_ftp.ROOT_NAME):raise ZoneError('La cuenta FTP del juego tiene una asignación ajena. Se conservó para revisión.')
  ftp_revision=game.game_ftp.ftp.revision(config)
 owned=_zone_owned() if record.get('edition')=='zone' else None
 resources=None;database=None
 if owned:
  resources=_zone_files(owned)
  if owned.get('database_cleanup',{}).get('phase')=='removed' and not mysql.load()['installed']:
   database={'database':owned['public']['database'],'username':owned['public']['db_user'],'schema_exists':False,'account_exists':False,'user_registered':False}
  else:database=zone_database_removal_snapshot(owned)
 provenance=(owned or record).get('dependencies')
 dependencies=dependency_removal_snapshot(provenance,zone_record=owned,game_record=record)
 remove=['Archivos del juego, gamemodes, plugins, scriptfiles y registros','Servicio y usuario del juego; sus reglas UDP']
 if record.get('ftp'):remove.append('Cuenta FTPS '+record['ftp']['username']+' y credencial guardada en el panel')
 if owned:remove+=['Web Zone y su foro en /foro/, configuración, caché y respaldos exclusivos','Base de datos '+database['database']+' completa, incluidas cuentas de jugadores y tablas del foro','Usuario MySQL '+database['username']+' y todos sus accesos administrados']
 remove+=dependencies.get('remove',[])
 preserve=['Bibliotecas compartidas del sistema y componentes del panel',*dependencies.get('preserve',[])]
 return dict(remove=remove,preserve=preserve,material=dict(game=record,game_unit=unit_hash,ftp_revision=ftp_revision,zone=owned,resources=resources,database=database,dependencies=dependencies))

def stop_zone_web(record):
 if record.get('edition')!='zone':return
 game.run(['systemctl','disable','--now',zone.WEB_UNIT],check=False)
 if game.run(['systemctl','is-active',zone.WEB_UNIT],check=False).stdout.strip() in ('active','activating','reloading','deactivating'):raise ZoneError('No se pudo detener la web Zone. Se conservaron sus archivos y su base.')
 zone.MARKER.unlink(missing_ok=True)
 stack=catalog.read(web.STATE/'stack.json')
 if stack:web.publish(catalog,linux.detect(),stack,{kind for kind in web.APPS if web.own(catalog,kind)},stack.get('frontuser','www-data'))

def remove_data(record):
 if record.get('edition')!='zone':return
 owned=_zone_owned()
 if owned.get('database_cleanup',{}).get('phase')=='removed' and not mysql.load()['installed']:return
 remove_zone_database(owned,lambda value:game.write_json(zone.STATE,value))

def finish(record,reviewed):
 owned=_zone_owned() if record.get('edition')=='zone' else None
 provenance=(owned or record).get('dependencies')
 holder=owned if owned is not None else record
 def save(value):
  holder['dependencies']=value
  game.write_json(zone.STATE if owned is not None else game.STATE,holder)
 if owned:
  resources=_zone_files(owned)
  for path in (zone.SITE,zone.CONFIG,zone.CACHE,ZONE_UNIT,*ZONE_BACKUPS):removal.remove_path(path)
  account=_zone_identity(owned)
  if account:
   game.run(['userdel','sm-zone-web'])
   try:group=grp.getgrnam('sm-zone-web')
   except KeyError:group=None
   if group:game.run(['groupdel','sm-zone-web'])
  if ZONE_RUNTIME.exists():
   removal.safe_path(ZONE_RUNTIME)
   socket=ZONE_RUNTIME/'php.sock'
   if socket.exists():
    info=socket.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in {0,*[item['uid'] for item in resources['runtime']]}:raise ZoneError('El directorio temporal web tiene un archivo ajeno.')
    socket.unlink()
   ZONE_RUNTIME.rmdir()
 # The controller holds the existing shared firewall lock; each service API
 # takes its own package lock and revalidates its own removal scope.
 result=apply_dependency_removals(provenance,owned,record,save,reviewed['material']['dependencies'])
 if provenance and 'web_stack' in provenance.get('completed',[]):
  identity=provenance.get('web_identity')
  if identity:
   account=_identity('server-monitor-web','/nonexistent',identity['uid'],identity['gid'])
   if account:
    group=grp.getgrgid(account.pw_gid)
    if group.gr_name!='server-monitor-web' or group.gr_mem or any(p.pw_name!='server-monitor-web' and p.pw_gid==group.gr_gid for p in pwd.getpwall()):raise ZoneError('La identidad PHP compartida cambió; se conservó para revisión.')
    game.run(['userdel','server-monitor-web'])
    try:group=grp.getgrnam('server-monitor-web')
    except KeyError:group=None
    if group:game.run(['groupdel','server-monitor-web'])
  for path in (web.BASE,web.CACHE,web.STATE):
   if path.exists() and path.is_dir() and not any(path.iterdir()):removal.safe_path(path);path.rmdir()
 game.run(['systemctl','daemon-reload'])
 return result

def complete(record):
 if record.get('edition')=='zone':zone.STATE.unlink(missing_ok=True)

"""Root-only dependency provenance and conservative SA-MP dependency removal.

This file is a workspace integration helper. No browser-selected names, paths,
packages or commands are accepted by these interfaces.
"""
import hashlib
import json
from pathlib import Path
import re
import types

_DEP_KINDS=('ftp','mysql','phpmyadmin','web_stack')
_DEP_LABELS={'ftp':'Servicio FTP','mysql':'MySQL / MariaDB','phpmyadmin':'phpMyAdmin','web_stack':'Servidor web y PHP exclusivos'}
_DEP_WEB_PACKAGE=re.compile(r'(?:nginx(?:-(?:common|core|full|light|extras|filesystem|modules))?|libnginx-mod-[a-z0-9-]+|php(?:[0-9]{1,2}\.[0-9]{1,2})?(?:-(?:fpm|cli|common|mysql|mysqlnd|mbstring|xml|curl|zip|gd|intl|opcache|readline|pdo|process|pecl-zip))?)')
_DEP_WEB_PACKAGE=re.compile(r'(?:'+_DEP_WEB_PACKAGE.pattern+r'|php-[a-z0-9][a-z0-9+.-]*)')
_DEP_PACKAGE=re.compile(r'(?:'+_DEP_WEB_PACKAGE.pattern+r'|vsftpd|phpmyadmin|phpMyAdmin|php-phpmyadmin-(?:motranslator|shapefile|sql-parser)|php-twig-i18n-extension|mariadb-(?:server|server-core|client|client-core)(?:-[0-9.]+)?|mariadb-plugin-provider-(?:bzip2|lz4|lzma|lzo|snappy)|mysql(?:8\.4)?(?:-community)?-(?:server|server-core|client|client-core|client-plugins)(?:-[0-9.]+)?|dbconfig-mysql)')
_DEP_SYSTEM_USERS={'root','mysql','mysql.sys','mysql.session','mysql.infoschema','mariadb.sys','debian-sys-maint'}


def _dependency_modules():
 import storypulse_games as game
 import storypulse_zone as zone
 import storypulse_mysql as mysql
 import storypulse_services as ftp
 import storypulse_catalog as catalog
 import storypulse_webapps as web
 import storypulse_platform as linux
 import storypulse_uninstall as removal
 import storypulse_cloudflare as cloudflare
 return types.SimpleNamespace(**locals())


def _dependency_rule(rule):
 keys=('action','direction','family','protocol','source','destination','spans','interface','comment','any_source','any_port')
 return {key:rule.get(key) for key in keys}


def _dependency_http_rules(m):
 rules=m.game.ports.read_snapshot()['rules']
 result=[_dependency_rule(row) for row in rules if row.get('comment') in ('StoryPulse port tcp/80','StoryPulse port tcp/443') and row.get('protocol')=='tcp' and row.get('direction')=='IN' and row.get('action')=='ALLOW' and row.get('spans') in ([(80,80)],[(443,443)]) and row.get('any_source') is True and not row.get('interface')]
 return sorted(result,key=lambda row:json.dumps(row,sort_keys=True))


def capture_dependency_inventory():
 m=_dependency_modules();p=m.linux.detect();m.mysql.configure_platform(p);m.ftp.configure_platform()
 packages=m.catalog.package_inventory(p)
 cohort=sorted(name for name in packages if _DEP_PACKAGE.fullmatch(name))
 mysql_present=m.mysql.STATE.exists() or m.mysql.load()['installed'] or any(re.fullmatch(r'(?:mysql(?:8\.4)?(?:-community)?|mariadb)-(?:server|server-core)(?:-[0-9.]+)?|mariadb',name) for name in packages)
 ftp_present=m.ftp.CONFIG.exists() or m.ftp.BASE.exists() or 'vsftpd' in packages
 pma_present=bool(m.web.own(m.catalog,'phpmyadmin')) or m.web.app_site(p,'phpmyadmin').exists() or any(name in packages for name in ('phpmyadmin','phpMyAdmin'))
 web_present=bool(m.catalog.read(m.web.STATE/'stack.json')) or m.web.CONF.exists() or m.web.UNIT.exists() or any(re.fullmatch(r'nginx(?:-[a-z0-9-]+)?|apache2|httpd|php(?:[0-9]{1,2}\.[0-9]{1,2})?-fpm',name) for name in packages)
 try:account=m.game.pwd.getpwnam('server-monitor-web');identity=dict(uid=account.pw_uid,gid=account.pw_gid)
 except (KeyError,AttributeError):identity=None
 return dict(version=1,profile=m.web.profile(p),packages=cohort,service_exists=dict(ftp=bool(ftp_present),mysql=bool(mysql_present),phpmyadmin=bool(pma_present),web_stack=bool(web_present)),web_identity=identity,http_rules=_dependency_http_rules(m))


def finish_provenance(before):
 if not isinstance(before,dict) or before.get('version')!=1 or set(before.get('service_exists',{}))!=set(_DEP_KINDS):raise RuntimeError('No se pudo verificar el inventario anterior de dependencias.')
 if any(type(value) is not bool for value in before['service_exists'].values()):raise RuntimeError('Inventario de dependencias no válido.')
 after=capture_dependency_inventory()
 if before.get('profile')!=after['profile']:raise RuntimeError('La distribución cambió durante la instalación.')
 if not isinstance(before.get('packages'),list) or any(not isinstance(name,str) or not _DEP_PACKAGE.fullmatch(name) for name in before['packages']):raise RuntimeError('Inventario de paquetes no válido.')
 previous={json.dumps(row,sort_keys=True) for row in before.get('http_rules',[])}
 identity=after.get('web_identity') if before.get('web_identity') is None else None
 return dict(version=1,created={kind:not before['service_exists'][kind] and after['service_exists'][kind] for kind in _DEP_KINDS},present=after['service_exists'],web_identity=identity,packages_added=sorted(set(after['packages'])-set(before['packages'])),http_rules_added=[row for row in after['http_rules'] if json.dumps(row,sort_keys=True) not in previous],completed=[])


def _dependency_provenance(provenance):
 if provenance is None:return None
 if not isinstance(provenance,dict) or provenance.get('version')!=1 or set(provenance.get('created',{}))!=set(_DEP_KINDS) or any(type(v) is not bool for v in provenance['created'].values()):raise RuntimeError('La procedencia de las dependencias no es válida.')
 packages=provenance.get('packages_added')
 if not isinstance(packages,list) or len(packages)>256 or any(not isinstance(name,str) or not _DEP_PACKAGE.fullmatch(name) for name in packages):raise RuntimeError('La lista de paquetes de la instalación no es válida.')
 completed=provenance.get('completed',[])
 if not isinstance(completed,list) or any(kind not in (*_DEP_KINDS,'http_rules') for kind in completed):raise RuntimeError('El progreso de eliminación no es válido.')
 present=provenance.get('present')
 if present is not None and (not isinstance(present,dict) or set(present)!=set(_DEP_KINDS) or any(type(value) is not bool for value in present.values())):raise RuntimeError('El inventario final de dependencias no es válido.')
 identity=provenance.get('web_identity')
 if identity is not None and (not isinstance(identity,dict) or set(identity)!={'uid','gid'} or any(type(value) is not int or value<=0 for value in identity.values())):raise RuntimeError('La identidad PHP registrada no es válida.')
 rules=provenance.get('http_rules_added',[])
 if not isinstance(rules,list) or len(rules)>4:raise RuntimeError('Las reglas web de la instalación no son válidas.')
 for row in rules:
  if not isinstance(row,dict) or row.get('comment') not in ('StoryPulse port tcp/80','StoryPulse port tcp/443') or row.get('protocol')!='tcp' or row.get('direction')!='IN' or row.get('action')!='ALLOW' or row.get('family') not in (4,6) or row.get('any_source') is not True or row.get('interface') or row.get('any_port'):raise RuntimeError('Una regla web no pertenece al alcance permitido.')
  port=80 if row['comment'].endswith('/80') else 443
  if row.get('destination')!=str(port)+'/tcp' or [list(pair) for pair in row.get('spans',[])]!=[[port,port]]:raise RuntimeError('Una regla web no corresponde al puerto esperado.')
 return provenance


def _dependency_consumers(m,zone_record,game_record):
 value=(zone_record or {}).get('public',{});database=value.get('database');username=value.get('db_user')
 m.mysql.configure_platform();m.ftp.configure_platform()
 config=m.mysql.load();ftp_config=m.ftp.load()
 others_ftp=[item['username'] for item in ftp_config['users'] if not (item.get('game')=='samp' and item['username']==((game_record or {}).get('ftp') or {}).get('username'))]
 dbs=set(config['databases'])-{database};users={item['username'] for item in config['users'] if item['username']!=username or item['database']!=database};unknown=False
 if config['installed']:
  try:
   with m.mysql.connect() as conn:
    dbs|={row['SCHEMA_NAME'] for row in m.mysql.query(conn,'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA') if row['SCHEMA_NAME'] not in m.mysql.SYSTEM and row['SCHEMA_NAME']!=database}
    for row in m.mysql.query(conn,'SELECT User,Host FROM mysql.user'):
     if row['User'] in _DEP_SYSTEM_USERS:continue
     if row['User']==username and row['Host']=='localhost':continue
     users.add(row['User']+'@'+row['Host'])
  except Exception:unknown=True
 apps=sorted(kind for kind in m.web.APPS if m.web.own(m.catalog,kind))
 return dict(ftp=sorted(others_ftp),databases=sorted(dbs),users=sorted(users),database_unknown=unknown,apps=apps,cloudflare=bool(m.cloudflare.enabled()))


def _dependency_web_preflight(m,provenance,*,check_packages=True):
 p=m.linux.detect();inventory=m.catalog.package_inventory(p);stack=m.catalog.read(m.web.STATE/'stack.json')
 if stack and stack.get('mode')!='dedicated':raise RuntimeError('El frontal web existente se conserva.')
 if stack:m.web.front(m.catalog,p,inventory)
 identity=provenance.get('web_identity')
 if identity:
  try:account=m.game.pwd.getpwnam('server-monitor-web')
  except KeyError:account=None
  if account:
   import grp
   group=grp.getgrgid(account.pw_gid)
   if account.pw_uid!=identity['uid'] or account.pw_gid!=identity['gid'] or account.pw_dir!='/nonexistent' or account.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/usr/bin/nologin') or group.gr_name!='server-monitor-web' or group.gr_mem or any(user.pw_name!='server-monitor-web' and user.pw_gid==group.gr_gid for user in m.game.pwd.getpwall()):raise RuntimeError('La identidad PHP se utiliza fuera de esta instalación.')
 # A custom native site or pool introduced after Zone also needs its packages.
 for directory in (Path('/etc/nginx/conf.d'),Path('/etc/nginx/sites-enabled')):
  if not directory.exists():continue
  for path in directory.iterdir():
   if stack and str(path)==stack.get('vhost'):continue
   if directory.name=='sites-enabled' and path.name=='default':
    if path.is_symlink() and path.resolve()!=Path('/etc/nginx/sites-available/default'):raise RuntimeError('El sitio Nginx predeterminado apunta a otra web.')
    continue
   if path.name.endswith('.conf') or directory.name=='sites-enabled':raise RuntimeError('Hay otro sitio o una configuración Nginx compartida.')
 pool_dirs=[*Path('/etc/php').glob('*/fpm/pool.d'),Path('/etc/php-fpm.d')]
 for directory in pool_dirs:
  if directory.exists() and any(path.name!='www.conf' for path in directory.iterdir() if path.name.endswith('.conf')):raise RuntimeError('Hay otro pool PHP que necesita las dependencias compartidas.')
 packages=sorted(name for name in provenance['packages_added'] if name in inventory and _DEP_WEB_PACKAGE.fullmatch(name))
 if p['family']=='apt' and packages:
  result=m.catalog.run(['dpkg','--verify',*packages],timeout=90,check=False)
  if result.returncode not in (0,1) or result.stdout.strip():raise RuntimeError('Hay configuración PHP/Nginx modificada; se conservan los paquetes.')
 if p['family']!='apt' and packages:raise RuntimeError('La eliminación de dependencias web se habilita inicialmente para Debian.')
 module=types.SimpleNamespace(distribution=lambda:p,run=m.catalog.run,ENGINE='none')
 command=m.removal.package_preflight(module,packages) if check_packages else None
 if command and p['family']=='apt' and command[2:]!=packages:raise RuntimeError('El gestor propone retirar otras dependencias.')
 return dict(packages=packages,command=command,stack=stack)


def _dependency_service_scope(m,kind):
 module=getattr(m,kind);namespace=types.SimpleNamespace(**vars(module));definition=m.removal.scope(kind,namespace)
 marker=m.removal.safe_path(definition['marker'])
 if not marker.exists():return None
 if not marker.is_file() or marker.stat().st_uid!=0 or marker.stat().st_mode&0o077:raise RuntimeError('La marca del servicio no es segura.')
 config=module.load();m.removal.validate_paths(definition['paths'])
 if kind=='ftp':m.removal.ftp_identity(namespace)
 else:
  if module.CNF.exists() and module.TLS.as_posix() not in module.CNF.read_text() and config['installed']:raise RuntimeError('La configuración MySQL cambió fuera del panel.')
  repo=Path('/etc/apt/sources.list.d/storypulse-mysql.list')
  if repo.exists() and ('https://repo.mysql.com/apt/debian/' not in repo.read_text() or 'signed-by=/usr/share/keyrings/storypulse-mysql.gpg' not in repo.read_text()):raise RuntimeError('El repositorio MySQL contiene cambios externos.')
  if config['installed'] and module.active()=='active':
   with module.connect() as conn:rows=module.query(conn,'SELECT @@datadir AS directory')
   if not rows or str(rows[0]['directory']).rstrip('/')!='/var/lib/mysql':raise RuntimeError('MySQL usa un directorio de datos externo.')
 return dict(paths=[str(path) for path in definition['paths']])


def _dependency_package_group(m,kind,provenance,inventory):
 added={name for name in provenance['packages_added'] if name in inventory}
 if kind=='ftp':return sorted(added&{'vsftpd'})
 if kind=='mysql':return sorted(name for name in added if re.fullmatch(r'(?:mysql(?:8\.4)?(?:-community)?|mariadb)-(?:server|server-core|client|client-core|client-plugins)(?:-[0-9.]+)?|mariadb-plugin-provider-(?:bzip2|lz4|lzma|lzo|snappy)|dbconfig-mysql',name))
 if kind=='phpmyadmin':
  p=m.linux.detect();recipe=m.catalog.recipe(kind,p,m.catalog.run)
  return sorted(name for name in added if re.fullmatch(recipe['cohort'],name))
 return sorted(name for name in added if _DEP_WEB_PACKAGE.fullmatch(name))


def _dependency_combined_preflight(m,packages):
 packages=sorted(set(packages));p=m.linux.detect();namespace=types.SimpleNamespace(distribution=lambda:p,run=m.catalog.run,ENGINE='none')
 command=m.removal.package_preflight(namespace,packages)
 if command and p['family']=='apt' and command[2:]!=packages:raise RuntimeError('El gestor propone retirar paquetes que no pertenecen al juego.')
 return command


def dependency_removal_snapshot(provenance,zone_record=None,game_record=None):
 m=_dependency_modules();provenance=_dependency_provenance(provenance)
 result=dict(candidates=[],remove=[],preserve=[],plans={})
 if provenance is None:
  result['preserve']=['FTP, MySQL, phpMyAdmin, servidor web y PHP: instalación anterior sin registro de procedencia; se conservan los servicios compartidos.'];return result
 consumers=_dependency_consumers(m,zone_record,game_record);result['consumers']=consumers
 created=provenance['created'];complete=set(provenance.get('completed',[]));other_apps=[kind for kind in consumers['apps'] if kind!='phpmyadmin']
 free_database=not(consumers['databases'] or consumers['users'] or consumers['database_unknown'])
 pma_removable=created['phpmyadmin'] and not other_apps and free_database
 reasons={
  'ftp':'hay otras cuentas FTP' if consumers['ftp'] else '',
  'phpmyadmin':'administra otras bases, usuarios o aplicaciones' if not pma_removable else '',
  'mysql':'hay otras bases, usuarios o aplicaciones, o no se pudo verificar su inventario' if not free_database or other_apps or ('phpmyadmin' in consumers['apps'] and not pma_removable) else '',
  'web_stack':'hay otros sitios, phpMyAdmin compartido o protección Cloudflare' if other_apps or ('phpmyadmin' in consumers['apps'] and not pma_removable) or consumers['cloudflare'] else ''}
 for kind in ('phpmyadmin','ftp','mysql','web_stack'):
  if kind in complete:continue
  if not created[kind]:
   if provenance.get('present',{}).get(kind,True):result['preserve'].append(_DEP_LABELS[kind]+': ya existía antes de instalar el juego.')
   continue
  reason=reasons[kind]
  if not reason:
   try:
    request=dict(action='uninstall',erase_data=True)
    if kind=='phpmyadmin':plan=m.catalog.plan(dict(service=kind,**request)) if m.web.own(m.catalog,kind) else None
    elif kind in ('ftp','mysql'):plan=_dependency_service_scope(m,kind)
    else:plan=_dependency_web_preflight(m,provenance,check_packages=False)
    result['plans'][kind]=plan
   except Exception as exc:reason='no pasó la verificación de eliminación segura: '+str(exc)[:300]
  if reason:result['preserve'].append(_DEP_LABELS[kind]+': '+reason+'.')
  else:result['candidates'].append(kind);result['remove'].append(_DEP_LABELS[kind])
 inventory=m.catalog.package_inventory(m.linux.detect())
 packages=sorted({name for kind in result['candidates'] for name in _dependency_package_group(m,kind,provenance,inventory)})
 try:command=_dependency_combined_preflight(m,packages)
 except Exception as exc:
  result['preserve']+=['Dependencias creadas para el juego: no pasó la simulación conjunta: '+str(exc)[:300]]
  result['candidates']=[];result['remove']=[];result['plans']={};packages=[];command=None
 result['packages']=packages;result['package_command']=command
 return result


def apply_dependency_removals(provenance,zone_record,game_record,saveprogress,approved_snapshot):
 """Own DB, site and game FTP account have already been removed by the caller.

 securityctl owns the firewall lock; each service API takes its own package lock.
 The callback must persist the supplied provenance before the next phase.
 """
 provenance=_dependency_provenance(provenance)
 if provenance is None:return dependency_removal_snapshot(None,zone_record,game_record)
 m=_dependency_modules();initial=dependency_removal_snapshot(provenance,zone_record,game_record)
 if approved_snapshot is None:raise RuntimeError('Falta el alcance revisado para eliminar dependencias.')
 approved=set(approved_snapshot.get('candidates',[]))
 if not approved<=set(_DEP_KINDS):raise RuntimeError('El alcance de dependencias revisado no es válido.')
 allowed=set(initial['candidates'])&approved
 for kind in ('phpmyadmin','ftp','mysql','web_stack'):
  if kind not in allowed or kind in provenance.get('completed',[]):continue
  # Never expand the reviewed removal scope after another component disappears.
  fresh=dependency_removal_snapshot(provenance,zone_record,game_record)
  if kind not in fresh['candidates']:continue
  request=dict(action='uninstall',erase_data=True)
  if kind=='phpmyadmin':
   if m.web.own(m.catalog,kind):
    plan=m.catalog.plan(dict(service=kind,**request));m.catalog.apply(dict(service=kind,**request,revision=plan['revision'],confirm=True))
  elif kind in ('ftp','mysql'):
   module=getattr(m,kind);marker=module.CONFIG if kind=='ftp' else module.STATE
   if marker.exists():
    namespace=types.SimpleNamespace(**vars(module));plan=m.removal.plan(kind,namespace,request)
    m.removal.apply(kind,namespace,dict(**request,revision=plan['revision'],confirm=True),m.catalog.flow.repair_monitors,firewall_locked=True)
  else:
   plan=_dependency_web_preflight(m,provenance)
   if plan['stack']:m.web.withdraw(m.catalog,plan['stack'])
   with m.removal.package_lock():
    verified=_dependency_web_preflight(m,provenance)
    if verified['command']:m.catalog.run(verified['command'],timeout=720)
    remaining=m.catalog.package_inventory(m.linux.detect())
    if any(name in remaining for name in verified['packages']):raise RuntimeError('Quedan paquetes web; se conservó el progreso para reintentar.')
  provenance['completed']=sorted(set(provenance.get('completed',[]))|{kind});saveprogress(provenance)
 # HTTP rules belong to the installation only when they were absent initially.
 if 'web_stack' in provenance.get('completed',[]) and 'http_rules' not in provenance.get('completed',[]) and not m.cloudflare.enabled():
  wanted={json.dumps(row,sort_keys=True) for row in provenance.get('http_rules_added',[])}
  rules=m.game.ports.read_snapshot()['rules']
  for row in sorted(rules,key=lambda item:item['number'],reverse=True):
   if json.dumps(_dependency_rule(row),sort_keys=True) in wanted:m.game.run(['ufw','--force','delete',str(row['number'])])
  if wanted:
   m.catalog.flow.repair_monitors(4);m.catalog.flow.repair_monitors(6)
  provenance['completed']=sorted(set(provenance.get('completed',[]))|{'http_rules'});saveprogress(provenance)
 return dependency_removal_snapshot(provenance,zone_record,game_record)
