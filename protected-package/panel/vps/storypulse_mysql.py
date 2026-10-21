"""Fixed MySQL administration and authenticated data operations. No SQL/shell input."""
import contextlib,datetime as dt,decimal,hashlib,ipaddress,json,os,re,secrets,shutil,subprocess,tempfile,time,urllib.request
from pathlib import Path
from storypulse_services import atomic,run,network
import storypulse_platform as linux
import storypulse_versions as versions

PROFILE=None
ENGINE="mysql"
LAYOUT=None
def configure_platform(profile=None,backend=None):
    global PROFILE,ENGINE,LAYOUT,CNF,SOCKET,SERVICE
    PROFILE=profile or linux.detect()
    saved=load()
    # Use the same native engine whether SQL or a dependent web app is installed
    # first. Preserve existing installations and explicitly selected backends.
    backend=saved.get("backend") or ("mysql" if saved["installed"] else backend or ('mariadb' if PROFILE['family'] in ('apt','arch') else None))
    LAYOUT=linux.database_layout(PROFILE,backend)
    ENGINE=LAYOUT["backend"];CNF=Path(LAYOUT["cnf"]);SOCKET=LAYOUT["socket"];SERVICE=LAYOUT["service"]
    return PROFILE

def distribution():return PROFILE or linux.detect()

BASE=Path('/etc/storypulse-mysql')
STATE=BASE/'state.json'
TLS=Path('/etc/mysql/storypulse-tls')
CNF=Path('/etc/mysql/mysql.conf.d/zz-storypulse.cnf')
SOCKET='/var/run/mysqld/mysqld.sock'
BACKUPS=Path('/var/lib/storypulse-security/mysql-backups')
SERVICE='mysql.service'
KEY_FINGERPRINT='BCA43417C3B485DD128EC6D4B7B3B788A8D3785C'
PRIVILEGES=('SELECT','INSERT','UPDATE','DELETE','CREATE','ALTER','INDEX','DROP','REFERENCES')
TYPES=('INT','BIGINT','VARCHAR','TEXT','DECIMAL','DATE','DATETIME','BOOLEAN')
ACTIONS=('install','start','stop','restart','create-database','create-user','update-user','delete-user','network',
         'create-table','add-column','modify-column','drop-column','drop-table','create-index','create-relation','rename-table','rename-column','drop-index','drop-relation')
SYSTEM={'mysql','sys','information_schema','performance_schema'}
BT=chr(96)
class MysqlError(RuntimeError):pass
class OwnershipError(MysqlError):pass

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def ident(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]{0,47}',value):raise MysqlError('Nombre inválido: usá letras, números y guiones bajos, hasta 48 caracteres.')
    return BT+value+BT
def dbname(value):
    ident(value)
    if value.lower() in SYSTEM:raise MysqlError('Las bases internas del servidor no se administran desde este panel.')
    return value
def username(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_]{2,23}',value) or value in ('root','mysql','debian','admin'):raise MysqlError('Usuario inválido: 3 a 24 letras minúsculas, números o guiones bajos.')
    return value
def password(value):
    if not isinstance(value,str) or not 12<=len(value)<=128 or any(ord(c)<32 or ord(c)==127 for c in value):raise MysqlError('Contraseña: 12 a 128 caracteres, sin caracteres de control.')
    try:value.encode('utf-8')
    except UnicodeError:raise MysqlError('La contraseña contiene caracteres inválidos.')
    return value
def boolean(value):
    if type(value) is not bool:raise MysqlError('Opción booleana inválida.')
    return value
def ips(value):
    if not isinstance(value,list) or len(value)>8:raise MysqlError('Indicá hasta ocho direcciones IPv4 públicas concretas por usuario.')
    result=[]
    for item in value:
        if not isinstance(item,str):raise MysqlError('La IP debe escribirse como una dirección IPv4.')
        try:ip=ipaddress.IPv4Address(item)
        except (ValueError,TypeError):raise MysqlError('Indicá una IPv4 concreta, sin rangos ni comodines.')
        if not ip.is_global or ip.is_multicast or ip.is_reserved:raise MysqlError('El acceso externo requiere una IPv4 pública concreta.')
        result.append(str(ip))
    return sorted(set(result))
def privileges(value):
    if not isinstance(value,list) or not value or any(not isinstance(p,str) or p not in PRIVILEGES for p in value) or len(set(value))!=len(value):raise MysqlError('Seleccioná permisos válidos de la base.')
    return [p for p in PRIVILEGES if p in value]
def load():
    if not STATE.exists():return dict(version=1,installed=False,remote=False,databases=[],users=[])
    try:value=json.loads(STATE.read_text(encoding='utf-8'))
    except (ValueError,OSError):raise MysqlError('No se pudo leer la configuración MySQL.')
    if value.get('version')!=1 or type(value.get('installed')) is not bool or type(value.get('remote')) is not bool:raise MysqlError('Configuración MySQL inválida.')
    if not isinstance(value.get('databases'),list) or len(value['databases'])>100 or not isinstance(value.get('users'),list) or len(value['users'])>100:raise MysqlError('Configuración MySQL inválida.')
    for name in value['databases']:dbname(name)
    seen=set()
    for user in value['users']:
        username(user['username']);dbname(user['database']);privileges(user['privileges']);ips(user['ips']);boolean(user['enabled'])
        if user['database'] not in value['databases'] or user['username'] in seen:raise MysqlError('Asociación MySQL inválida.')
        seen.add(user['username'])
    return value
def save(value):atomic(STATE,(canonical(value)+'\n').encode())
def active():return run(['systemctl','is-active',SERVICE],check=False).stdout.strip() or 'inactive'
def revision(value):
    material=canonical(value)+active()
    if CNF.exists():material+=hashlib.sha256(CNF.read_bytes()).hexdigest()
    return hashlib.sha256(material.encode()).hexdigest()
def driver():
    try:import pymysql
    except ImportError:raise MysqlError('Instalá primero MySQL desde Instalar servicios.')
    return pymysql
@contextlib.contextmanager
def connect(user='root',secret='',database=None,*,read_timeout=8):
    pymysql=driver()
    if user=='root' and not secret and (BASE/'root-secret').is_file():secret=(BASE/'root-secret').read_text().strip()
    try:
        conn=pymysql.connect(unix_socket=SOCKET,user=user,password=secret,database=database,charset='utf8mb4',
            autocommit=False,connect_timeout=5,read_timeout=read_timeout,write_timeout=8,max_allowed_packet=4*1024*1024,
            cursorclass=pymysql.cursors.DictCursor)
        try:
            with conn.cursor() as cur:
                cur.execute('SET SESSION lock_wait_timeout=5')
                cur.execute('SET SESSION innodb_lock_wait_timeout=5')
            yield conn
        finally:conn.close()
    except pymysql.MySQLError as exc:
        code=exc.args[0] if exc.args and isinstance(exc.args[0],int) else 0
        messages={1045:'Usuario o contraseña incorrectos.',1044:'El usuario no tiene acceso a esa base.',1142:'El usuario no tiene permiso para esta operación.',
          1143:'Faltan permisos para esos campos.',1062:'Ya existe un registro con ese valor único.',1451:'Otro registro depende de este dato.',1452:'La relación apunta a un registro inexistente.',
          1213:'Otro proceso está modificando estos datos. Recargá e intentá nuevamente.',1205:'La operación quedó esperando otro cambio. Reintentá.',
          1050:'La tabla ya existe.',1060:'El campo ya existe.',1068:'La tabla ya tiene una clave primaria.',1406:'Un valor supera el tamaño permitido por el campo.',
          1364:'Un campo obligatorio quedó sin valor.',1366:'Un valor no corresponde al tipo de campo.',3819:'Los valores incumplen una restricción.',3118:'El usuario está deshabilitado.'}
        raise MysqlError(messages.get(code,f'MySQL rechazó la operación (código {code}). Revisá los tipos, permisos y estado del servicio.')) from None
def query(conn,sql,args=()):
    with conn.cursor() as cur:cur.execute(sql,args);return cur.fetchall()
def execute(conn,sql,args=()):
    with conn.cursor() as cur:cur.execute(sql,args);return cur.rowcount
def require_database(config,name):
    dbname(name)
    if name not in config['databases']:raise MysqlError('Esa base no está administrada por el panel.')
    return ident(name)
def column_spec(field):
    if not isinstance(field,dict):raise MysqlError('Definición de campo inválida.')
    name=ident(field.get('name'));kind=field.get('type')
    if kind not in TYPES:raise MysqlError('Tipo de campo no permitido.')
    nullable=boolean(field.get('nullable',True));primary=boolean(field.get('primary',False));auto=boolean(field.get('auto',False))
    sql=kind
    if kind=='VARCHAR':
        size=field.get('length',255)
        if type(size) is not int or not 1<=size<=4096:raise MysqlError('VARCHAR requiere longitud entre 1 y 4096.')
        sql+='('+str(size)+')'
    if kind=='DECIMAL':
        precision=field.get('precision',10);scale=field.get('scale',2)
        if type(precision) is not int or type(scale) is not int or not 1<=precision<=38 or not 0<=scale<=min(precision,12):raise MysqlError('Precisión o decimales inválidos.')
        sql+=f'({precision},{scale})'
    if auto and (not primary or kind not in ('INT','BIGINT')):raise MysqlError('La numeración automática requiere una clave primaria INT o BIGINT.')
    if primary and kind=='TEXT':raise MysqlError('Usá un identificador numérico o un campo corto como clave primaria.')
    sql+=' NOT NULL' if primary or not nullable else ' NULL'
    if auto:sql+=' AUTO_INCREMENT'
    default=field.get('default')
    args=[]
    if default is not None:
        if auto or kind=='TEXT':raise MysqlError('Ese campo no admite valor predeterminado en el editor.')
        scalar(default);sql+=' DEFAULT %s';args.append(default)
    return name+' '+sql,args,primary
def scalar(value):
    if value is not None and (not isinstance(value,(str,int,float,bool)) or isinstance(value,float) and (value!=value or abs(value)==float('inf'))):raise MysqlError('Valor de celda inválido.')
    if isinstance(value,str):
        if len(value)>65536:raise MysqlError('La celda supera 65536 caracteres.')
        try:value.encode('utf-8')
        except UnicodeError:raise MysqlError('La celda contiene caracteres inválidos.')
    return value
def ddl(conn,payload):
    table=ident(payload.get('table'));action=payload['action'];args=[]
    if action=='create-table':
        fields=payload.get('fields')
        if not isinstance(fields,list) or not 1<=len(fields)<=32:raise MysqlError('Definí entre 1 y 32 campos.')
        names=[f.get('name') if isinstance(f,dict) else None for f in fields]
        for field_name in names:ident(field_name)
        if len(set(n.lower() for n in names))!=len(names):raise MysqlError('Hay campos repetidos.')
        parts=[];primary=[]
        for field in fields:
            fragment,values,is_primary=column_spec(field);parts.append(fragment);args.extend(values)
            if is_primary:primary.append(ident(field['name']))
        if len(primary)>1:raise MysqlError('El editor crea una clave primaria simple por tabla.')
        if primary:parts.append('PRIMARY KEY ('+','.join(primary)+')')
        sql='CREATE TABLE '+table+' ('+','.join(parts)+') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    elif action in ('add-column','modify-column'):
        fragment,args,is_primary=column_spec(payload.get('field'))
        if is_primary or payload['field'].get('auto'):raise MysqlError('En tablas existentes, editá campos sin cambiar la clave primaria o su numeración.')
        sql='ALTER TABLE '+table+(' ADD COLUMN ' if action=='add-column' else ' MODIFY COLUMN ')+fragment
    elif action=='drop-column':sql='ALTER TABLE '+table+' DROP COLUMN '+ident(payload.get('column'))
    elif action=='drop-table':sql='DROP TABLE '+table
    elif action=='rename-table':sql='ALTER TABLE '+table+' RENAME TO '+ident(payload.get('new_name'))
    elif action=='rename-column':sql='ALTER TABLE '+table+' RENAME COLUMN '+ident(payload.get('column'))+' TO '+ident(payload.get('new_name'))
    elif action=='drop-index':
        if payload.get('name','').upper()=='PRIMARY':raise MysqlError('La clave primaria se conserva.')
        sql='DROP INDEX '+ident(payload.get('name'))+' ON '+table
    elif action=='drop-relation':sql='ALTER TABLE '+table+' DROP FOREIGN KEY '+ident(payload.get('name'))
    elif action=='create-index':
        columns=payload.get('columns')
        if not isinstance(columns,list) or not 1<=len(columns)<=4:raise MysqlError('Un índice requiere entre uno y cuatro campos.')
        sql='CREATE '+('UNIQUE ' if boolean(payload.get('unique',False)) else '')+'INDEX '+ident(payload.get('name'))+' ON '+table+' ('+','.join(ident(c) for c in columns)+')'
    elif action=='create-relation':
        sql='ALTER TABLE '+table+' ADD CONSTRAINT '+ident(payload.get('name'))+' FOREIGN KEY ('+ident(payload.get('column'))+') REFERENCES '+ident(payload.get('target_table'))+' ('+ident(payload.get('target_column'))+') ON DELETE RESTRICT ON UPDATE RESTRICT'
    else:raise MysqlError('Operación de estructura no permitida.')
    if conn is not None:
        if action=='modify-column':
            columns=metadata(conn,payload['database'],payload['table'])['columns']
            if any(c['name']==payload['field']['name'] and (c['column_key']=='PRI' or 'auto_increment' in c['extra'] or 'GENERATED' in c['extra']) for c in columns):
                raise MysqlError('La clave primaria y los campos automáticos o generados se conservan. Elegí otro campo.')
        execute(conn,sql,args)
    return sql,args
def collision():
    for row in run(['ss','-H','-lntp']).stdout.splitlines():
        fields=row.split()
        if len(fields)>3 and fields[3].rsplit(':',1)[-1] in ('3306','33060') and 'mysqld' not in row and 'mariadbd' not in row:raise MysqlError('Un puerto necesario está utilizado por otro servicio.')
    path=Path('/etc/storypulse-security/forwarding.json')
    if path.exists() and any(r.get('enabled') and r.get('protocol')=='tcp' and r.get('port') in (3306,33060) for r in json.loads(path.read_text())['entries']):raise MysqlError('Pausá las redirecciones de MySQL antes de iniciar o habilitarlo.')
def platform():
    return distribution()['codename']

def ports_module():
    import importlib.util
    spec=importlib.util.spec_from_file_location('mysql_ports',Path(__file__).with_name('storypulse_ports.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def firewall_preflight():
    mod=ports_module();snapshot=mod.read_snapshot()
    if not snapshot['active'] or snapshot['default'] not in ('deny','reject'):raise MysqlError('El acceso externo requiere UFW activo y denegación entrante predeterminada.')
    protected=snapshot['protected'].get((3306,'tcp'),'')
    if protected and not protected.startswith('MySQL administrado'):raise MysqlError('El puerto 3306 está protegido por otro acceso.')
    for rule in snapshot['rules']:
        if rule['direction']!='IN' or rule['family']!=4:continue
        if not rule['spans'] and not rule['any_port']:raise MysqlError('Hay reglas UFW por aplicación que requieren revisión antes de habilitar MySQL externo.')
        owned=(rule['comment']=='StoryPulse MySQL' and rule['action']=='ALLOW' and rule['spans']==[(3306,3306)] and rule['protocol']=='tcp' and not rule['any_source'] and not rule['interface'])
        if mod.rule_matches(rule,3306,'tcp') and rule['action'] in ('ALLOW','LIMIT') and not owned:
            raise MysqlError('Hay reglas de acceso ajenas al panel que incluyen 3306. Revisalas antes de habilitar el acceso externo.')
    return snapshot
def plan(payload):
    if payload.get('action')=='uninstall':return removal(payload)
    if payload.get('action')=='upgrade':return versions.upgrade_plan('mysql',__import__('types').SimpleNamespace(**globals()),payload)
    config=load();action=payload.get('action');result={'ok':True,'action':action}
    if action not in ACTIONS:raise MysqlError('Acción MySQL no permitida.')
    if action=='install':
        if set(payload)-{'action','selection','confirm','revision'}:raise MysqlError('Campos de instalación no válidos.')
        platform();collision()
        memory=re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)
        if not memory or int(memory[1])<512*1024 or shutil.disk_usage('/var').free<2*1024**3:raise MysqlError('La instalación requiere al menos 512 MB de memoria disponible y 2 GB de espacio libre.')
        if config['installed']:raise MysqlError('MySQL ya está instalado.')
        if not STATE.exists() and (BASE.exists() or Path('/var/lib/mysql/mysql').exists() or any(linux.installed(run,distribution(),p) for p in ('mysql-community-server','mysql-server','mysql8.4-server','mariadb-server','mariadb'))):
            raise MysqlError('Existe una instalación ajena al panel. Se conserva y requiere revisión.')
    else:
        if not config['installed']:raise MysqlError('Instalá primero MySQL desde Instalar servicios.')
        if action in ('start','restart','network'):collision()
        if action=='create-database':
            name=dbname(payload.get('database'))
            if name in config['databases']:
                with connect() as conn:exists=query(conn,'SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(name,))
                if exists:raise MysqlError('La base ya está registrada.')
            elif len(config['databases'])>=100:raise MysqlError('Se alcanzó el límite de bases administradas.')
        elif action in ('create-user','update-user','delete-user'):
            name=username(payload.get('username'));old=next((u for u in config['users'] if u['username']==name),None)
            if action=='create-user' and (old or len(config['users'])>=100):raise MysqlError('El usuario ya existe o se alcanzó el límite.')
            if action!='create-user' and old is None:raise MysqlError('Ese usuario no existe.')
            if action!='delete-user':
                require_database(config,payload.get('database'));privileges(payload.get('privileges'));ips(payload.get('ips'));boolean(payload.get('enabled',True))
                if old and old['database']!=payload['database']:raise MysqlError('La base asignada se mantiene fija para evitar transferencias accidentales de acceso.')
                if config['remote']:firewall_preflight()
        elif action=='network':
            boolean(payload.get('enabled'))
            if payload['enabled']:firewall_preflight()
        elif action not in ('start','stop','restart'):
            require_database(config,payload.get('database'));ddl(None,payload)
    rev=revision(config)
    if action in ('create-table','add-column','modify-column','drop-column','drop-table','create-index','create-relation','rename-table','rename-column','drop-index','drop-relation'):
        with connect() as conn:
            existing=query(conn,'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',(payload['database'],payload['table']))
            structure=query(conn,'SHOW CREATE TABLE '+ident(payload['database'])+'.'+ident(payload['table'])) if existing else []
        rev=hashlib.sha256((rev+canonical(structure)).encode()).hexdigest()
    result.update(revision=rev,notice='La operación está limitada a los objetos administrados por el panel. Las operaciones de estructura pueden afectar datos y requieren confirmación.')
    if action=='install':result['notice']=('Se instalará '+('MariaDB compatible con el panel MySQL desde el repositorio de la distribución' if ENGINE=='mariadb' else 'MySQL y su conector Python desde un repositorio firmado')+'. Acceso inicial privado, sin abrir 3306. Se limita la memoria y la cantidad de conexiones.')
    if action=='install':
        selected=versions.select('mysql',__import__('types').SimpleNamespace(**globals()),payload.get('selection'))
        check,_=versions.commands('mysql',__import__('types').SimpleNamespace(**globals()),selected)
        result_check=run(check,timeout=900,check=False)
        if result_check.returncode:raise MysqlError('No se pudieron resolver las dependencias SQL: '+(result_check.stderr or result_check.stdout)[-1200:])
        result['target_version']=selected['version'];result['revision']=hashlib.sha256((result['revision']+payload['selection']).encode()).hexdigest()
    if action=='network':result['notice']='Se reiniciará sólo MySQL. El acceso externo exige TLS y sólo permite las IPv4 concretas asignadas a usuarios habilitados. Desactivar conserva el acceso privado por SSH.'
    return result
def connection_audit_available():
    return ENGINE=='mariadb' and any((Path(folder)/'server_audit.so').is_file() for folder in
        ('/usr/lib/mysql/plugin','/usr/lib64/mysql/plugin','/usr/lib/mariadb/plugin','/usr/lib/x86_64-linux-gnu/mariadb/plugin'))

def server_config(remote=False):
    address='127.0.0.1,'+network() if remote else '127.0.0.1'
    text=f"""[mysqld]
bind-address={address}
mysqlx=0
require_secure_transport=ON
tls_version=TLSv1.2,TLSv1.3
ssl_cert={TLS}/server.crt
ssl_key={TLS}/server.key
partial_revokes=ON
local_infile=OFF
secure_file_priv=NULL
skip_name_resolve=ON
innodb_buffer_pool_size=128M
innodb_log_buffer_size=16M
max_connections=30
max_allowed_packet=4M
table_open_cache=256
thread_cache_size=4
tmp_table_size=16M
max_heap_table_size=16M
temptable_max_ram=32M
performance_schema=OFF
"""
    if ENGINE=='mariadb':
        text=text.replace('mysqlx=0\n','').replace('partial_revokes=ON\n','').replace('temptable_max_ram=32M\n','')
        text=text.replace('secure_file_priv=NULL','secure_file_priv=/var/lib/mysql-files')
        if remote:text=text.replace('bind-address='+address,'bind-address=0.0.0.0')
    if connection_audit_available():
        text+='plugin_load_add=server_audit\nserver_audit_events=CONNECT\nserver_audit_output_type=SYSLOG\nserver_audit_syslog_ident=storypulse-db-audit\nserver_audit_logging=ON\n'
    return text+'socket='+SOCKET+'\n' 

def repository():
    if not (LAYOUT or linux.database_layout(distribution()))['oracle']:
        packages=(LAYOUT or linux.database_layout(distribution()))['packages']
        linux.install_packages(run,distribution(),[p for p in packages if p!=packages[0]])
        return
    codename=platform()
    linux.install_packages(run,distribution(),['ca-certificates','gnupg','python3-pymysql'])
    with tempfile.TemporaryDirectory(prefix='storypulse-mysql-key-') as temp:
        path=Path(temp)/'key.asc'
        with urllib.request.urlopen('https://repo.mysql.com/RPM-GPG-KEY-mysql-2025',timeout=20) as response:content=response.read(16384)
        path.write_bytes(content)
        output=run(['gpg','--batch','--with-colons','--show-keys',str(path)]).stdout
        fingerprints=[line.split(':')[9] for line in output.splitlines() if line.startswith('fpr:')]
        if not fingerprints or fingerprints[0]!=KEY_FINGERPRINT:raise MysqlError('La firma del repositorio MySQL no coincide con la clave esperada.')
        key=run(['gpg','--batch','--yes','--dearmor','--output',str(Path(temp)/'key.gpg'),str(path)])
        atomic(Path('/usr/share/keyrings/storypulse-mysql.gpg'),(Path(temp)/'key.gpg').read_bytes(),0o644)
    current=versions.package_version(run,distribution(),'mysql-community-server')
    branch='mysql-9.7-lts' if current.startswith('9.7.') else 'mysql-innovation' if current.startswith('9.') else 'mysql-8.4-lts'
    atomic(Path('/etc/apt/sources.list.d/storypulse-mysql.list'),f'deb [arch=amd64 signed-by=/usr/share/keyrings/storypulse-mysql.gpg] https://repo.mysql.com/apt/debian/ {codename} {branch}\n'.encode(),0o644)
    run(['apt-get','-o','DPkg::Lock::Timeout=30','update'],timeout=180)
    candidate=run(['apt-cache','policy','mysql-community-server']).stdout
    if not re.search(r'Candidate: (?:8\.4|9\.[0-9]+)\.',candidate):raise MysqlError('No hay un paquete MySQL firmado compatible con la rama instalada.')
def initialize_database():
    import pwd
    bootstrap=Path('/var/lib/mysql/.storypulse-bootstrap.sql')
    secret=None
    if ENGINE=='mysql' and distribution()['family']=='rpm' and not load()['installed']:
        secret=(BASE/'root-secret').read_text().strip() if (BASE/'root-secret').exists() else secrets.token_urlsafe(40)
        if not re.fullmatch(r'[A-Za-z0-9_-]{40,80}',secret):raise MysqlError('Credencial interna MySQL inválida.')
        atomic(BASE/'root-secret',(secret+'\n').encode())
    if not Path('/var/lib/mysql/mysql').exists():
        if ENGINE=='mariadb':
            run(['mariadb-install-db','--user=mysql','--basedir=/usr','--datadir=/var/lib/mysql','--auth-root-authentication-method=socket'],timeout=120)
        elif distribution()['family']=='rpm':
            run(['mysqld','--initialize-insecure','--user=mysql','--datadir=/var/lib/mysql'],timeout=120)
    if secret:
        atomic(bootstrap,("ALTER USER 'root'@'localhost' IDENTIFIED BY '"+secret+"';\n").encode(),0o640)
        identity=pwd.getpwnam('mysql');os.chown(bootstrap,0,identity.pw_gid)

def wait_ready():
    for attempt in range(30):
        try:
            with connect() as conn:
                query(conn,'SELECT 1 AS ready')
                if ENGINE=='mariadb':execute(conn,'SET GLOBAL max_statement_time=5')
            return
        except MysqlError:time.sleep(0.5)
    raise MysqlError('MySQL no respondió con su autenticación local. Revisá el servicio.')
def _install(selection):
    module=__import__('types').SimpleNamespace(**globals())
    row=versions.select('mysql',module,selection,check_available=True)
    # Resolve conflicts before masking a service or writing configuration.
    check,_=versions.commands('mysql',module,row);result=run(check,timeout=900,check=False)
    if result.returncode:raise MysqlError('No se pudieron resolver las dependencias SQL: '+(result.stderr or result.stdout)[-1200:])
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(BASE,0o700)
    config=load();config['backend']=ENGINE;save(config)
    run(['systemctl','mask',SERVICE])
    try:return _install_masked(selection)
    finally:run(['systemctl','unmask',SERVICE],check=False)

def _install_masked(selection):
    if (LAYOUT or linux.database_layout(distribution()))['oracle']:run(['debconf-set-selections'],input='mysql-community-server mysql-community-server/root-pass password\nmysql-community-server mysql-community-server/re-root-pass password\n')
    # Package initialization remains private even before custom TLS is configured.
    CNF.parent.mkdir(parents=True,exist_ok=True)
    atomic(CNF,('[mysqld]\nbind-address=127.0.0.1\n'+('mysqlx=0\n' if ENGINE=='mysql' else '')).encode(),0o644)
    layout=LAYOUT or linux.database_layout(distribution())
    linux.install_packages(run,distribution(),layout['packages'][1:])
    versions.install_selected('mysql',__import__('types').SimpleNamespace(**globals()),selection)
    initialize_database()
    Path('/var/lib/mysql-files').mkdir(exist_ok=True,mode=0o750)
    import pwd
    mysql=pwd.getpwnam('mysql');tls=TLS;tls.mkdir(parents=True,exist_ok=True,mode=0o750);os.chown(tls,0,mysql.pw_gid);os.chmod(tls,0o750)
    valid_cert=(tls/'server.crt').exists() and run(['openssl','x509','-in',str(tls/'server.crt'),'-noout','-checkend','0'],check=False).returncode==0
    if not (tls/'server.key').exists() or not valid_cert:
        ip=network()
        run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365','-subj','/CN='+ip,'-addext','subjectAltName=IP:'+ip+',DNS:localhost,IP:127.0.0.1','-keyout',str(tls/'server.key'),'-out',str(tls/'server.crt')],timeout=45)
    os.chown(tls/'server.key',0,mysql.pw_gid);os.chmod(tls/'server.key',0o640);os.chmod(tls/'server.crt',0o644)
    text=server_config()
    bootstrap=Path('/var/lib/mysql/.storypulse-bootstrap.sql')
    if bootstrap.exists():text+='init_file='+str(bootstrap)+'\n'
    atomic(CNF,text.encode(),0o644)
    linux.database_selinux(run,CNF,TLS)
    run(['systemctl' ,'unmask',SERVICE]);run(['systemctl','enable','--now',SERVICE]);wait_ready()
    if bootstrap.exists():bootstrap.unlink();atomic(CNF,server_config().encode(),0o644)
    config=load();config['installed']=True;config['backend']=ENGINE;save(config)
    return dict(ok=True,action='install')
def removal(payload,applying=False,repair_monitor=None):
    import storypulse_uninstall as remover
    from types import SimpleNamespace
    try:
        apps=dependent_applications()
        if apps:raise MysqlError('Primero eliminá '+', '.join(apps)+': utilizan esta base de datos. Sus datos y servicios se conservaron.')
        module=SimpleNamespace(**globals())
        return remover.apply('mysql',module,payload,repair_monitor) if applying else remover.plan('mysql',module,payload)
    except remover.RemovalError as exc:raise MysqlError(str(exc)) from exc

def install(selection):
    import storypulse_uninstall as remover
    try:
        with remover.package_lock():return _install(selection)
    except remover.RemovalError as exc:raise MysqlError(str(exc)) from exc

def grants(conn,db,user,host,perms):
    # partial_revokes=ON makes database identifiers literal, including underscores.
    scope=ident(db) if ENGINE=='mysql' else BT+dbname(db).replace('_',r'\_')+BT
    execute(conn,'GRANT '+','.join(perms)+' ON '+scope+'.* TO %s@%s',(user,host))
def kill_sessions(conn,user):
    sessions=query(conn,'SELECT ID FROM information_schema.PROCESSLIST WHERE USER=%s',(user,))
    for session in sessions:
        try:execute(conn,'KILL CONNECTION '+str(int(session['ID'])))
        except driver().MySQLError as exc:
            if not exc.args or exc.args[0]!=1094:raise
def user_accounts(conn,name):
    if ENGINE=='mysql':return query(conn,'SELECT Host,plugin,authentication_string,User_attributes AS attributes FROM mysql.user WHERE User=%s',(name,))
    rows=query(conn,'SELECT Host,plugin,authentication_string FROM mysql.user WHERE User=%s',(name,))
    bindings=ownership()
    for row in rows:
        key=name+'@'+row['Host'];saved=bindings.get(key,{})
        signature=hashlib.sha256((row['plugin']+':'+row['authentication_string']).encode()).hexdigest()
        row['attributes']={'storypulse':1,'database':saved.get('database')} if saved.get('signature')==signature else {}
    return rows

def ownership():
    path=BASE/'ownership.json'
    if path.is_symlink():raise OwnershipError('Archivo de propiedad MySQL inseguro.')
    if not path.exists():return {}
    if path.stat().st_size>1024*1024:raise OwnershipError('Archivo de propiedad MySQL demasiado grande.')
    value=json.loads(path.read_text())
    if not isinstance(value,dict) or len(value)>1024:raise OwnershipError('Archivo de propiedad MySQL inválido.')
    return value

def bind_account(conn,name,host,db):
    if ENGINE!='mariadb':return
    row=query(conn,'SELECT plugin,authentication_string FROM mysql.user WHERE User=%s AND Host=%s',(name,host))
    if len(row)!=1:raise OwnershipError('No se pudo identificar la cuenta creada.')
    signature=hashlib.sha256((row[0]['plugin']+':'+row[0]['authentication_string']).encode()).hexdigest()
    value=ownership();value[name+'@'+host]={'database':db,'signature':signature}
    atomic(BASE/'ownership.json',(canonical(value)+'\n').encode())
def account_owned(account,db):
    attrs=account.get('attributes') or '{}'
    if isinstance(attrs,str):attrs=json.loads(attrs)
    attrs=attrs.get('metadata',attrs)
    return attrs.get('storypulse')==1 and attrs.get('database')==db
def user_update(conn,payload,config):
    action=payload['action'];name=username(payload['username']);old=next((u for u in config['users'] if u['username']==name),None)
    previous=user_accounts(conn,name)
    if action=='create-user' and previous:raise OwnershipError('Ese usuario ya existe fuera del panel. Se conserva.')
    if old and any(a['Host'] not in ['localhost',*old['ips']] for a in previous):raise OwnershipError('El usuario tiene cuentas de origen ajenas al panel. Revisalas antes de modificarlo.')
    if old and any(not account_owned(a,old['database']) for a in previous):raise OwnershipError('El usuario tiene accesos ajenos al panel. Se conservan para revisión.')
    for account in previous:execute(conn,'ALTER USER %s@%s ACCOUNT LOCK',(name,account['Host']))
    if action=='delete-user':
        for account in previous:execute(conn,'DROP USER %s@%s',(name,account['Host']))
        if ENGINE=='mariadb':
            saved=ownership();saved={key:value for key,value in saved.items() if not key.startswith(name+'@')}
            atomic(BASE/'ownership.json',(canonical(saved)+'\n').encode())
        kill_sessions(conn,name);config['users']=[u for u in config['users'] if u['username']!=name];return
    item=dict(username=name,database=payload['database'],privileges=privileges(payload['privileges']),ips=ips(payload['ips']),enabled=payload.get('enabled',True))
    secret=payload.get('password')
    marker=canonical({'storypulse':1,'database':item['database']})
    if action=='create-user':
        sql='CREATE USER %s@%s IDENTIFIED BY %s REQUIRE NONE WITH MAX_USER_CONNECTIONS 5 ACCOUNT LOCK'
        execute(conn,sql+(' ATTRIBUTE %s' if ENGINE=='mysql' else ''),(name,'localhost',password(secret),marker) if ENGINE=='mysql' else (name,'localhost',password(secret)))
        bind_account(conn,name,'localhost',item['database'])
    elif secret:
        execute(conn,'ALTER USER %s@%s IDENTIFIED BY %s',(name,'localhost',password(secret)))
        bind_account(conn,name,'localhost',item['database'])
    local=next((a for a in user_accounts(conn,name) if a['Host']=='localhost'),None)
    if not local or local['plugin']!=('caching_sha2_password' if ENGINE=='mysql' else 'mysql_native_password'):raise MysqlError('El usuario no usa la autenticación segura esperada.')
    oldhosts={a['Host'] for a in previous}
    for host in oldhosts-set(['localhost',*item['ips']]):execute(conn,'DROP USER %s@%s',(name,host))
    if ENGINE=='mariadb':
        saved=ownership()
        for host in oldhosts-set(['localhost',*item['ips']]):saved.pop(name+'@'+host,None)
        atomic(BASE/'ownership.json',(canonical(saved)+'\n').encode())
    for host in ['localhost',*item['ips']]:
        if host!='localhost':
            verb='ALTER' if host in oldhosts else 'CREATE'
            if ENGINE=='mysql':execute(conn,verb+' USER %s@%s IDENTIFIED WITH caching_sha2_password AS %s REQUIRE SSL WITH MAX_USER_CONNECTIONS 5 ACCOUNT LOCK ATTRIBUTE %s',(name,host,local['authentication_string'],marker))
            else:
                execute(conn,verb+' USER %s@%s IDENTIFIED BY PASSWORD %s REQUIRE SSL WITH MAX_USER_CONNECTIONS 5 ACCOUNT LOCK',(name,host,local['authentication_string']))
                bind_account(conn,name,host,item['database'])
        execute(conn,'REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s@%s',(name,host))
        grants(conn,item['database'],name,host,item['privileges'])
    for host in ['localhost',*item['ips']]:execute(conn,'ALTER USER %s@%s ACCOUNT '+('UNLOCK' if item['enabled'] else 'LOCK'),(name,host))
    kill_sessions(conn,name);config['users']=[u for u in config['users'] if u['username']!=name]+[item]
def sync_firewall(config,repair_monitor):
    import fcntl
    with Path('/run/lock/storypulse-securityctl.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);mod=ports_module();snapshot=mod.read_snapshot()
        desired={ip for u in config['users'] if u['enabled'] for ip in u['ips']} if config['remote'] else set()
        owned=[r for r in snapshot['rules'] if r['comment']=='StoryPulse MySQL' and r['spans']==[(3306,3306)] and r['protocol']=='tcp' and r['direction']=='IN' and r['family']==4 and r['action']=='ALLOW' and not r['interface']]
        keep=set();remove=[]
        for row in owned:
            if row['source'] in desired and row['source'] not in keep:keep.add(row['source'])
            else:remove.append(row)
        for row in sorted(remove,key=lambda r:r['number'],reverse=True):run(['ufw','--force','delete',str(row['number'])])
        for ip in sorted(desired-keep):run(['ufw','allow','in','proto','tcp','from',ip,'to','any','port','3306','comment','StoryPulse MySQL'])
        if remove or desired-keep:repair_monitor(4)
def backup_structure(conn,db,table):
    """Bounded metadata backup before DDL; data is never silently restored."""
    rows=query(conn,'SHOW CREATE TABLE '+ident(db)+'.'+ident(table))
    directory=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
    directory.mkdir(parents=True,mode=0o700);os.chmod(BACKUPS,0o700)
    atomic(directory/'structure.json',(canonical(rows)+'\n').encode())
    return str(directory)
def change(payload,repair_monitor):
    if payload.get('action')=='uninstall':return removal(payload,True,repair_monitor)
    if payload.get('confirm') is not True:raise MysqlError('Falta confirmar la operación.')
    proposal=plan(payload);config=load();action=payload['action']
    if payload.get('revision')!=proposal['revision']:raise MysqlError('La configuración cambió. Revisá otra vez la vista previa.')
    if action=='create-user' or action=='update-user' and payload.get('password'):password(payload.get('password'))
    if action=='upgrade':return versions.upgrade('mysql',__import__('types').SimpleNamespace(**globals()),payload)
    if action=='install':return install(payload['selection'])
    if action in ('start','stop','restart'):
        run(['systemctl',action,SERVICE])
        if action!='stop':wait_ready()
        return dict(ok=True,action=action)
    # Save metadata before changing grants/network; no passwords in snapshots.
    previous=json.loads(canonical(config))
    if action=='network':
        config['remote']=payload['enabled']
        old=CNF.read_bytes()
        try:
            # Close first when disabling; open firewall only after the TLS listener is ready.
            if not config['remote']:sync_firewall(config,repair_monitor)
            atomic(CNF,server_config(config['remote']).encode(),0o644)
            if linux.selinux_active(run):run(['restorecon',str(CNF)])
            run(['systemctl','restart',SERVICE]);wait_ready()
            if config['remote']:sync_firewall(config,repair_monitor)
            save(config)
        except (RuntimeError,OSError,subprocess.TimeoutExpired):
            atomic(CNF,old,0o644)
            if linux.selinux_active(run):run(['restorecon',str(CNF)])
            run(['systemctl','restart',SERVICE],check=False);sync_firewall(previous,repair_monitor)
            raise MysqlError('No se completó el cambio de red. Se intentó recuperar la configuración anterior; revisá el estado.')
        return dict(ok=True,action=action)
    with connect(read_timeout=120) as conn:
        if ENGINE=='mysql' and not query(conn,'SELECT @@partial_revokes AS enabled')[0]['enabled']:raise MysqlError('La configuración de permisos literales fue modificada. Revisá MySQL antes de asignar accesos.')
        if action=='create-database':
            name=dbname(payload['database']);execute(conn,'CREATE DATABASE '+ident(name)+' CHARACTER SET utf8mb4 COLLATE '+('utf8mb4_0900_ai_ci' if ENGINE=='mysql' else 'utf8mb4_unicode_ci'))
            if name not in config['databases']:config['databases'].append(name)
        elif action.endswith('-user'):
            directory=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
            directory.mkdir(parents=True,mode=0o700);os.chmod(BACKUPS,0o700);atomic(directory/'state.json',(canonical(config)+'\n').encode())
            try:user_update(conn,payload,config)
            except OwnershipError:raise
            except (driver().MySQLError,MysqlError,OSError):
                # DCL commits implicitly. Fail closed if an interrupted grant update cannot finish.
                name=payload['username']
                owned=[]
                for account in user_accounts(conn,name):
                    if account_owned(account,payload.get('database')):
                        execute(conn,'ALTER USER %s@%s ACCOUNT LOCK',(name,account['Host']));owned.append(account)
                if action=='create-user' and owned:
                    config['users'].append(dict(username=name,database=payload['database'],privileges=privileges(payload['privileges']),ips=ips(payload['ips']),enabled=False))
                for item in config['users']:
                    if item['username']==name:item['enabled']=False
                kill_sessions(conn,name)
                save(config)
                raise MysqlError('No se completó el cambio de usuario. Sus accesos quedaron bloqueados; revisá y volvé a aplicar sus permisos.') from None
        else:
            db=payload['database'];require_database(config,db);execute(conn,'USE '+ident(db))
            if action in ('modify-column','drop-column','drop-table','rename-column','rename-table','drop-index','drop-relation'):backup_structure(conn,db,payload['table'])
            ddl(conn,payload)
        conn.commit()
    save(config)
    if action.endswith('-user') and config['remote']:sync_firewall(config,repair_monitor)
    return dict(ok=True,action=action)
def metadata(conn,db,table):
    ident(table)
    columns=query(conn,'SELECT COLUMN_NAME AS name,DATA_TYPE AS type,COLUMN_TYPE AS definition,IS_NULLABLE AS nullable,COLUMN_KEY AS column_key,EXTRA AS extra,COLUMN_DEFAULT AS default_value FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION',(db,table))
    if not columns:raise MysqlError('La tabla no existe o no tenés acceso.')
    if len(columns)>64:raise MysqlError('Esta tabla supera los 64 campos admitidos por la grilla.')
    for c in columns:ident(c['name']);c['editable']=c['type'] not in ('binary','varbinary','blob','tinyblob','mediumblob','longblob','geometry','point') and 'GENERATED' not in c['extra']
    indexes=query(conn,'SELECT INDEX_NAME AS name,COLUMN_NAME AS column_name,NON_UNIQUE AS non_unique,SEQ_IN_INDEX AS position FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY INDEX_NAME,SEQ_IN_INDEX',(db,table))
    keys=[r['column_name'] for r in indexes if r['name']=='PRIMARY']
    if not keys:
        for name in dict.fromkeys(r['name'] for r in indexes if not r['non_unique']):
            selected=[r['column_name'] for r in indexes if r['name']==name]
            if all(next(c for c in columns if c['name']==k)['nullable']=='NO' for k in selected):keys=selected;break
    relations=query(conn,'SELECT CONSTRAINT_NAME AS name,COLUMN_NAME AS column_name,REFERENCED_TABLE_NAME AS target_table,REFERENCED_COLUMN_NAME AS target_column FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND REFERENCED_TABLE_NAME IS NOT NULL',(db,table))
    return dict(columns=columns,keys=keys,indexes=indexes,relations=relations)
def row_expression(columns):
    values=[]
    for c in columns:
        name=ident(c['name']);values.append(('HEX('+name+')') if c['type'] in ('binary','varbinary','blob','tinyblob','mediumblob','longblob','geometry','point') else 'CAST('+name+' AS CHAR)')
    return 'SHA2(CAST(JSON_ARRAY('+','.join(values)+') AS CHAR),256)'
def safe_values(values,columns,*,insert=False):
    if not isinstance(values,dict) or (not values and not insert) or len(values)>64:raise MysqlError('Indicá los campos y valores a guardar.')
    allowed={c['name'] for c in columns if c['editable'] and (insert or c['column_key']!='PRI')}
    if set(values)-allowed:raise MysqlError('Hay campos no editables en la operación.')
    return {k:scalar(v) for k,v in values.items()}
def data(payload):
    config=load();db=payload.get('database');require_database(config,db);name=username(payload.get('username'))
    account=next((u for u in config['users'] if u['username']==name and u['database']==db and u['enabled']),None)
    if not account:raise MysqlError('Usuario no habilitado para esa base.')
    secret=password(payload.get('password'));action=payload.get('operation')
    if action not in ('login','tables','table','rows','insert','update','delete'):raise MysqlError('Operación de datos no permitida.')
    with connect(name,secret,db) as conn:
        grantee="'"+name+"'@'localhost'"
        if ENGINE=='mariadb':effective=query(conn,'SELECT PRIVILEGE_TYPE AS privilege_type FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA IN (%s,%s) AND GRANTEE=%s',(db,db.replace('_',r'\_'),grantee))
        else:effective=query(conn,'SELECT PRIVILEGE_TYPE AS privilege_type FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA=%s AND GRANTEE=%s',(db,grantee))
        allowed=[p for p in PRIVILEGES if any(r['privilege_type']==p for r in effective)]
        if action in ('login','tables'):
            tables=query(conn,'SELECT TABLE_NAME AS name,TABLE_TYPE AS type,TABLE_ROWS AS estimated_rows FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s ORDER BY TABLE_NAME LIMIT 200',(db,))
            return dict(ok=True,tables=tables,username=name,database=db,privileges=allowed)
        table=payload.get('table');meta=metadata(conn,db,table);columns=meta['columns']
        if action=='table':return dict(ok=True,**meta,privileges=allowed)
        if action=='rows':
            limit=payload.get('limit',25);offset=payload.get('offset',0)
            if type(limit) is not int or not 1<=limit<=50 or type(offset) is not int or not 0<=offset<=1000000:raise MysqlError('Paginación inválida.')
            sort=payload.get('sort') or (meta['keys'][0] if meta['keys'] else columns[0]['name'])
            if sort not in {c['name'] for c in columns}:raise MysqlError('Orden inválido.')
            descending=boolean(payload.get('descending',False));search=payload.get('search','')
            if not isinstance(search,str) or len(search)>100:raise MysqlError('Búsqueda inválida.')
            fields=[];truncations=[]
            for c in columns:
                column=ident(c['name']);binary=c['type'] in ('binary','varbinary','blob','tinyblob','mediumblob','longblob','geometry','point');expr='HEX('+column+')' if binary else 'CAST('+column+' AS CHAR)'
                fields.append('LEFT('+expr+',2048) AS '+column);truncations.append('IF(CHAR_LENGTH('+expr+')>2048,1,0)')
            selection=','.join(fields)+','+row_expression(columns)+' AS '+BT+'__sp_revision'+BT+',JSON_ARRAY('+','.join(truncations)+') AS '+BT+'__sp_truncated'+BT
            args=[];where=''
            if search:
                # Literal substring, not a user-supplied LIKE pattern.
                escaped=search.replace('!','!!').replace('%','!%').replace('_','!_')
                if not any(c['editable'] for c in columns):raise MysqlError('Esta tabla no tiene campos de texto consultables.')
                where=' WHERE '+' OR '.join('CAST('+ident(c['name'])+" AS CHAR) LIKE %s ESCAPE '!'" for c in columns if c['editable']);args=['%'+escaped+'%']*sum(c['editable'] for c in columns)
            order=[sort,*[k for k in meta['keys'] if k!=sort]]
            rows=query(conn,'SELECT /*+ MAX_EXECUTION_TIME(3000) */ '+selection+' FROM '+ident(table)+where+' ORDER BY '+','.join(ident(k)+(' DESC' if descending else ' ASC') for k in order)+' LIMIT %s OFFSET %s',(*args,limit+1,offset))
            more=len(rows)>limit;result=[]
            for row in rows[:limit]:
                trunc=row.pop('__sp_truncated');trunc=json.loads(trunc) if isinstance(trunc,str) else trunc
                rowrev=row.pop('__sp_revision');key={k:row[k] for k in meta['keys']}
                result.append(dict(values=row,key=key,revision=rowrev,truncated=[c['name'] for c,t in zip(columns,trunc) if t]))
            return dict(ok=True,rows=result,more=more,offset=offset,limit=limit,**meta,privileges=allowed)
        if payload.get('confirm') is not True:raise MysqlError('Falta confirmar la modificación de datos.')
        if action=='insert':
            values=safe_values(payload.get('values'),columns,insert=True)
            execute(conn,'INSERT INTO '+ident(table)+' ('+','.join(ident(c) for c in values)+') VALUES ('+','.join(['%s']*len(values))+')',tuple(values.values()))
        else:
            keys=payload.get('key')
            if not meta['keys'] or not isinstance(keys,dict) or set(keys)!=set(meta['keys']):raise MysqlError('La tabla necesita una clave única para modificar una fila con seguridad.')
            where=' AND '.join(ident(k)+' <=> %s' for k in meta['keys']);args=tuple(scalar(keys[k]) for k in meta['keys'])
            current=query(conn,'SELECT '+row_expression(columns)+' AS revision FROM '+ident(table)+' WHERE '+where+' FOR UPDATE',args)
            if len(current)!=1 or current[0]['revision']!=payload.get('row_revision'):raise MysqlError('El registro cambió o ya no existe. Recargá antes de guardar.')
            if action=='delete':execute(conn,'DELETE FROM '+ident(table)+' WHERE '+where,args)
            else:
                values=safe_values(payload.get('values'),columns)
                if set(values)&set(meta['keys']):raise MysqlError('La clave que identifica la fila no se modifica desde la grilla.')
                execute(conn,'UPDATE '+ident(table)+' SET '+','.join(ident(k)+'=%s' for k in values)+' WHERE '+where,(*values.values(),*args))
        conn.commit();return dict(ok=True,operation=action)
def dependent_applications():
    import storypulse_catalog as catalog
    web=catalog.webapps
    return [label for kind,(label,_) in web.APPS.items() if web.own(catalog,kind) and web.app_site(distribution(),kind).is_dir()]

def status():
    config=load();fingerprint='';certificate=''
    cert=TLS/'server.crt'
    if cert.exists():
        check=run(['openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256'],check=False)
        if check.returncode==0:certificate=cert.read_text();fingerprint=check.stdout.strip().partition('=')[2]
    return dict(ok=True,installed_version=versions.installed('mysql',__import__('types').SimpleNamespace(**globals())),backend=ENGINE,distribution=(PROFILE or {}).get('id','debian'),installed=config['installed'],managed=STATE.exists(),state=active(),revision=revision(config),remote=config['remote'],
        host=network(),port=3306,databases=config['databases'],users=config['users'],types=list(TYPES),privilege_options=list(PRIVILEGES),certificate=certificate,certificate_sha256=fingerprint,used_by=dependent_applications())

def structure(payload):
    config=load();db=payload.get('database');require_database(config,db)
    with connect() as conn:
        tables=query(conn,'SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_TYPE=%s ORDER BY TABLE_NAME LIMIT 200',(db,'BASE TABLE'))
        meta=metadata(conn,db,payload['table']) if payload.get('table') else {}
        return dict(ok=True,tables=tables,**meta)
