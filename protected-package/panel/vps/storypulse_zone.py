"""Server Security Monitor v3.0 - fixed, verified SA-MP Zone deployment."""
import ipaddress,base64,contextlib,hashlib,io,json,os,pwd,re,secrets,shutil,stat,subprocess,tarfile,tempfile,time,urllib.request,urllib.parse,zipfile
from pathlib import Path,PurePosixPath
import storypulse_games as game
import storypulse_catalog as catalog
import storypulse_webapps as web
import storypulse_mysql as mysql
import storypulse_uninstall as removal
import storypulse_platform as linux

CONFIG=Path('/etc/server-monitor-zone')
STATE=Path('/var/lib/storypulse-security/games/zone.json')
MARKER=Path('/var/lib/storypulse-security/games/zone-web.json')
SITE=Path('/var/www/server-monitor-zone')
CACHE=Path('/var/cache/server-monitor-zone')
SOCKET='/run/server-monitor-zone/php.sock'
WEB_UNIT='server-monitor-zone-php.service'
PLUGINS=['crashdetect.so','mysql.so','sscanf.so','streamer.so','pawncmd.so','pawnraknet.so']
ASSETS={
 'smf':('https://codeload.github.com/SimpleMachines/SMF/zip/refs/tags/v2.1.8','5693fd769fac1ec294d68e082d3b622930b552ee4abfe56acd0f4a61378cd118',16*1024**2),
 'gm':('https://drive.usercontent.google.com/download?id=1F18Qv2d00xZgYFx8upI5eE2w23MwLD0s&export=download&confirm=t','5a6c51aef27419e35f9d6eb930429485d7bcb2009027b691abb6b586c1432eb2',64*1024**2),
 'web':('https://drive.usercontent.google.com/download?id=1aDkHjCTLp90SCfWEsYdLv6b3XLCm1pq7&export=download&confirm=t','019eb423818617ddc628507568e41ae22c4e3d3376fc910e6dc4ea68b6709b95',400*1024**2),
 'db':('https://drive.usercontent.google.com/download?id=15b2bXAbi5zR7ZNP1Ozzo9yiTwWub6Fs9&export=download&confirm=t','915799117ea253474cfa7aead60a12eba967c5fae6ffee701de11d43aa309367',4*1024**2),
 'compiler':('https://github.com/pawn-lang/compiler/releases/download/v3.10.10/pawnc-3.10.10-linux.tar.gz','9bbb1df6e933318fce1fa61951e4196b70613c637a5a1d4c96937e147c18468d',2*1024**2),
 'mysql_library':('https://github.com/pBlueG/SA-MP-MySQL/releases/download/R41-4/mysql-R41-4-Debian-static.tar.gz','2e24aabfb7d674a454961e341a7df219f65069d273c44d4323e5199a59f135be',4*1024**2),
}
HOSTS={'codeload.github.com','drive.usercontent.google.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}
class ZoneError(RuntimeError):pass

def valid_url(url):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='https' or p.hostname not in HOSTS or p.username or p.password or p.port not in (None,443):raise ZoneError('La descarga salió del alojamiento permitido.')
 return url
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  valid_url(newurl);return super().redirect_request(req,fp,code,msg,headers,newurl)

def artifact(kind):
 url,digest,limit=ASSETS[kind];game.private_dir(CACHE);path=CACHE/(kind+'.archive')
 if path.exists() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==digest:return path
 fd,tmp=tempfile.mkstemp(dir=CACHE)
 try:
  size=0;h=hashlib.sha256()
  with os.fdopen(fd,'wb') as out,urllib.request.build_opener(Redirect()).open(valid_url(url),timeout=60) as response:
   valid_url(response.url)
   while True:
    chunk=response.read(1024*1024)
    if not chunk:break
    size+=len(chunk)
    if size>limit:raise ZoneError('El paquete '+kind+' supera el límite permitido.')
    h.update(chunk);out.write(chunk)
  if h.hexdigest()!=digest:raise ZoneError('El paquete '+kind+' cambió o Drive no entregó el archivo. No se instalará.')
  os.chmod(tmp,0o600);os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
 return path

def unpack(archive,target):
 with zipfile.ZipFile(archive) as source:
  if sum(x.file_size for x in source.infolist())>1024**3 or len(source.infolist())>10000:raise ZoneError('ZIP demasiado grande.')
  seen=set()
  for item in source.infolist():
   name=PurePosixPath(item.filename)
   if name.is_absolute() or '..' in name.parts or '\\' in item.filename or ':' in item.filename or stat.S_ISLNK(item.external_attr>>16):raise ZoneError('Ruta ZIP no permitida.')
   if name.as_posix() in seen:raise ZoneError('Ruta ZIP repetida.')
   seen.add(name.as_posix())
   dest=target.joinpath(*name.parts)
   if item.is_dir():dest.mkdir(parents=True,exist_ok=True,mode=0o755)
   else:
    dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    with source.open(item) as inp,dest.open('xb') as out:shutil.copyfileobj(inp,out)
    dest.chmod(0o644)

def website_domain(value):
 if not isinstance(value,str) or len(value)>253:raise ZoneError('Indicá el dominio web sin protocolo, puerto ni rutas.')
 host=value.lower();labels=host.split('.')
 if len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels) or not (re.fullmatch(r'[a-z]{2,63}',labels[-1]) or labels[-1].startswith('xn--')):raise ZoneError('Indicá un dominio válido, por ejemplo rol.ejemplo.com; no una dirección IP.')
 return host

def payload(body,apply=False):
 required={'web_domain','name','port','maxplayers','database','db_user','db_password','rcon_password','ftp_user'}
 if not isinstance(body,dict) or set(body)!=required|({'confirm','revision','ftp_secret'} if apply else set()):raise ZoneError('Parámetros de Zone no permitidos.')
 value={k:body[k] for k in required}
 value['web_domain']=website_domain(value['web_domain'])
 if not isinstance(value['name'],str) or not re.fullmatch('[A-Za-z]{1,24}',value['name']) or value['name'].lower().endswith('zone'):raise ZoneError('Escribí una palabra de hasta 24 letras, sin espacios ni Zone; Zone se agrega automáticamente.')
 for key,lo,hi in [('port',1024,65535),('maxplayers',1,500)]:
  if type(value[key]) is not int or not lo<=value[key]<=hi:raise ZoneError('Puerto o jugadores fuera de rango.')
 mysql.dbname(value['database']);mysql.username(value['db_user'])
 for key in ('db_password','rcon_password'):
  if not isinstance(value[key],str) or not re.fullmatch(r'[A-Za-z0-9_!@%+=.,:-]{16,64}',value[key]):raise ZoneError('Las contraseñas MySQL y RCON deben tener entre 16 y 64 caracteres: letras, números o _!@%+=.,:-')
 if value['db_password']==value['rcon_password']:raise ZoneError('Usá contraseñas distintas para MySQL y RCON.')
 game.game_ftp.options({'enabled':True,'username':value['ftp_user']})
 if apply and (body['confirm'] is not True or not isinstance(body['revision'],str) or not re.fullmatch('[a-f0-9]{64}',body['revision'])):raise ZoneError('Revisá y confirmá la instalación.')
 return value

def settings(value):return dict(game.DEFAULT,hostname=value['name']+' Zone Roleplay',port=value['port'],maxplayers=value['maxplayers'],gamemode='FZRP',plugins=PLUGINS)
def status(body):
 if body!={}:raise ZoneError('La consulta no acepta parámetros.')
 row=game.status({});p=linux.detect()
 return dict(ok=True,maintenance_revision=maintenance_revision(),forum_installed=(SITE/'foro/Settings.php').is_file(),installed=row['installed'],edition=(game.checked_record() or {}).get('edition',''),conflict=row['conflict'],compatible=p['id']=='debian' and p['version'].split('.')[0] in ('12','13') and row['compatible'],distribution=row['distribution'],architecture=row['architecture'],notice='La instalación Zone se habilita inicialmente para Debian 12/13 x86.',details=(game.read_json(STATE) or {}).get('public',{}))

def plan(body):
 value=payload(body);row=status({});p=linux.detect()
 if not row['compatible']:raise ZoneError(row['notice'])
 if row['installed'] or row['conflict']:raise ZoneError('Ya existe SA-MP. Eliminá su instalación desde Eliminar juegos antes de instalar Zone.')
 old=game.read_json(STATE)
 if SITE.exists() or old and old.get('db_created') or MARKER.exists() or CONFIG.exists():raise ZoneError('Hay una instalación Zone previa; se conserva y no se sobrescribe.')
 if shutil.disk_usage('/var').free<2*1024**3:raise ZoneError('Se requieren al menos 2 GB libres para preparar los paquetes.')
 game.port_check(value['port'],None,{})
 game.game_ftp.preflight(value['ftp_user'])
 if web.own(catalog,'wordpress'):raise ZoneError('La raíz de esta IP ya pertenece a WordPress. Se conserva el sitio existente.')
 web.front(catalog,p,catalog.package_inventory(p))
 from storypulse_wordpress_db import database_dependencies
 database_dependencies(catalog,p)
 mysql.configure_platform(p)
 if mysql.load()['installed']:
  with mysql.connect() as conn:
   if mysql.query(conn,'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=%s',(value['database'],)) or mysql.query(conn,'SELECT User FROM mysql.user WHERE User=%s',(value['db_user'],)):raise ZoneError('La base o el usuario MySQL ya existe. Elegí nombres nuevos.')
 public={k:v for k,v in value.items() if k not in ('db_password','rcon_password')}
 identity={'request':value,'distribution':row['distribution'],'assets':{k:v[1] for k,v in ASSETS.items()},'ports':game.ports.read_snapshot()['revision'],'ftp':game.game_ftp.ftp.revision(game.game_ftp.ftp.load())}
 return dict(ok=True,revision=catalog.digest(identity),settings=settings(value),directory=str(game.BASE),web_directory=str(SITE),distribution=row['distribution'],request=public,
  packages=game.runtime_packages(p)+['nginx','php-fpm','php-mysql','php-gd','php-mbstring','php-xml','php-curl','php-zip','php-intl','phpmyadmin','MySQL/MariaDB','FTPS'],
  warning='Se instalarán GM, web, base local, phpMyAdmin en /phpmyadmin/ y FTP aislado. Se habilitan HTTP y el puerto UDP elegido. No se habilita MySQL remoto. El correo queda desactivado.')

def normalize_includes(game_root):
 inc=game_root/'pawno/include';lookup={p.relative_to(inc).as_posix().lower():p.relative_to(inc).as_posix() for p in inc.rglob('*.inc')}
 for path in [*inc.rglob('*.inc'),game_root/'gamemodes/FZRP.pwn']:
  text=path.read_bytes().decode('latin1')
  def replace(m):
   key=m[2].replace('\\','/');key=key if key.lower().endswith('.inc') else key+'.inc';found=lookup.get(key.lower())
   return m[1]+(found if m[2].lower().endswith('.inc') else found[:-4] if found else m[2])+m[3] if found else m[0]
  path.write_bytes(re.sub(r'(?m)(^\s*#(?:try)?include\s*[<"])([^>"\r\n]+)([>"])',replace,text).encode('latin1'))

def define(text,key,value):
 pattern=r'(?m)^(\s*#define\s+'+re.escape(key)+r'\s+)[^\r\n]*'
 text,count=re.subn(pattern,lambda m:m[1]+'"'+value+'"',text)
 if count!=1:raise ZoneError('No se encontró una definición única de '+key+'.')
 return text

def rebrand_gm(text, prefix, server_ip, web_domain=None):
    if not isinstance(prefix, str) or not re.fullmatch(r'[A-Za-z]{1,24}', prefix) or prefix.lower().endswith('zone'):
        raise ValueError('Invalid Zone prefix')
    address = ipaddress.ip_address(server_ip)
    host = website_domain(web_domain) if web_domain is not None else '[' + str(address) + ']' if address.version == 6 else str(address)
    brand = prefix + ' Zone'
    # Tokenizing comments before strings prevents quotes inside comments from
    # accidentally changing the lexer state. Escapes and source bytes survive.
    tokens = re.compile(r'''//[^\r\n]*|/\*[\s\S]*?\*/|'(?:\\[^\r\n]|[^'\\\r\n])*'|"(?:\\[^\r\n]|[^"\\\r\n])*"''')
    domain = re.compile(r'(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]+\.)*fenixzone\.com(?![A-Za-z0-9_.-])', re.I)
    def replace(token):
        literal = token[0]
        if not literal.startswith('"'):
            return literal
        literal = domain.sub(lambda match: host, literal)
        return re.sub('fenixzone', lambda match: brand.upper() if match[0].isupper() else brand, literal, flags=re.I)
    return tokens.sub(replace, text)


REGISTRATION_MARKER = "// Server Monitor Zone: serialized registration v1"


def _function_span(text, name):
    match = re.search(r"(?m)^[ \t]*public " + re.escape(name) + r"\([^\n]*\)\s*\{", text)
    if not match:
        raise ValueError("No se encontro la funcion esperada: " + name)
    start = text.index("{", match.start())
    depth, quote, comment, index = 0, None, None, start
    while index < len(text):
        char = text[index]
        pair = text[index:index + 2]
        if comment == "line":
            if char == "\n":
                comment = None
        elif comment == "block":
            if pair == "*/":
                comment = None
                index += 1
        elif quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = None
        elif pair == "//":
            comment = "line"
            index += 1
        elif pair == "/*":
            comment = "block"
            index += 1
        elif char in ('"', "'"):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return match.start(), index + 1
        index += 1
    raise ValueError("Funcion incompleta: " + name)


def _replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("La GM no coincide con la version de registro verificada.")
    return text.replace(old, new, 1)


REGISTER = r'''public OnPlayerRegister(playerid, smSession)
{
    if(!IsPlayerConnected(playerid) || smSession != SmZoneRegistrationSession[playerid] || !SmZoneRegistrationPending[playerid]) return 1;
    if(!cache_is_any_active()) return SmZoneRegistrationFailed(playerid);
    if(cache_num_rows() != 0)
    {
        SmZoneRegistrationPending[playerid] = false;
        ShowPlayerDialog(playerid, LOGIN, DIALOG_STYLE_PASSWORD, "Esta cuenta ya existe", "Ingresa la contrasena de esta cuenta:", "Enviar", "Salir");
        return 1;
    }
    new Query[1400], day, month, year, Pais[30], FechaRegistro[30];
    getdate(year, month, day);
    GetPlayerCountry(playerid, Pais, sizeof(Pais));
    format(PlayerInfo[playerid][pPaisRegistro], 30, "%s", Pais);
    format(FechaRegistro, sizeof(FechaRegistro), "%d/%d/%d", day, month, year);
    mysql_format(handle_db, Query, sizeof(Query), "INSERT INTO `usuarios` (Username,Password,posX,posY,posZ,posA,Vida,Registro,Email,EMS,Edad,Pais_Registro,Registro_U,username_low,Skin,Sexo,IP) VALUES ('%e','%e','1714.7008','-1898.6792','13.5666','0.0000','100','%02d/%02d/%02d','%e',1,%d,'%e','%e','ninguno','%d','%d','%e')", PlayerInfo[playerid][Nickname],PlayerInfo[playerid][pPassword],day,month,year,PlayerInfo[playerid][pEmail],PlayerInfo[playerid][jEdad],PlayerInfo[playerid][pPaisRegistro],FechaRegistro,PlayerInfo[playerid][jRopa],PlayerInfo[playerid][jSexo],PlayerIP(playerid));
    mysql_tquery(handle_db, Query, "UsuarioRegistrado", "dd", playerid, smSession);
    return 1;
}'''

REGISTERED = r'''public UsuarioRegistrado(playerid, smSession)
{
    if(!IsPlayerConnected(playerid) || smSession != SmZoneRegistrationSession[playerid] || !SmZoneRegistrationPending[playerid]) return 1;
    if(!cache_is_any_active() || cache_affected_rows() != 1 || cache_insert_id() <= 0) return SmZoneRegistrationFailed(playerid);
    PlayerInfo[playerid][pID] = cache_insert_id();
    new Query[1024], Pais[30];
    GetPlayerCountry(playerid, Pais, sizeof(Pais));
    mysql_format(handle_db, Query, sizeof(Query), "INSERT INTO `achievements` (Nombre_Jugador,Tipo,Completado,Titulo,Descripcion,Valor,Progreso) VALUES ('%e','1','1','Nivel','Alcanza el nivel %d',0,0)", PlayerInfo[playerid][Nickname], PlayerInfo[playerid][Level]);
    mysql_tquery(handle_db, Query);
    mysql_format(handle_db, Query, sizeof(Query), "INSERT INTO `perfiles` (Nombre,Pais_Actual,Avatar,Color) VALUES ('%e','%e','32','1')", PlayerInfo[playerid][Nickname],Pais);
    mysql_tquery(handle_db, Query);
    Usuarios[Cantidad]++;
    mysql_tquery(handle_db, "UPDATE `registros` SET `Cantidad` = `Cantidad` + 1");
    mysql_format(handle_db, Query, sizeof(Query), "SELECT * FROM `usuarios` WHERE `ID` = %d AND `Username` = '%e' LIMIT 1", PlayerInfo[playerid][pID], PlayerInfo[playerid][Nickname]);
    mysql_tquery(handle_db, Query, "SmZoneRegistrationLoaded", "dd", playerid, smSession);
    return 1;
}

public SmZoneRegistrationLoaded(playerid, smSession)
{
    if(!IsPlayerConnected(playerid) || smSession != SmZoneRegistrationSession[playerid] || !SmZoneRegistrationPending[playerid]) return 1;
    if(!cache_is_any_active() || cache_num_rows() != 1) return SmZoneRegistrationFailed(playerid);
    SmZoneRegistrationPending[playerid] = false;
    return OnPlayerSpawnLoaded(playerid);
}

stock SmZoneRegistrationFailed(playerid)
{
    SmZoneRegistrationPending[playerid] = false;
    if(!IsPlayerConnected(playerid)) return 1;
    SendClientMessage(playerid, COLOR_ORANGE, "No se pudo guardar o cargar la cuenta. Reintenta o avisa al administrador.");
    ShowPlayerDialog(playerid, REGISTRO, DIALOG_STYLE_PASSWORD, "No se pudo completar el registro", "La base de datos no pudo completar el registro. Ingresa nuevamente la contrasena para reintentar.", "Reintentar", "Salir");
    return 1;
}'''


def transform_registration(source, forum_registration_hook=None):
    """Transform only the verified stock registration blocks; fail closed on drift."""
    if forum_registration_hook is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", forum_registration_hook):
        raise ValueError("Nombre de integracion del foro invalido.")
    text = source.replace("\r\n", "\n")
    if REGISTRATION_MARKER in text:
        return text
    if "public OnPlayerRegister(playerid)" not in text or "public UsuarioRegistrado(playerid)" not in text:
        raise ValueError("Version de registro de la GM no reconocida.")
    # Optional SMF forum is not distributed with these three archives. Remove
    # only its exact format+dispatch pairs, never provision fake forum tables.
    pattern = re.compile(r'(?m)^[ \t]*mysql_format\(handle_db, (DB_Query|Query|Querys|query),[^\n]*"PREFIX_DB"[^\n]*\);\n[ \t]*mysql_[tp]query\(handle_db, \1\);[ \t]*\n')
    text, forum_count = pattern.subn("", text)
    if forum_count != 11:
        raise ValueError("Las consultas del foro no coinciden con la GM verificada.")
    registered = REGISTERED
    if forum_registration_hook:
        registered = _replace_once(registered, "    PlayerInfo[playerid][pID] = cache_insert_id();", "    PlayerInfo[playerid][pID] = cache_insert_id();\n    " + forum_registration_hook + "(playerid);")
    for name, replacement in (("OnPlayerRegister", REGISTER), ("UsuarioRegistrado", registered)):
        start, end = _function_span(text, name)
        text = text[:start] + replacement + text[end:]
    text = _replace_once(text, "forward OnPlayerRegister(playerid);", "forward OnPlayerRegister(playerid, smSession);\nforward SmZoneRegistrationLoaded(playerid, smSession);")
    text = _replace_once(text, "forward UsuarioRegistrado(playerid);", REGISTRATION_MARKER + "\nnew SmZoneRegistrationSession[MAX_PLAYERS];\nnew bool:SmZoneRegistrationPending[MAX_PLAYERS];\nforward UsuarioRegistrado(playerid, smSession);")
    text = _replace_once(text, 'mysql_pquery(handle_db, pQuery, "OnPlayerRegister", "d", playerid);', 'if(SmZoneRegistrationPending[playerid]) return 1;\n                SmZoneRegistrationPending[playerid] = true;\n                mysql_tquery(handle_db, pQuery, "OnPlayerRegister", "dd", playerid, SmZoneRegistrationSession[playerid]);')
    for name in ("OnPlayerConnect", "OnPlayerDisconnect"):
        start, _ = _function_span(text, name)
        opening = text.index("{", start) + 1
        text = text[:opening] + "\n    SmZoneRegistrationSession[playerid]++;\n    SmZoneRegistrationPending[playerid] = false;" + text[opening:]
    # Failed asynchronous writes invoke OnQueryError rather than the success
    # callback. Match this module's query to the pending account, not all users.
    error_start, _ = _function_span(text, "OnQueryError")
    opening = text.index("{", error_start) + 1
    failure_handler = r'''
        if(!strcmp(callback, "UsuarioRegistrado") || !strcmp(callback, "OnPlayerRegister") || !strcmp(callback, "SmZoneRegistrationLoaded"))
        {
            for(new smPlayer = 0; smPlayer <= GetPlayerPoolSize(); smPlayer++)
            {
                if(!IsPlayerConnected(smPlayer) || !SmZoneRegistrationPending[smPlayer]) continue;
                new smNeedle[128];
                if(!strcmp(callback, "UsuarioRegistrado")) mysql_format(handle_db, smNeedle, sizeof(smNeedle), "VALUES ('%e',", PlayerInfo[smPlayer][Nickname]);
                else mysql_format(handle_db, smNeedle, sizeof(smNeedle), "`Username` = '%e'", PlayerInfo[smPlayer][Nickname]);
                if(strfind(query, smNeedle) != -1) SmZoneRegistrationFailed(smPlayer);
            }
            printf("[Zone registro] Error MySQL %d en %s. No se completo la cuenta.", errorid, callback);
            return 1;
        }
'''
    text = text[:opening] + failure_handler + text[opening:]
    if re.search(r'mysql_pquery\([^\n]*"(?:OnPlayerRegister|UsuarioRegistrado|SmZoneRegistrationLoaded)"', text):
        raise ValueError("El registro aun contiene consultas paralelas.")
    return text


def detach_unused_forum_ssi(text, relative):
    """Remove only unused SSI bootstraps verified in the pinned Zone web.

    SMF must be loaded by /foro itself. These legacy pages do not consume any
    SSI result or function, yet loading SSI changes their global state/session
    and can abort the whole site when the independent forum has an error.
    """
    expected = {'index.php': 2, 'descargas.php': 1}
    if relative not in expected:
        return text
    if re.search(r'\bssi_[A-Za-z_][A-Za-z0-9_]*\s*\(', text, re.I):
        raise ValueError('La página '+relative+' utiliza funciones SSI nuevas; se conservó para revisar su integración.')
    pattern = re.compile(r'''(?m)^[ \t]*include_once\s*\(\s*(['"])\./foro/SSI\.php\1\s*\)\s*;[ \t]*(?=\r?$)''')
    matches = list(pattern.finditer(text))
    if not matches:
        # An unexpected include/require must not be silently treated as a fixed
        # page. Comments and ordinary /foro links are intentionally preserved.
        if re.search(r'''\b(?:include|require)(?:_once)?\s*(?:\(\s*)?['"][^'"\r\n]*SSI\.php['"]''', text, re.I):
            raise ValueError('Cambió la inclusión SSI de '+relative+'; no se modificó automáticamente.')
        return text
    if len(matches) != expected[relative]:
        raise ValueError('La cantidad de inclusiones SSI de '+relative+' no coincide con el paquete verificado.')
    return pattern.sub('// El foro funciona de forma independiente en /foro/.', text)


ZONE_ADMIN_PDO_FILES = frozenset((
    'admin/assets/config.php',
    'admin/global_assets/config.php',
))
ZONE_ADMIN_MAIN_PDO = '$con = new PDO("mysql:host=$ip_mysql;dbname=$nombre_db", $user_sa, $password_sa);'
ZONE_ADMIN_ACTION_PDO = '$act_con = new PDO("mysql:host=$ip_mysql;dbname=$nombre_act", $user_sa, $password_sa);'
ZONE_ADMIN_REUSED_PDO = '$act_con = ($nombre_act === $nombre_db) ? $con : new PDO("mysql:host=$ip_mysql;dbname=$nombre_act", $user_sa, $password_sa);'


def reuse_zone_pdo(text, relative):
    """Reuse PDO only for the two known duplicate Zone admin configurations.

    Different databases retain an independent connection. Changes to either
    constructor fail closed rather than guessing what a custom file means.
    Text outside the exact statement (including CRLF) remains byte-identical.
    """
    if relative not in ZONE_ADMIN_PDO_FILES:
        return text
    if text.count(ZONE_ADMIN_MAIN_PDO) != 1:
        raise ValueError('La conexión principal del administrador Zone cambió. Se conservó el archivo.')
    old_count = text.count(ZONE_ADMIN_ACTION_PDO)
    new_count = text.count(ZONE_ADMIN_REUSED_PDO)
    if old_count == 0 and new_count == 1:
        return text
    if old_count != 1 or new_count != 0:
        raise ValueError('La conexión de acciones del administrador Zone cambió. Se conservó el archivo.')
    return text.replace(ZONE_ADMIN_ACTION_PDO, ZONE_ADMIN_REUSED_PDO, 1)


ZONE_CONNECTION_LIMIT=16

def configure_connection_budget(value):
 # Four game connections + four PHP workers with up to two legacy handles
 # each + four maintenance slots. This never changes the global DB limit.
 mysql.configure_platform();config=mysql.load()
 mysql.require_database(config,value['database']);name=mysql.username(value['db_user'])
 if not any(row.get('username')==name and row.get('database')==value['database'] for row in config['users']):raise ZoneError('El usuario Zone no pertenece a esta base administrada.')
 with mysql.connect() as conn:
  accounts=[row for row in mysql.user_accounts(conn,name) if row['Host']=='localhost']
  if len(accounts)!=1 or not mysql.account_owned(accounts[0],value['database']):raise ZoneError('La cuenta local Zone tiene cambios ajenos. Se conservó.')
  rows=mysql.query(conn,'SELECT max_user_connections FROM mysql.user WHERE User=%s AND Host=%s',(name,'localhost'))
  if len(rows)!=1:raise ZoneError('No se pudo comprobar el límite del usuario Zone.')
  before=int(rows[0]['max_user_connections'])
  if before!=ZONE_CONNECTION_LIMIT:mysql.execute(conn,'ALTER USER %s@%s WITH MAX_USER_CONNECTIONS 16',(name,'localhost'))
 return {'previous':before,'limit':ZONE_CONNECTION_LIMIT}

ADMIN_ENTRY_PHP = '''<?php
// Server Monitor Zone: route the original empty admin entry to its login.
header('Cache-Control: no-store');
header('Location: ./login.php', true, 302);
exit;
'''


def repair_empty_admin_entry(text, relative):
    """Repair only the exact empty admin/index.php shipped in the pinned web ZIP."""
    if relative == 'admin/index.php' and text == '':
        return ADMIN_ENTRY_PHP
    return text


WEB_REVISION='zone-web-admin-entry-v3'

def repair_web_dependencies(ip):
 owned=game.checked_record()
 if not owned or owned.get('edition')!='zone' or not game.read_json(STATE):raise ZoneError('No se encontró el sitio Zone administrado.')
 changes=[]
 for name in ('index.php','descargas.php','admin/index.php',*sorted(ZONE_ADMIN_PDO_FILES)):
  path=SITE/name;web.removal.safe_path(path);info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ZoneError('La página '+name+' no tiene permisos seguros.')
  before=path.read_bytes()
  try:after=repair_empty_admin_entry(reuse_zone_pdo(detach_unused_forum_ssi(before.decode('latin1'),name),name),name).encode('latin1')
  except ValueError as exc:raise ZoneError(str(exc)) from None
  if after!=before:changes.append((path,before,after,info))
 backup=None;written=[]
 if changes:
  backup=Path('/var/backups/server-monitor-zone-web')/str(time.time_ns());game.private_dir(backup)
  for path,before,after,info in changes:
   saved=backup/path.relative_to(SITE);saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
 try:
  for path,before,after,info in changes:
   fd,temporary=tempfile.mkstemp(prefix='.zone-web-',dir=path.parent)
   try:
    with os.fdopen(fd,'wb') as stream:
     stream.write(after);stream.flush();os.fchmod(stream.fileno(),stat.S_IMODE(info.st_mode));os.fchown(stream.fileno(),info.st_uid,info.st_gid);os.fsync(stream.fileno())
    os.replace(temporary,path);written.append(path)
   finally:
    if os.path.exists(temporary):os.unlink(temporary)
   if game.run(['php','-l',str(path)],check=False).returncode:raise ZoneError('PHP rechazó '+path.name+'. Se restauró el respaldo.')
  configure_connection_budget(game.read_json(STATE)['public'])
  verify_web(ip)
  if (SITE/'foro/Settings.php').is_file():
   req=urllib.request.Request('http://127.0.0.1/foro/',headers={'Host':ip})
   with urllib.request.urlopen(req,timeout=20) as response:body=response.read(2*1024**2)
   if b'SMF was unable to connect' in body or not (b'SMF' in body or b'Simple Machines' in body):raise ZoneError('El foro no superó la comprobación junto con la web principal.')
 except Exception:
  if backup:
   for path in written:shutil.copy2(backup/path.relative_to(SITE),path)
  raise
 return {'ok':True,'updated':[path.relative_to(SITE).as_posix() for path,_,_,_ in changes],'connection_limit':ZONE_CONNECTION_LIMIT}


RUNTIME_REVISION='zone-registration-forum-20261022-v1'

def migrate_game_schema(value):
 mysql.configure_platform()
 mysql.require_database(mysql.load(),value['database'])
 changes=[]
 with mysql.connect(database=value['database'],read_timeout=30) as conn:
  for table in ('usuarios','achievements','perfiles','registros'):
   fields=mysql.query(conn,'SHOW COLUMNS FROM '+mysql.ident(table))
   for field in fields:
    if field['Null']!='NO' or field['Default'] is not None or 'auto_increment' in field['Extra'].lower():continue
    kind=field['Type'].lower().split('(')[0]
    if kind in ('int','tinyint','smallint','mediumint','bigint','float','double','decimal'):
     default='250' if table=='usuarios' and field['Field']=='Skin' else '0'
    elif kind in ('varchar','char','text','mediumtext','longtext','tinytext'):default="''"
    else:raise ZoneError('No se reconoce el valor inicial de '+table+'.'+field['Field']+'.')
    changes.append((table,field['Field'],default))
  # Preserve the original schema before scoped, additive compatibility changes.
  if changes:
   backup=Path('/var/backups/server-monitor-zone-schema');game.private_dir(backup)
   snapshot={table:mysql.query(conn,'SHOW CREATE TABLE '+mysql.ident(table))[0]['Create Table'] for table in ('usuarios','achievements','perfiles','registros')}
   game.write_json(backup/(str(time.time_ns())+'.json'),snapshot)
  for table,column,default in changes:mysql.execute(conn,'ALTER TABLE '+mysql.ident(table)+' ALTER COLUMN '+mysql.ident(column)+' SET DEFAULT '+default)
  for table,column,definition in [('facciones','Color','BIGINT NOT NULL DEFAULT 0'),('facciones','EnUso','TINYINT NOT NULL DEFAULT 0'),('actores_tiendas','EnUso','TINYINT NOT NULL DEFAULT 0')]:
   if not any(field['Field']==column for field in mysql.query(conn,'SHOW COLUMNS FROM '+mysql.ident(table))):
    mysql.execute(conn,'ALTER TABLE '+mysql.ident(table)+' ADD COLUMN '+mysql.ident(column)+' '+definition)
  mysql.execute(conn,'INSERT INTO registros (Cantidad) SELECT (SELECT COUNT(*) FROM usuarios) WHERE NOT EXISTS (SELECT 1 FROM registros)')
  conn.commit()
 return len(changes)

def verify_registration_database(value):
 mysql.configure_platform()
 with mysql.connect(database=value['database']) as conn:
  before=mysql.query(conn,'SELECT @@SESSION.sql_mode AS mode')[0]['mode']
  # Temporary tables exercise the actual strict schema without player records.
  mysql.execute(conn,'CREATE TEMPORARY TABLE sm_zone_registration_probe LIKE usuarios')
  mysql.execute(conn,"INSERT INTO sm_zone_registration_probe (Username,Password,posX,posY,posZ,posA,Vida,Registro,Email,EMS,Edad,Pais_Registro,Registro_U,username_low,Skin,Sexo,IP) VALUES ('Zone_Probe','temporary',1714.7008,-1898.6792,13.5666,0,100,'22/10/2026','probe@example.invalid',1,18,'Unknown','22/10/2026','ninguno',250,1,'127.0.0.1')")
  rows=mysql.query(conn,"SELECT ID,Skin,Sexo FROM sm_zone_registration_probe WHERE Username='Zone_Probe'")
  if len(rows)!=1 or int(rows[0]['ID'])<=0 or int(rows[0]['Skin'])!=250:raise ZoneError('La base no superó la comprobación del registro.')
  if mysql.query(conn,'SELECT @@SESSION.sql_mode AS mode')[0]['mode']!=before:raise ZoneError('El modo estricto cambió durante la comprobación.')
 return True

def maintenance_revision():
 row=game.checked_record();record=game.read_json(STATE)
 if not row or row.get('edition')!='zone' or not record or record.get('phase')!='ready':return None
 paths=[game.BASE/'gamemodes/FZRP.pwn',game.BASE/'gamemodes/FZRP.amx',game.BASE/'server.cfg']
 if any(not p.is_file() or p.is_symlink() for p in paths):raise ZoneError('Faltan archivos seguros de la GM instalada.')
 return catalog.digest({'revision':RUNTIME_REVISION,'web_revision':WEB_REVISION,'state':record,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}})

def repair(body):
 if not isinstance(body,dict) or set(body) not in ({'confirm','revision'},{'confirm','revision','web_domain'}) or body['confirm'] is not True or not isinstance(body['revision'],str) or not re.fullmatch('[a-f0-9]{64}',body['revision']):raise ZoneError('Revisá y confirmá la actualización de Zone.')
 if not secrets.compare_digest(body['revision'],maintenance_revision() or ''):raise ZoneError('La instalación cambió. Actualizá su estado y revisá nuevamente.')
 record=game.read_json(STATE)
 requested_domain=website_domain(body['web_domain']) if 'web_domain' in body else None
 domain_changed=requested_domain is not None and requested_domain!=record['public'].get('web_domain')
 if not domain_changed and record.get('runtime_revision')==RUNTIME_REVISION and record.get('web_revision')!=WEB_REVISION:
  ip=next(x for x in web.addresses(catalog) if ':' not in x)
  result=repair_web_dependencies(ip);record['web_revision']=WEB_REVISION;game.write_json(STATE,record)
  return {'ok':True,'message':'Web principal corregida y comprobada junto con el foro. La GM y sus cuentas se conservaron sin reiniciar el juego.'}
 current=game.status({});players=current.get('players') or {}
 if current['active'] and (not players.get('available') or players.get('connected')!=0):raise ZoneError('La actualización requiere el servidor sin jugadores conectados. Salí del juego y volvé a confirmar.')
 record=game.read_json(STATE);owned=game.checked_record();text=(game.BASE/'gamemodes/FZRP.pwn').read_bytes().decode('latin1')
 public=record['public'];match=re.fullmatch(r'([A-Za-z]{1,24}) Zone(?: Roleplay)?',public['name'])
 if not match:raise ZoneError('El nombre de esta instalación Zone no coincide con el formulario.')
 def constant(name):
  found=re.findall(r'(?m)^\s*#define\s+'+re.escape(name)+r'\s+"([^"\r\n]+)"',text)
  if len(found)!=1:raise ZoneError('No se encontró una definición única de '+name+'.')
  return found[0]
 value=dict(web_domain=requested_domain or public.get('web_domain'),name=match[1],database=public['database'],db_user=public['db_user'],db_password=constant('PASS_DB'),rcon_password=constant('RCON_PSSWRD'),port=current['settings']['port'],maxplayers=current['settings']['maxplayers'],ftp_user=owned['ftp']['username'])
 payload(value)
 if constant('USER_DB')!=value['db_user'] or constant('SELE_DB')!=value['database']:raise ZoneError('La GM apunta a otra base. Se conservó sin sobrescribir.')
 mysql.configure_platform();mysql.require_database(mysql.load(),value['database'])
 root=Path(tempfile.mkdtemp(prefix='server-monitor-zone-update-',dir='/var/tmp'));root.chmod(0o755)
 backup=Path('/var/backups/server-monitor-zone-update')/str(time.time_ns());game.private_dir(backup)
 paths=[game.BASE/'gamemodes/FZRP.pwn',game.BASE/'gamemodes/FZRP.amx',game.BASE/'server.cfg']
 for path in paths:shutil.copy2(path,backup/path.name)
 stopped=False;written=[]
 try:
  ip=next(x for x in web.addresses(catalog) if ':' not in x)
  _,amx=prepare_gm(value,root,ip,source=text.encode('latin1'))
  proposal=maintenance_revision()
  if proposal!=body['revision']:raise ZoneError('Los archivos cambiaron durante la compilación. No se aplicó la actualización.')
  fresh=game.status({});players=fresh.get('players') or {}
  if fresh['active'] and (not players.get('available') or players.get('connected')!=0):raise ZoneError('Se conectaron jugadores durante la compilación. No se reemplazó la GM; salí del juego y volvé a confirmar.')
  if current['active']:game.run(['systemctl','stop',game.SERVICE]);stopped=True
  migrate_game_schema(value);verify_registration_database(value)
  if domain_changed or record.get('runtime_revision')==RUNTIME_REVISION:repair_web_dependencies(ip)
  else:ensure_forum(value,ip)
  for source,target in [(root/'game/gamemodes/FZRP.pwn',paths[0]),(amx,paths[1])]:
   info=target.stat();shutil.copyfile(source,target);os.chown(target,info.st_uid,info.st_gid);os.chmod(target,stat.S_IMODE(info.st_mode));written.append(target)
  config=(game.BASE/'server.cfg').read_text();config,n=re.subn(r'(?m)^hostname[^\r\n]*','hostname '+settings(value)['hostname'],config)
  if n!=1:raise ZoneError('No se encontró el nombre del servidor en su configuración.')
  target=game.BASE/'server.cfg';info=target.stat();temporary=game.BASE/('server.cfg.zone-'+secrets.token_hex(8))
  try:
   with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|game.NOFOLLOW,stat.S_IMODE(info.st_mode)),'w') as stream:
    stream.write(config);stream.flush();os.fchmod(stream.fileno(),stat.S_IMODE(info.st_mode));os.fchown(stream.fileno(),info.st_uid,info.st_gid);os.fsync(stream.fileno())
   os.replace(temporary,target);written.append(target)
  finally:temporary.unlink(missing_ok=True)
  if current['active']:game.start_game();stopped=False
  record['public']['web_domain']=value['web_domain']
  record['runtime_revision']=RUNTIME_REVISION;record['web_revision']=WEB_REVISION;record['forum_url']='http://'+ip+'/foro/';game.write_json(STATE,record)
  return {'ok':True,'message':'GM recompilada con el dominio indicado. Web y registro comprobados; cuentas conservadas y archivos anteriores respaldados.'}
 except Exception:
  for target in written:shutil.copy2(backup/target.name,target)
  if current['active'] and (stopped or written):game.run(['systemctl','restart',game.SERVICE],check=False)
  raise
 finally:shutil.rmtree(root)


SMF_VERSION = '2.1.8'
SOURCE_URL = 'https://codeload.github.com/SimpleMachines/SMF/zip/refs/tags/v2.1.8'
SOURCE_SHA256 = '5693fd769fac1ec294d68e082d3b622930b552ee4abfe56acd0f4a61378cd118'
SMF_PREFIX = 'smf_'


def php_literal(value):
    return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"


def php_json(script, payload):
    """No secret is placed in a process argument, generated PHP, or a log."""
    result = subprocess.run(['/usr/bin/php', '-d', 'auto_prepend_file=', '-r', script],
                            input=json.dumps(payload), text=True, encoding='utf-8',
                            capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError('PHP no pudo preparar los datos del foro SMF.')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise RuntimeError('PHP no devolvió datos válidos para SMF.') from None


def prepare_forum(archive, staged_web, value, ip, final_site='/var/www/server-monitor-zone'):
    """Extract a new forum only; never overwrite an existing forum or config.

    Returns immutable package/schema information. Keep this object inside the
    privileged installer, because admin_password is only consumed by seed_forum.
    """
    archive = Path(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise RuntimeError('El paquete oficial SMF no coincide con su verificación.')
    forum = Path(staged_web) / 'foro'
    if forum.exists():
        raise RuntimeError('Ya existe un directorio foro; se conservó sin sobrescribirlo.')
    forum.mkdir(mode=0o755)
    with zipfile.ZipFile(archive) as source:
        if len(source.infolist()) > 10000 or sum(x.file_size for x in source.infolist()) > 100*1024**2:
            raise RuntimeError('El paquete SMF supera los límites permitidos.')
        for member in source.infolist():
            path = PurePosixPath(member.filename)
            if path.parts[0] != 'SMF-2.1.8' or path.is_absolute() or '..' in path.parts or '\\' in member.filename or stat.S_ISLNK(member.external_attr >> 16):
                raise RuntimeError('Ruta de archivo SMF no permitida.')
            parts = path.parts[1:]
            if not parts or parts[0].startswith('.') or parts[0] in ('other', 'composer.json', 'composer.lock', 'README.md', 'DCO.txt'):
                continue
            dest = forum.joinpath(*parts)
            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with source.open(member) as inp, dest.open('xb') as out:
                    shutil.copyfileobj(inp, out)
                dest.chmod(0o644)
        schema = source.read('SMF-2.1.8/other/install_2-1_mysql.sql').decode('utf-8')
        defaults_file = forum / 'Themes/default/languages/Install.english.php'
        # This file only defines translated default strings and cannot install or
        # mutate a forum. Its content was verified as part of the fixed package.
        defaults = php_json("$p=json_decode(stream_get_contents(STDIN),true); define('SMF',1); $txt=[]; require $p['path']; echo json_encode($txt);", {'path':str(defaults_file)})
    final_forum = str(Path(final_site) / 'foro')
    admin_name = 'ZoneAdmin'
    admin_password = secrets.token_urlsafe(30)
    data = {'db_name':value['database'], 'db_user':value['db_user'], 'db_passwd':value['db_password'],
            'db_server':'localhost', 'db_prefix':SMF_PREFIX, 'db_character_set':'utf8', 'db_type':'mysql',
            'mbname':value['name']+' Zone Roleplay', 'boardurl':'http://'+ip+'/foro',
            'language':'english', 'webmaster_email':'noreply@example.invalid',
            'cookiename':'SMFZone'+secrets.token_hex(8), 'boarddir':final_forum,
            'sourcedir':final_forum+'/Sources', 'cachedir':final_forum+'/cache',
            'packagesdir':final_forum+'/Packages', 'tasksdir':final_forum+'/Sources/tasks',
            'auth_secret':secrets.token_hex(32), 'image_proxy_secret':secrets.token_hex(32)}
    settings = '<?php\n// Server Security Monitor v3.0 - SMF '+SMF_VERSION+' Zone\n'
    settings += ''.join('$'+key+' = '+php_literal(item)+';\n' for key,item in data.items())
    settings += '$maintenance = 0;\n$db_port = 0;\n$db_persist = false;\n$db_error_send = false;\n$db_mb4 = null;\n$cache_enable = 0;\n$cache_accelerator = "";\n$image_proxy_enabled = false;\n$image_proxy_maxsize = 5192;\n'
    (forum / 'Settings.php').write_text(settings, encoding='utf-8')
    (forum / 'Settings.php').chmod(0o640)
    (forum / 'Settings_bak.php').write_text(settings, encoding='utf-8')
    (forum / 'Settings_bak.php').chmod(0o640)
    for directory in ('cache','attachments','custom_avatar'):
        (forum / directory).mkdir(exist_ok=True,mode=0o750)
    return {'schema':schema, 'defaults':defaults, 'forum':forum, 'final_forum':final_forum,
            'boardurl':data['boardurl'], 'admin_name':admin_name, 'admin_password':admin_password}


def render_schema(info, connection):
    esc = connection.escape_string
    values = {'db_prefix':SMF_PREFIX, 'engine':'InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci',
              'memory':'InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci',
              'boardurl':esc(info['boardurl']), 'boarddir':esc(info['final_forum']),
              'attachdir':esc(json.dumps({'1':info['final_forum']+'/attachments'})),
              'enableCompressedOutput':'0', 'databaseSession_enable':'1', 'smf_version':SMF_VERSION,
              'current_time':str(int(time.time())), 'sched_task_offset':'86400', 'registration_method':'3'}
    values.update({key:esc(val) for key,val in info['defaults'].items() if key.startswith('default_') and isinstance(val,str)})
    schema = info['schema']
    for key,val in values.items():
        schema = schema.replace('{$'+key+'}',str(val))
    if re.search(r'\{\$[^}]+\}',schema):
        raise RuntimeError('SMF requiere parámetros de esquema desconocidos.')
    return '\n'.join(line for line in schema.splitlines() if not line.lstrip().startswith('#'))


def seed_forum(info, connection, value, private_config):
    """Only create a complete fresh smf_ schema; pre-existing tables are untouched.

    Caller connection must enable MULTI_STATEMENTS, just like the Zone SQL import.
    Existing game accounts are imported as ordinary members, never administrators.
    """
    with connection.cursor() as cursor:
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,4)='smf_'")
        if cursor.fetchone():
            raise RuntimeError('Ya hay tablas smf_ en esta base; se conservaron sin modificarlas.')
        cursor.execute(render_schema(info,connection))
        while cursor.nextset():
            pass
        salt = secrets.token_hex(16)
        hashes = php_json("$p=json_decode(stream_get_contents(STDIN),true); echo json_encode(['hash'=>password_hash(strtolower($p['name']).$p['password'],PASSWORD_BCRYPT,['cost'=>10])]);", {'name':info['admin_name'],'password':info['admin_password']})
        cursor.execute("INSERT INTO smf_members (member_name,real_name,passwd,password_salt,email_address,id_group,date_registered,buddy_list,pm_ignore_list,signature,ignore_boards,is_activated) VALUES (%s,%s,%s,%s,%s,1,UNIX_TIMESTAMP(),'','','','',1)",
                       (info['admin_name'],info['admin_name'],hashes['hash'],salt,'admin@example.invalid'))
        # The supplied GM assigns regular game accounts group 13. Clone only
        # ordinary-member permissions, keeping administration (group 1) separate.
        cursor.execute("INSERT INTO smf_membergroups (id_group,group_name,description,min_posts,group_type) VALUES (13,'Jugadores','Cuentas registradas desde el servidor de juego',-1,0)")
        cursor.execute("INSERT INTO smf_permissions(id_group,permission,add_deny) SELECT 13,permission,add_deny FROM smf_permissions WHERE id_group=0")
        cursor.execute("INSERT INTO smf_board_permissions(id_group,id_profile,permission,add_deny) SELECT 13,id_profile,permission,add_deny FROM smf_board_permissions WHERE id_group=0")
        # Original game passwords are plain strings; use SMF's documented legacy
        # SHA1(lower(username)+password) format. SMF upgrades it to bcrypt at login.
        cursor.execute("INSERT INTO smf_members (member_name,real_name,passwd,password_salt,email_address,id_group,date_registered,buddy_list,pm_ignore_list,signature,ignore_boards,is_activated) SELECT username,REPLACE(username,'_',' '),SHA1(CONCAT(LOWER(username),password)),%s,Email,13,UNIX_TIMESTAMP(),'','','','',1 FROM usuarios WHERE username<>%s",(secrets.token_hex(16),info['admin_name']))
        rows = [('registration_method','3'),('enable_password_conversion','0'),('global_character_set','UTF-8'),('default_timezone','UTC'),
                ('allow_sm_stats','0'),('enable_sm_stats','0'),('disableHostnameLookup','1')]
        cursor.executemany("REPLACE INTO smf_settings (variable,value) VALUES (%s,%s)",rows)
        cursor.execute("REPLACE INTO smf_settings(variable,value) SELECT 'totalMembers',COUNT(*) FROM smf_members WHERE is_activated=1")
        cursor.execute("REPLACE INTO smf_settings(variable,value) SELECT 'latestMember',id_member FROM smf_members ORDER BY id_member DESC LIMIT 1")
        cursor.execute("REPLACE INTO smf_settings(variable,value) SELECT 'latestRealName',real_name FROM smf_members ORDER BY id_member DESC LIMIT 1")
        smileys={':)':'smiley',';)':'wink',':D':'cheesy',';D':'grin','>:(':'angry',':(':'sad',':o':'shocked','8)':'cool','???':'huh','::)':'rolleyes',':P':'tongue',':-[':'embarrassed',':-X':'lipsrsealed',':-\\':'undecided',':-*':'kiss',":'(":'cry','>:D':'evil','^-^':'azn','O0':'afro',':))':'laugh','C:-)':'police','O:-)':'angel'}
        cursor.execute('SELECT id_smiley,code FROM smf_smileys')
        for row in cursor.fetchall():
            sid,code = (row['id_smiley'],row['code']) if isinstance(row,dict) else row
            if code in smileys:
                cursor.executemany('INSERT IGNORE INTO smf_smiley_files(id_smiley,smiley_set,filename) VALUES (%s,%s,%s)',[(sid,set_name,smileys[code]+'.png') for set_name in ('fugue','alienine')])
    private_config = Path(private_config)
    private_config.mkdir(parents=True,exist_ok=True,mode=0o750)
    secretfile = private_config / 'forum-admin.json'
    fd = os.open(secretfile,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as out:
        json.dump({'username':info['admin_name'],'password':info['admin_password'],'url':info['boardurl']},out)
    return {'version':SMF_VERSION,'url':info['boardurl'],'registration_enabled':False,'admin_username':info['admin_name'],'admin_secret_file':str(secretfile)}


def finalize_permissions(site, web_uid, web_gid):
    """Run after Zone's generic publish chmod loop, so uploads/cache can work."""
    forum = Path(site)/'foro'
    for name in ('cache','attachments','custom_avatar'):
        directory = forum/name
        directory.mkdir(exist_ok=True,mode=0o750)
        os.chown(directory,web_uid,web_gid)
        directory.chmod(0o750)
    for name in ('Settings.php','Settings_bak.php'):
        os.chown(forum/name,0,web_gid)
        (forum/name).chmod(0o640)


FORUM_PAWN=r'''
// Server Monitor: only synchronize a forum member after game INSERT succeeds.
forward SmZoneForumRegistered(playerid);
stock SmZoneSyncForumMember(playerid)
{
    new Query[1800];
    mysql_format(handle_db, Query, sizeof(Query), "INSERT INTO smf_members (member_name,real_name,passwd,password_salt,email_address,id_group,date_registered,buddy_list,pm_ignore_list,signature,ignore_boards,is_activated,member_ip) SELECT '%e',REPLACE('%e','_',' '),SHA1(CONCAT(LOWER('%e'),'%e')),MD5(UUID()),'%e',13,UNIX_TIMESTAMP(),'','','','',1,'%e' WHERE NOT EXISTS (SELECT 1 FROM smf_members WHERE member_name='%e')", PlayerInfo[playerid][Nickname],PlayerInfo[playerid][Nickname],PlayerInfo[playerid][Nickname],PlayerInfo[playerid][pPassword],PlayerInfo[playerid][pEmail],PlayerIP(playerid),PlayerInfo[playerid][Nickname]);
    mysql_tquery(handle_db, Query, "SmZoneForumRegistered", "d", playerid);
    return 1;
}
public SmZoneForumRegistered(playerid)
{
    mysql_tquery(handle_db, "REPLACE INTO smf_settings(variable,value) SELECT 'totalMembers',COUNT(*) FROM smf_members WHERE is_activated=1");
    mysql_tquery(handle_db, "REPLACE INTO smf_settings(variable,value) SELECT 'latestMember',id_member FROM smf_members ORDER BY id_member DESC LIMIT 1");
    mysql_tquery(handle_db, "REPLACE INTO smf_settings(variable,value) SELECT 'latestRealName',real_name FROM smf_members ORDER BY id_member DESC LIMIT 1");
    return 1;
}
'''

def add_forum_registration(text):
 if '// Server Monitor: only synchronize a forum member' in text:return text
 start,_=_function_span(text,'OnQueryError');opening=text.index('{',start)+1
 text=text[:opening]+r'''
        if(!strcmp(callback, "SmZoneForumRegistered"))
        {
            printf("[Zone foro] Error MySQL %d. La cuenta del juego se conserva.", errorid);
            return 1;
        }
'''+text[opening:]
 return text+'\n'+FORUM_PAWN

def ensure_forum(value,ip):
 forum=SITE/'foro';private=CONFIG/'forum-admin.json'
 if forum.exists():
  if not private.is_file() or not (forum/'Settings.php').is_file():raise ZoneError('La carpeta foro ya existe fuera de esta instalación. Se conservó.')
  with mysql.connect(database=value['database']) as conn:
   if mysql.query(conn,"SELECT value FROM smf_settings WHERE variable='smfVersion'")[0]['value']!=SMF_VERSION:raise ZoneError('La versión instalada del foro requiere una actualización separada.')
   mysql.execute(conn,"REPLACE INTO smf_settings(variable,value) VALUES ('registration_method','3'),('enable_password_conversion','0')");conn.commit()
  repair_web_dependencies(ip)
  return
 with mysql.connect(database=value['database']) as conn:
  if mysql.query(conn,"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,4)='smf_'"):raise ZoneError('Ya hay tablas de otro foro en la base. Se conservaron.')
 root=Path(tempfile.mkdtemp(prefix='server-monitor-zone-forum-',dir='/var/tmp'));root.chmod(0o700)
 seeded=False;published=False
 try:
  info=prepare_forum(artifact('smf'),root,value,ip)
  driver=mysql.driver()
  conn=driver.connect(unix_socket=mysql.SOCKET,user=value['db_user'],password=value['db_password'],database=value['database'],charset='utf8mb4',autocommit=True,client_flag=driver.constants.CLIENT.MULTI_STATEMENTS,read_timeout=120,cursorclass=driver.cursors.DictCursor)
  try:
   seeded=True
   seed_forum(info,conn,value,CONFIG)
  finally:conn.close()
  account=pwd.getpwnam('sm-zone-web')
  for directory,dirs,files in os.walk(info['forum']):
   os.chown(directory,0,account.pw_gid);os.chmod(directory,0o755)
   for name in files:
    path=Path(directory)/name;os.chown(path,0,account.pw_gid);path.chmod(0o640 if name.endswith('.php') else 0o644)
  os.rename(info['forum'],forum);published=True
  finalize_permissions(SITE,account.pw_uid,account.pw_gid)
  stack=catalog.read(web.STATE/'stack.json')
  web.publish(catalog,linux.detect(),stack,{'phpmyadmin'},stack.get('frontuser','www-data'))
  for attempt in range(12):
   try:
    with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1/foro/index.php',headers={'Host':ip}),timeout=20) as response:body=response.read(2*1024**2)
    if b'Simple Machines' in body or b'SMF' in body:break
   except urllib.error.URLError:pass
   if attempt==11:raise ZoneError('El foro SMF no confirmó una respuesta correcta.')
   time.sleep(.5)
  repair_web_dependencies(ip)
 except Exception:
  # Only a fresh prefix owned by this operation can be rolled back here.
  if published:shutil.rmtree(forum)
  if seeded:
   with mysql.connect(database=value['database']) as conn:
    for row in mysql.query(conn,"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,4)='smf_'"):
     mysql.execute(conn,'DROP TABLE '+mysql.ident(row['TABLE_NAME']))
    conn.commit()
   private.unlink(missing_ok=True)
  raise
 finally:shutil.rmtree(root)

def forum_credentials(body):
 if body!={}:raise ZoneError('La consulta de acceso al foro no admite parámetros.')
 row=game.checked_record()
 if not row or row.get('edition')!='zone':raise ZoneError('No hay una instalación Zone administrada.')
 path=CONFIG/'forum-admin.json';info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ZoneError('Los datos del administrador del foro no tienen permisos seguros.')
 value=json.loads(path.read_text())
 if set(value)!={'username','password','url'}:raise ZoneError('Los datos del administrador del foro no son válidos.')
 return dict(ok=True,**value)


def apply_website_domain(text, domain, legacy_ip=None):
    domain = website_domain(domain)
    if legacy_ip is not None:ipaddress.ip_address(legacy_ip)

    tokens = re.compile(r'''//[^\r\n]*|/\*[\s\S]*?\*/|'(?:\\[^\r\n]|[^'\\\r\n])*'|"(?:\\[^\r\n]|[^"\\\r\n])*"''')
    # Keep every offset and line ending so matching code cannot touch comments.
    code = tokens.sub(lambda m: re.sub(r'[^\r\n]', ' ', m[0]) if m[0].startswith(('//', '/*')) else m[0], text)
    replacements = []
    values = {
        'WEB_ROL': domain, 'WEB_LOGEO': domain, 'WEB_INDEX': domain,
        'WEB_INDEX2': domain, 'WEB_SONIDOS': domain + '/sonidos',
        'WEB_RADIO': domain + '/%d',
    }
    for key, value in values.items():
        matches = list(re.finditer(r'(?m)^[ \t]*#define[ \t]+' + key + r'[ \t]+([^\r\n]*?)[ \t]*(?=\r?$)', code))
        if len(matches) != 1:
            raise ValueError('No se encontró una definición única de ' + key + '.')
        match = matches[0]
        expression = match[1]
        if not re.fullmatch(r'"(?:\\.|[^"\\])*"', expression) and not (key == 'WEB_INDEX2' and expression == '"www."SERVER_NAME2".com"'):
            raise ValueError('La definición de ' + key + ' tiene una estructura no reconocida.')
        replacements.append((match.start(1), match.end(1), '"' + value + '"'))

    for variable in ('CN4', 'CN5'):
        matches = list(re.finditer(r'(?m)^[ \t]*' + variable + r'[ \t]*=[ \t]*TextDrawCreate\([^\r\n"]*"([^"\r\n]*)"', code))
        if len(matches) != 1:
            raise ValueError('No se encontró un TextDraw único de ' + variable + '.')
        match = matches[0]
        if variable == 'CN4':
            old = re.fullmatch(r'(WEB:[ \t]+HTTPS?://)([^/\s]+)', match[1], flags=re.I)
            value = old[1] + domain if old else None
        else:
            old = re.fullmatch(r'([^/\s]+)( - Servidor RP )', match[1])
            value = domain + old[2] if old else None
        if value is None:
            raise ValueError('El TextDraw de ' + variable + ' tiene una estructura no reconocida.')
        replacements.append((match.start(1), match.end(1), value))

    for start, end, replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def prepare_gm(value,root,ip,source=None):
 game_root=root/'game';game_root.mkdir();unpack(artifact('gm'),game_root)
 if source is not None:(game_root/'gamemodes/FZRP.pwn').write_bytes(source)
 normalize_includes(game_root)
 path=game_root/'gamemodes/FZRP.pwn';text=path.read_bytes().decode('latin1');name=value['name']+' Zone';short=value['name'][0].upper()+'Z'
 constants={'HOST_DB':'localhost','USER_DB':value['db_user'],'SELE_DB':value['database'],'PASS_DB':value['db_password'],'RCON_PSSWRD':value['rcon_password'],'SERVER_NAME2':name,'SERVER_COIN':short,'SERVER_COIN2':short,'SERVER_COIN3':short,'WEB_ROL':value['web_domain'],'WEB_LOGEO':value['web_domain'],'WEB_INDEX':value['web_domain'],'WEB_INDEX2':value['web_domain']}
 for key,val in constants.items():text=define(text,key,val)
 text,count=re.subn(r'SendRconCommand\("hostname FZ Roleplay \[S1\] Rol en espa[^\r\n]*', '// El nombre se lee de server.cfg, administrado por el panel.',text)
 if count!=1 and (count!=0 or '// El nombre se lee de server.cfg, administrado por el panel.' not in text):raise ZoneError('La configuración del nombre de esta GM cambió.')
 text=text.replace('SetGameModeText("FZ:RP v5.00 - Rol en espa\xf1ol");','SetGameModeText("'+short+' Roleplay");')
 text=rebrand_gm(text,value['name'],ip,value['web_domain'])
 text=apply_website_domain(text,value['web_domain'],ip)
 text=transform_registration(text,forum_registration_hook='SmZoneSyncForumMember')
 text=add_forum_registration(text)
 path.write_bytes(text.encode('latin1'))
 compiler=root/'compiler';compiler.mkdir()
 with tarfile.open(artifact('compiler'),'r:gz') as archive:
  for item in archive.getmembers():
   if PurePosixPath(item.name).is_absolute() or '..' in PurePosixPath(item.name).parts or not (item.isfile() or item.isdir()):raise ZoneError('Archivo del compilador no permitido.')
   dest=compiler.joinpath(*PurePosixPath(item.name).parts)
   if item.isdir():dest.mkdir(parents=True,exist_ok=True,mode=0o755)
   else:
    dest.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    with archive.extractfile(item) as src,dest.open('wb') as out:shutil.copyfileobj(src,out)
    dest.chmod(0o755 if dest.name=='pawncc' else 0o644)
 out=root/'output';out.mkdir(mode=0o700);nobody=pwd.getpwnam('nobody');os.chown(out,nobody.pw_uid,nobody.pw_gid)
 path.chmod(0o644)
 result=game.run(['runuser','-u','nobody','--','env','LD_LIBRARY_PATH='+str(compiler/'pawnc-3.10.10-linux/lib'),str(compiler/'pawnc-3.10.10-linux/bin/pawncc'),str(path),'-i'+str(game_root/'pawno/include'),'-o'+str(out/'FZRP.amx'),'-d2','-Z'],timeout=180,check=False)
 game.private_dir(CACHE);log=(result.stdout or '')+(result.stderr or '')
 for secret in (value['db_password'],value['rcon_password']):log=log.replace(secret,'[oculto]')
 web.text_file(CACHE/'compile.log',log,0o600)
 if result.returncode or not (out/'FZRP.amx').is_file():raise ZoneError('La GM no compiló. Se conservó el registro en /var/cache/server-monitor-zone/compile.log; no se reemplazó ningún AMX.')
 return game_root,out/'FZRP.amx'

def php_string(value):return "'"+value.replace('\\','\\\\').replace("'","\\'")+"'"

def prepare_web(value,root,ip):
 site=root/'web';site.mkdir();unpack(artifact('web'),site)
 replacements={'ip_mysql':'localhost','nombre_db':value['database'],'nombre_act':value['database'],'user_sa':value['db_user'],'password_sa':value['db_password'],'NombreServidor':value['name']+' Zone','Diminutivo':value['name'][0].upper()+'Z','serverIP':ip,'serverPort':value['port'],'DBIps':'localhost','UserDBSamp':value['db_user'],'ClaveSVR':value['db_password'],'DBNameSVR':value['database']}
 connections=[]
 for path in site.rglob('*.php'):
  text=repair_empty_admin_entry(detach_unused_forum_ssi(path.read_bytes().decode('latin1'),path.relative_to(site).as_posix()),path.relative_to(site).as_posix())
  for key,val in replacements.items():
   pattern=r'(\$'+key+r'\s*=\s*)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|\d+)\s*;'
   text,count=re.subn(pattern,lambda m:m[1]+(str(val) if type(val) is int else php_string(val))+';',text)
   if count and key=='nombre_db':connections.append(path.relative_to(site).as_posix())
  try:text=reuse_zone_pdo(text,path.relative_to(site).as_posix())
  except ValueError as exc:raise ZoneError(str(exc)) from None
  # Known defects in the pinned archive, not arbitrary source rewrites.
  if path.name=='perfil.php':text=re.sub(r'\bcase\s+0([1-9])\s*:',r'case \1:',text)
  if path.name=='firma.php':text=text.replace("imagecreatefrompng('imagenes/firmas/firma3.png);","imagecreatefrompng('imagenes/firmas/firma3.png');")
  if path.relative_to(site).as_posix()=='admin/images/mailer.php':text="<?php http_response_code(503); exit('Correo no configurado.');\n"
  text=re.sub(r'function\s+sql_inject\s*\(', 'function __construct(',text)
  path.write_bytes(text.encode('latin1'))
  lint=game.run(['php','-l',str(path)],check=False)
  if lint.returncode:raise ZoneError('PHP rechazó '+str(path.relative_to(site))+'. No se publicó la web.')
 if not {'kev/pdo.php','sapd/kev/pdo.php'}<=set(connections):raise ZoneError('No se encontraron las conexiones PDO esperadas.')
 return site,connections

def database(value,sqlfile,record):
 mysql.configure_platform();
 for payload in [dict(action='create-database',database=value['database']),dict(action='create-user',database=value['database'],username=value['db_user'],password=value['db_password'],privileges=list(mysql.PRIVILEGES),ips=[],enabled=True)]:
  proposal=mysql.plan(payload);mysql.change({**payload,'revision':proposal['revision'],'confirm':True},catalog.flow.repair_monitors)
  record['db_created']=True;game.write_json(STATE,record)
 configure_connection_budget(value)
 driver=mysql.driver();conn=driver.connect(unix_socket=mysql.SOCKET,user=value['db_user'],password=value['db_password'],database=value['database'],charset='utf8mb4',autocommit=True,client_flag=driver.constants.CLIENT.MULTI_STATEMENTS,read_timeout=120)
 try:
  with conn.cursor() as cursor:
   cursor.execute(sqlfile.read_text(encoding='utf-8-sig'))
   while cursor.nextset():pass
   cursor.execute('SHOW TABLES');count=len(cursor.fetchall())
   if count!=36:raise ZoneError('La importación no creó las 36 tablas esperadas.')
   # The supplied dump omits two tables referenced by this exact pinned GM.
   # These migrations apply only to the newly-created Zone database.
   cursor.execute('CREATE TABLE `admin_names` (`Nickname` VARCHAR(24) NOT NULL PRIMARY KEY) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')
   cursor.execute('CREATE TABLE `zonas` (`ID` INT NOT NULL AUTO_INCREMENT PRIMARY KEY, `Banda` INT NOT NULL DEFAULT 0, `Nombre` VARCHAR(64) NOT NULL DEFAULT \'\', `Min_X` FLOAT NOT NULL DEFAULT 0, `Min_Y` FLOAT NOT NULL DEFAULT 0, `Min_Z` FLOAT NOT NULL DEFAULT 0, `Max_X` FLOAT NOT NULL DEFAULT 0, `Max_Y` FLOAT NOT NULL DEFAULT 0, `Max_Z` FLOAT NOT NULL DEFAULT 0, `Color` BIGINT NOT NULL DEFAULT 0, `Z_Activa` TINYINT NOT NULL DEFAULT 0, INDEX (`Z_Activa`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')
 finally:conn.close()
 migrate_game_schema(value)
 verify_registration_database(value)

def install_pma():
 p=linux.detect();info=web.own(catalog,'phpmyadmin')
 if info and info.get('phase')=='installed':
  result=catalog.control_plan({'service':'phpmyadmin','action':'start'});catalog.control_apply({'service':'phpmyadmin','action':'start','revision':result['revision'],'confirm':True});return
 rows=catalog.refresh({'service':'phpmyadmin'})['versions'];row=next(x for x in rows if not x.get('archived'))
 request={'service':'phpmyadmin','action':'install','selection':row['id']};proposal=catalog.plan(request);catalog.apply({**request,'revision':proposal['revision'],'confirm':True})

def install(body):
 value=payload(body,True)
 reviewed=plan(value)
 if not secrets.compare_digest(reviewed['revision'],body['revision']):raise ZoneError('El servidor cambió. Revisá nuevamente la instalación.')
 game.game_ftp.options({'enabled':True,'username':value['ftp_user']})
 secret=body['ftp_secret']
 if not isinstance(secret,dict) or set(secret)!={'id','password'} or not re.fullmatch('[a-f0-9]{32}',str(secret.get('id',''))) or not re.fullmatch('[A-Za-z0-9_-]{32,128}',str(secret.get('password',''))):raise ZoneError('Credencial FTP inválida.')
 with removal.package_lock():linux.install_packages(game.run,linux.detect(),game.runtime_packages(linux.detect()))
 import storypulse_game_cleanup as cleanup
 dependency_before=cleanup.capture_dependency_inventory()
 try:web_identity_before=pwd.getpwnam('sm-zone-web')
 except KeyError:web_identity_before=None
 root=Path(tempfile.mkdtemp(prefix='server-monitor-zone-build-',dir='/var/tmp'));root.chmod(0o755)
 stage_record={'public':{'name':value['name']+' Zone','database':value['database'],'db_user':value['db_user'],'web_domain':value['web_domain']},'phase':'preparing','db_created':False,'dependency_baseline':dependency_before}
 record=None
 try:
  ip=next(x for x in web.addresses(catalog) if ':' not in x)
  game_root,amx=prepare_gm(value,root,ip)
  # phpMyAdmin provisions the panel-owned database server, FPM, GD and HTTP.
  install_pma()
  stage_site,connections=prepare_web(value,root,ip)
  stage_record['phase']='database';game.write_json(STATE,stage_record)
  sqlroot=root/'db';sqlroot.mkdir();unpack(artifact('db'),sqlroot);sqls=list(sqlroot.glob('*.sql'))
  if len(sqls)!=1:raise ZoneError('El paquete debe contener un solo SQL en su raíz.')
  database(value,sqls[0],stage_record)
  game.run(['useradd','--system','--user-group','--no-create-home','--home-dir',str(game.BASE),'--shell','/usr/sbin/nologin',game.USER]);account=pwd.getpwnam(game.USER)
  record=dict(game='samp',edition='zone',version=game.VERSION,uid=account.pw_uid,gid=account.pw_gid,owned_ports=[],phase='installing')
  game.write_json(game.STATE,record);game.BASE.parent.mkdir(parents=True,exist_ok=True,mode=0o755);game.BASE.mkdir(mode=0o755)
  game.extract_archive(game.download(),game.BASE)
  for name in ('gamemodes','plugins','scriptfiles','filterscripts'):
   source=game_root/name
   if source.exists():shutil.copytree(source,game.BASE/name,dirs_exist_ok=True)
  shutil.copy2(amx,game.BASE/'gamemodes/FZRP.amx')
  # The upstream MySQL plugin's companion library is supplied by the pinned package.
  install_mysql_library(game.BASE)
  for name in PLUGINS:
   result=game.run(['ldd',str(game.BASE/'plugins'/name)],check=False)
   if result.returncode or 'not found' in (result.stdout or '')+(result.stderr or ''):raise ZoneError('Faltan bibliotecas Linux para '+name+'. No se inició la GM.')
  for directory,dirs,files in os.walk(game.BASE):
   os.chown(directory,0,account.pw_gid);os.chmod(directory,0o750)
   for name in files:
    path=Path(directory)/name;os.chown(path,0,account.pw_gid);path.chmod(0o750 if name in ('samp03svr','samp-npc','announce') else 0o640)
  for directory,dirs,files in os.walk(game.BASE/'scriptfiles'):
   os.chown(directory,account.pw_uid,account.pw_gid)
   for name in files:os.chown(Path(directory)/name,account.pw_uid,account.pw_gid)
  log=game.BASE/'server_log.txt';log.touch();os.chown(log,0,account.pw_gid);log.chmod(0o660)
  logs=game.BASE/'logs';logs.mkdir(exist_ok=True);os.chown(logs,account.pw_uid,account.pw_gid);logs.chmod(0o750)
  game.write_config(settings(value),value['rcon_password'],account.pw_gid)
  game.write_unit();unit=game.UNIT.read_text();unit=unit.replace('ReadWritePaths='+str(game.BASE)+'/scriptfiles '+str(game.BASE)+'/server_log.txt','ReadWritePaths='+str(game.BASE)+'/scriptfiles '+str(game.BASE)+'/server_log.txt '+str(logs));web.text_file(game.UNIT,unit)
  with removal.FIREWALL_LOCK.open('a') as handle:
   __import__('fcntl').flock(handle,__import__('fcntl').LOCK_EX|__import__('fcntl').LOCK_NB)
   game.open_port(value['port'],record)
   game.game_ftp.create({'enabled':True,'username':value['ftp_user']},secret,record,lambda:game.write_json(game.STATE,record))
  publish_web(stage_site,stage_record,ip)
  web_account=pwd.getpwnam('sm-zone-web');stage_record['web_identity']=dict(uid=web_account.pw_uid,gid=web_account.pw_gid,created=web_identity_before is None)
  ensure_forum(value,ip)
  game.run(['systemctl','daemon-reload']);game.run(['systemctl','enable',game.SERVICE]);game.start_game();time.sleep(5)
  logtext=(game.BASE/'server_log.txt').read_text(errors='replace')
  if not game.unit_state()['active'] or 'Run time error 19' in logtext or 'Failed (' in logtext or '[ERROR]' in logtext or 'fallida con la base' in logtext:raise ZoneError('La GM no confirmó un arranque sin errores. Revisá su consola; no se marcó como instalada.')
  with mysql.connect(user=value['db_user'],secret=value['db_password'],database=value['database']) as conn:mysql.query(conn,'SELECT COUNT(*) AS total FROM usuarios')
  record['phase']='ready';game.write_json(game.STATE,record)
  stage_record['dependencies']=cleanup.finish_provenance(dependency_before)
  stage_record.update(phase='ready',connections=connections,runtime_revision=RUNTIME_REVISION,web_revision=WEB_REVISION,forum_url='http://'+ip+'/foro/');game.write_json(STATE,stage_record)
  return {'ok':True,'message':'SA-MP GM Zone instalado y encendido. Web: http://'+ip+'/ · phpMyAdmin: http://'+ip+'/phpmyadmin/ · FTP disponible en Gestionar juegos.'}
 except Exception as error:
  if record:
   record['phase']='error';game.write_json(game.STATE,record);game.run(['systemctl','disable','--now',game.SERVICE],check=False)
   with contextlib.suppress(Exception):game.close_owned_ports(record)
  stage_record['phase']='error'
  game.write_json(STATE,stage_record)
  message=str(error)
  for s in (value['db_password'],value['rcon_password'],secret['password']):message=message.replace(s,'[oculto]')
  try:
   if record:game.uninstall(record)
   elif SITE.exists() or CONFIG.exists():withdraw(record or {})
   rollback_database(stage_record)
   STATE.unlink(missing_ok=True)
  except Exception:
   message+=' La limpieza quedó pendiente; se conservó el registro para no borrar recursos ajenos.'
  raise ZoneError(message[:2000]) from None
 finally:
  shutil.rmtree(root)

def install_mysql_library(base):
 with tarfile.open(artifact('mysql_library'),'r:gz') as archive:
  data=archive.extractfile('mysql-R41-4-Debian/log-core.so').read(1024**2)
  path=base/'log-core.so';path.write_bytes(data);path.chmod(0o644)

def publish_web(staged,record,ip):
 try:account=pwd.getpwnam('sm-zone-web')
 except KeyError:
  game.run(['useradd','--system','--user-group','--no-create-home','--home-dir',str(SITE),'--shell','/usr/sbin/nologin','sm-zone-web']);account=pwd.getpwnam('sm-zone-web')
 if account.pw_uid==0:raise ZoneError('Identidad de PHP no válida.')
 game.private_dir(CONFIG);CONFIG.chmod(0o750);os.chown(CONFIG,0,account.pw_gid)
 private={'database':record['public']['database'],'user':record['public']['db_user']}
 # Credentials already reside in the PDO files. Bootstrap reads only that fixed file.
 compatibility=(Path('/usr/local/sbin/storypulse_zone_compat.php')).read_text(encoding='utf-8')
 web.text_file(CONFIG/'compat.php',compatibility,0o640);os.chown(CONFIG/'compat.php',0,account.pw_gid)
 shutil.copytree(staged,SITE)
 for directory,dirs,files in os.walk(SITE):
  os.chown(directory,0,account.pw_gid);os.chmod(directory,0o755)
  for name in files:
   path=Path(directory)/name;os.chown(path,0,account.pw_gid);path.chmod(0o640 if name.endswith('.php') else 0o644)
 stack=catalog.read(web.STATE/'stack.json');frontuser=stack.get('frontuser','www-data')
 config='[global]\ndaemonize=no\nerror_log=syslog\n[zone]\nuser=sm-zone-web\ngroup=sm-zone-web\nlisten='+SOCKET+'\nlisten.owner='+frontuser+'\nlisten.mode=0600\npm=ondemand\npm.max_children=4\npm.process_idle_timeout=10s\nclear_env=yes\nsecurity.limit_extensions=.php\nphp_admin_value[auto_prepend_file]='+str(CONFIG/'compat.php')+'\nphp_admin_value[disable_functions]=mail\nphp_admin_value[cgi.fix_pathinfo]=0\nphp_admin_flag[display_errors]=off\nphp_admin_flag[log_errors]=on\nphp_admin_value[memory_limit]=192M\n'
 web.text_file(CONFIG/'php-fpm.conf',config,0o640)
 _,binary=web.packages(catalog,linux.detect())
 game.run([binary,'-t','-y',str(CONFIG/'php-fpm.conf')])
 unit='[Unit]\nDescription=Server Monitor Zone PHP\nAfter=network.target\n[Service]\nType=simple\nExecStart='+binary+' -F -y '+str(CONFIG/'php-fpm.conf')+'\nRuntimeDirectory=server-monitor-zone\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\n[Install]\nWantedBy=multi-user.target\n'
 web.text_file(Path('/etc/systemd/system')/WEB_UNIT,unit)
 game.run(['systemctl','daemon-reload']);game.run(['systemctl','enable','--now',WEB_UNIT]);catalog.flow.wait_service(game.run,WEB_UNIT,socket=SOCKET)
 game.write_json(MARKER,{'site':str(SITE),'phase':'installed'})
 try:
  web.publish(catalog,linux.detect(),stack,{'phpmyadmin'},frontuser)
  verify_web(ip)
 except Exception:
  MARKER.unlink(missing_ok=True)
  web.publish(catalog,linux.detect(),stack,{'phpmyadmin'},frontuser)
  raise
 record['public'].update(web_url='http://'+ip+'/',phpmyadmin_url='http://'+ip+'/phpmyadmin/')

def verify_web(ip):
 url='http://127.0.0.1/'
 for path,marker in [('index.php',b'<html'),('descargas.php',b'<html'),('ingresar.php',b'<form'),('phpmyadmin/',b'phpMyAdmin'),('admin/',b'id="entrar-1"'),('admin/login.php',b'id="entrar-1"')]:
  req=urllib.request.Request(url+path,headers={'Host':ip})
  for attempt in range(15):
   try:
    with urllib.request.urlopen(req,timeout=20) as response:body=response.read(2*1024**2)
    if any(error in body.lower() for error in (b'sqlstate',b'max_user_connections',b'error conectando con la base de datos')):raise ZoneError('La comprobación de base de datos falló en '+path+'.')
    if marker.lower() in body.lower():break
   except (urllib.error.URLError,TimeoutError):pass
   if attempt==14:raise ZoneError('La comprobación HTTP falló en '+path+' después de recargar Nginx.')
   time.sleep(.3)
 # An ephemeral probe reaches the actual FPM pool; it contains no credentials.
 probe=SITE/'zone-health-check.php'
 source="<?php header('Content-Type: application/json'); require __DIR__.'/kev/pdo.php'; echo json_encode(['db'=>(int)$con->query('SELECT 1')->fetchColumn(),'gd'=>function_exists('imagettftext'),'png'=>gd_info()['PNG Support'],'session'=>function_exists('session_start')]);"
 web.text_file(probe,source,0o644)
 try:
  with urllib.request.urlopen(urllib.request.Request(url+probe.name,headers={'Host':ip}),timeout=15) as response:row=json.load(response)
  if row!={'db':1,'gd':True,'png':True,'session':True}:raise ZoneError('PHP-FPM no confirmó conexión, imágenes o sesiones.')
 finally:probe.unlink(missing_ok=True)

def withdraw(record):
 owned=game.read_json(STATE)
 if not owned:return
 game.run(['systemctl','disable','--now',WEB_UNIT],check=False)
 MARKER.unlink(missing_ok=True)
 stack=catalog.read(web.STATE/'stack.json')
 if stack:web.publish(catalog,linux.detect(),stack,{kind for kind in web.APPS if web.own(catalog,kind)},stack.get('frontuser','www-data'))
 # The shared MySQL service, phpMyAdmin and existing databases are preserved.
 # This installation's database is retained intentionally to avoid losing players.
 for path in (SITE,CONFIG):
  removal.safe_path(path)
  if path.exists():shutil.rmtree(path)
 unit=Path('/etc/systemd/system')/WEB_UNIT;removal.safe_path(unit);unit.unlink(missing_ok=True)
 game.run(['systemctl','daemon-reload']);STATE.unlink(missing_ok=True)

def rollback_database(record):
 if not record.get('db_created'):return
 value=record['public'];name=mysql.dbname(value['database']);user=mysql.username(value['db_user']);mysql.configure_platform();config=mysql.load()
 if name not in config['databases']:raise ZoneError('La base dejó de pertenecer a esta instalación.')
 matching=next((x for x in config['users'] if x['username']==user and x['database']==name),None)
 if matching:
  request={'action':'delete-user','username':user};proposal=mysql.plan(request);mysql.change({**request,'revision':proposal['revision'],'confirm':True},catalog.flow.repair_monitors)
 with mysql.connect() as conn:mysql.execute(conn,'DROP DATABASE '+mysql.ident(name))
 config=mysql.load();config['databases']=[x for x in config['databases'] if x!=name];mysql.save(config)

def dispatch(command,body):
 if command=='zone-status':return status(body)
 if command=='zone-plan':return plan(body)
 if command=='zone-forum-credentials':return forum_credentials(body)
 if command in ('zone-apply','zone-repair'):
  lock=Path('/run/lock/storypulse-zone-install.lock')
  with lock.open('a') as handle:
   try:__import__('fcntl').flock(handle,__import__('fcntl').LOCK_EX|__import__('fcntl').LOCK_NB)
   except BlockingIOError:raise ZoneError('Hay otra instalación Zone en curso.') from None
   return install(body) if command=='zone-apply' else repair(body)
 raise ZoneError('Acción Zone no permitida.')
