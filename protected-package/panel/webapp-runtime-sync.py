"""Panel-owned, bounded web module maintenance over its pinned SSH connection."""
import ast,base64,fcntl,hashlib,json,os,shutil,stat,tempfile,time,uuid
from pathlib import Path

ROOT=Path('/usr/local/sbin')
BACKUPS=Path('/var/backups/server-monitor-web-runtime')
LOCK=Path('/run/lock/storypulse-service-packages.lock')
PREVIOUS={
 'storypulse_webapps.py':{'0a601e83fdd5d454a45b9cf7f909e84ce08c3ae9dc4941370e6ce8376c473836','64a1d9956beb358cb6786ad7adfac9cb0d1af5006cdfccf4afd9081afcd68c7a','942f2ed9467ca4651c86ce6eedc2848360c515c45842c6c62722d5d9d980db17','9ff86c1f53b1f82cc98e986506ae52be0752d02e2be48e5fcd3b3e2c6c2ea7f2','ec73c347cfe0a5b700f6e25308109bf6a5819c23aebc77ff084af42b6c68d434'},
 'storypulse_catalog.py':{'85c90f3f611a980830d7613bd95b60787edca87406951345287e07f4ff3784d0','8c52630ee1f1f61766a3802cc4da6e4d90ccab98134b98a11294b259d86eff6a','8d9f508658611427fdaf3f4fc8a1e867b6dab0cc98fa09bc15be615dd4c80089'},
 'storypulse_mysql.py':{'7c77f1827105da1a0946b24f7628d3c1688010fe820695512d95a6d3e0f1fb9e','ac43f649b23d9afe0527017b5a8e819859f03a3d467a6e1438861d501c2ef9dc','bf5151815b31ab61f8df076d5bfd3e1c6bcdf8c4b6329eee79ebfb1e27b9ff8d','d77811ac24978a3e86a7471ad6c8c349c9366644dd81ea2fe47b8c96cd0b48fd'},
 'storypulse_platform.py':{'400fcd835f5988018f8227a0daca934f2398412978e0e3170c1fe26194fb0ca5','dee12ff6f381738827232b3fb3bd7aaf5598fdde5764ca041b378c9f14e693f2'},
 'storypulse_versions.py':{'615e21eaa8567babdb76f06fca5fec04b82cfe42a784ffe945349a8bc8653b84','8a252a4649a5272c0ca8407f468fdbfc421c43d4efbf232a5bc3406a4c6253bd'},
 'storypulse_uninstall.py':{'39ab5379ebda8f91dc6faf78a8671bec8a86dcb2607c8f9b817be004a79e5623','5ddacd22b6249e409fa72c4d5071ecca04aea2b35b88421ca209cb102fffcc60','b9c9a73bfb223bc51e8aadf6e2f52bc449b54a46f8431a734e6bfac1ac195cc9','bf83a7c05aa3d64b6a5866a57e9eab55f0e541d105f025dc78e61991f511544f'},
}
def sha(data):return hashlib.sha256(data).hexdigest()
def content_sha(data):return sha(data.replace(b'\r\n',b'\n'))
def safe(path,directory=False):
 path=Path(path);info=path.lstat()
 if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)):
  raise RuntimeError('La ruta del módulo web no tiene permisos seguros. No se modificó.')
 return info
def replace(path,data,info):
 fd,name=tempfile.mkstemp(prefix='.panel-web-runtime-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  os.chmod(name,stat.S_IMODE(info.st_mode));os.chown(name,info.st_uid,info.st_gid);os.replace(name,path)
 finally:
  if os.path.exists(name):os.unlink(name)
def install(payload):
 if os.geteuid()!=0:raise RuntimeError('Falta permiso para actualizar el instalador web del panel.')
 if not isinstance(payload,dict) or set(payload)!={'modules'} or not isinstance(payload['modules'],list) or len(payload['modules'])!=len(PREVIOUS):raise ValueError('Paquete de módulos no válido.')
 modules=payload['modules']
 if any(not isinstance(x,dict) or set(x)!={'name','sha256','data'} for x in modules) or {x['name'] for x in modules}!=set(PREVIOUS):raise ValueError('Sólo se permiten los seis módulos fijos de servicios web y base de datos del panel.')
 staged=[]
 for row in modules:
  if not isinstance(row['data'],str) or len(row['data'])>512000:raise ValueError('Módulo demasiado grande.')
  data=base64.b64decode(row['data'],validate=True)
  if sha(data)!=row['sha256']:raise ValueError('El módulo no coincide con el paquete local.')
  ast.parse(data.decode('utf-8'));staged.append((row['name'],data,row['sha256']))
 for directory in [ROOT,*ROOT.parents]:safe(directory,True)
 fd=os.open(LOCK,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as handle:
  safe(LOCK)
  try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise RuntimeError('Hay otra instalación en curso. Esperá a que termine.') from None
  changes=[]
  for name,data,digest in staged:
   target=ROOT/name;info=safe(target);before=target.read_bytes();current=sha(before)
   # Treat Windows CRLF and Linux LF as the same source, never other edits.
   if current==digest or content_sha(before)==content_sha(data):continue
   if current not in PREVIOUS[name] and content_sha(before) not in PREVIOUS[name]:raise RuntimeError('El módulo web remoto '+name+' tiene una versión ajena al panel. Se conservó sin sobrescribir.')
   changes.append((target,data,info,before))
  backup=None;written=[]
  if changes:
   if not BACKUPS.exists():
    safe(BACKUPS.parent,True);BACKUPS.mkdir(mode=0o700)
   safe(BACKUPS,True)
   backup=BACKUPS/(time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+uuid.uuid4().hex)
   backup.mkdir(mode=0o700)
   for target,_,_,_ in changes:shutil.copy2(target,backup/target.name)
   try:
    for target,data,info,before in changes:
     written.append((target,info,before));replace(target,data,info)
    if any(content_sha((ROOT/name).read_bytes())!=content_sha(data) for name,data,_ in staged):raise RuntimeError('No se pudo verificar la actualización del módulo web.')
   except Exception:
    for target,info,before in reversed(written):replace(target,before,info)
    raise
 return {'ok':True,'updated':[target.name for target,_,_,_ in changes],'hashes':{name:digest for name,_,digest in staged}}
def main(encoded):
 try:
  if not isinstance(encoded,str) or len(encoded)>1500000:raise ValueError('Paquete de actualización no válido.')
  result=install(json.loads(base64.b64decode(encoded,validate=True)))
  print(json.dumps(result))
 except Exception as error:
  print(json.dumps({'ok':False,'error':str(error)[:600]}));raise SystemExit(1)
