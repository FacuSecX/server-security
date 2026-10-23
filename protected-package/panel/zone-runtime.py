"""Server Security Monitor v3.0 - install only the fixed Zone runtime modules."""
import ast,base64,hashlib,json,os,stat,tempfile,time,sys,shutil
from pathlib import Path
NAMES={'storypulse_zone.py','storypulse_zone_web.py','storypulse_zone_compat.php','storypulse_games.py','storypulse_webapps.py','storypulse_uninstall.py','storypulse_game_cleanup.py'}
def main(encoded):
 try:
  data=json.loads(base64.b64decode(encoded,validate=True));rows=data['modules'];command=data['command'];body=data['body']
  if set(data)!={'modules','command','body'} or command not in ('zone-status','zone-plan','zone-apply','zone-repair','zone-forum-credentials','zone-runtime-check') or not isinstance(rows,list) or len(rows)!=len(NAMES) or {x['name'] for x in rows}!=NAMES:raise ValueError('Operación Zone no válida.')
  root=Path('/usr/local/sbin')
  for p in (root,*root.parents):
   info=p.lstat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Directorio del controlador inseguro.')
  staged=[]
  for row in rows:
   if set(row)!={'name','sha256','data','previous'} or len(row['data'])>600000:raise ValueError('Módulo Zone no válido.')
   content=base64.b64decode(row['data'],validate=True)
   if hashlib.sha256(content).hexdigest()!=row['sha256']:raise ValueError('Módulo Zone modificado.')
   if row['name'].endswith('.py'):ast.parse(content.decode('utf-8'))
   dest=root/row['name']
   current=None
   if dest.exists() or dest.is_symlink():
    info=dest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Módulo remoto inseguro.')
    before=dest.read_bytes();current=hashlib.sha256(before).hexdigest()
    # SSH packages use LF; Git on Windows can retain equivalent CRLF sources.
    normalized=hashlib.sha256(before.replace(b'\r\n',b'\n')).hexdigest()
    expected=hashlib.sha256(content.replace(b'\r\n',b'\n')).hexdigest()
    if current==row['sha256'] or normalized==expected:continue
    if current not in row['previous'] and normalized not in row['previous']:raise RuntimeError('El controlador remoto '+row['name']+' tiene cambios ajenos al paquete. Se conservó.')
   staged.append((dest,content,current))
  # Validate every target before replacing any module in the bundle.
  for dest,content,current in staged:
   if current is not None:
    backup=Path('/var/backups/server-monitor-zone-runtime');backup.mkdir(mode=0o700,exist_ok=True)
    shutil.copy2(dest,backup/(dest.name+'.'+current))
   fd,tmp=tempfile.mkstemp(prefix='.zone-',dir=root)
   try:
    with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
    os.chmod(tmp,0o644);os.replace(tmp,dest)
   finally:
    if os.path.exists(tmp):os.unlink(tmp)
  sys.path.insert(0,str(root))
  if command=='zone-runtime-check':
   print(json.dumps({'ok':True}),flush=True);return
  import storypulse_zone
  print(json.dumps(storypulse_zone.dispatch(command,body)),flush=True)
 except Exception as error:
  message=str(error)
  for key in ('db_password','rcon_password'):
   if isinstance(locals().get('body'),dict) and isinstance(body.get(key),str):message=message.replace(body[key],'[oculto]')
  print(json.dumps({'ok':False,'error':message[:2000]}),flush=True);raise SystemExit(1)
