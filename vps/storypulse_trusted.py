# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import hashlib
import ast
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ENV_FILES=(Path('/etc/storypulse-alerts/telegram.env'),Path('/etc/storypulse-security/alerts.env'))
LOCK=Path('/run/lock/storypulse-trusted.lock')
LEGACY=Path('/usr/local/sbin/storypulse-alerts.py')
DYNAMIC_MARKER='STORYPULSE_DYNAMIC_TRUSTED_V1'
SSH_POLICY_MARKER='STORYPULSE_DYNAMIC_SSH_POLICY_V2'
SETTING=re.compile(r'^[ \t]*(?:export[ \t]+)?TRUSTED_IPS[ \t]*=[ \t]*(.*?)[ \t]*$',re.M)

class TrustedError(RuntimeError):pass

def canonical(value, *, network=False):
    if not isinstance(value,str) or len(value)>80 or '%' in value:raise TrustedError('Indicá una IPv4 o IPv6 válida.')
    try:
        if '/' in value:
            if not network:raise ValueError()
            address=ipaddress.ip_network(value,strict=True)
            if address.prefixlen==0:raise ValueError()
            if address.prefixlen==address.max_prefixlen:return str(address.network_address)
            return str(address)
        address=ipaddress.ip_address(value.strip())
        if address.is_unspecified or address.is_multicast:raise ValueError()
        if getattr(address,'ipv4_mapped',None):address=address.ipv4_mapped
        return str(address)
    except ValueError:raise TrustedError('Indicá una IP concreta, sin comodines ni comandos.') from None

def read_setting(paths=None):
    for path in ENV_FILES if paths is None else paths:
        path=Path(path)
        try:descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        except FileNotFoundError:continue
        except OSError:raise TrustedError('No se pudo leer de forma segura el archivo de IP autorizadas.') from None
        with os.fdopen(descriptor,'r',encoding='utf-8',newline='') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>65536 or info.st_uid!=0 or info.st_mode&0o022:
                raise TrustedError('El archivo de IP autorizadas debe pertenecer a root y tener permisos seguros.')
            text=stream.read(65537)
        matches=list(SETTING.finditer(text))
        if not matches:continue
        if len(matches)!=1:raise TrustedError('TRUSTED_IPS está duplicado en el archivo de entorno.')
        raw=matches[0].group(1).strip()
        if raw[:1] in ('"',"'"):
            if len(raw)<2 or raw[-1]!=raw[0]:raise TrustedError('Revisá las comillas de TRUSTED_IPS.')
            raw=raw[1:-1]
        else:raw=raw.split('#',1)[0].strip()
        values=[v for v in re.split(r'[,;\s]+',raw) if v]
        if len(values)>256:raise TrustedError('La lista admite hasta 256 IP o redes.')
        values=sorted(set(canonical(v,network=True) for v in values))
        return path,text,values,info
    raise TrustedError('Falta configurar TRUSTED_IPS en el VPS; ejecutá el instalador actualizado.')

def policy(paths=None):
    try:
        path,text,values,info=read_setting(paths)
        revision=hashlib.sha256((str(path)+'\n'+'\n'.join(values)).encode()).hexdigest()
        return dict(ready=True,source=str(path),authorized_count=len(values),authorized_ips=values,revision=revision)
    except (TrustedError,OSError,UnicodeError):
        return dict(ready=False,source='',authorized_ips=[],error='Revisá TRUSTED_IPS y los permisos del archivo de IP autorizadas.')

def status():
    result=policy()
    if not result['ready']:raise TrustedError(result['error'])
    return dict(ok=True,**result)

def validate(body, *, apply=False):
    allowed={'action','ip'}|({'confirm','revision'} if apply else set())
    if not isinstance(body,dict) or set(body)!=allowed or body.get('action') not in ('add','remove'):
        raise TrustedError('La operación sólo permite añadir o quitar una IP.')
    value=canonical(body.get('ip'),network=body['action']=='remove')
    if apply and (body.get('confirm') is not True or not isinstance(body.get('revision'),str) or not re.fullmatch('[a-f0-9]{64}',body['revision'])):
        raise TrustedError('Revisá y confirmá el cambio de IP autorizadas.')
    return dict(action=body['action'],ip=value)

def plan(body):
    action=validate(body);current=status();exists=action['ip'] in current['authorized_ips']
    if action['action']=='add' and exists:raise TrustedError('Esa IP ya está autorizada.')
    if action['action']=='remove' and not exists:raise TrustedError('Esa IP ya no está en la lista.')
    if action['action']=='add' and len(current['authorized_ips'])>=256:raise TrustedError('La lista alcanzó el límite de 256 entradas.')
    effect=('Sus accesos autenticados no generarán alertas.' if action['action']=='add' else 'Sus próximos accesos autenticados generarán alertas.')
    return dict(ok=True,**action,revision=current['revision'],effect=effect+' Esta lista no cambia permisos de acceso ni reglas del firewall.')

def atomic(path,data,mode=0o600):
    fd,name=tempfile.mkstemp(prefix='.authorized-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),0,0)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def prepare_monitor():
    
    if not LEGACY.exists():return dict(ok=True,changed=False,installed=False)
    info=LEGACY.stat()
    if LEGACY.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:raise TrustedError('El monitor existente tiene permisos inseguros.')
    text=LEGACY.read_text(encoding='utf-8')
    tree=ast.parse(text)
    notify=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='notify_ssh_success'),None)
    if DYNAMIC_MARKER in text and (notify is None or SSH_POLICY_MARKER in text) and not any(v in text for v in ('"Accepted publickey" in message','"Accepted password" in message')):return dict(ok=True,changed=False,installed=True,dynamic=True)
    result=text
    if DYNAMIC_MARKER not in text:
        function=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='trusted_ip_addresses'),None)
        if function is None:return dict(ok=True,changed=False,installed=True,dynamic=False)
        segment=ast.get_source_segment(text,function)
        pattern=r'(?m)^(\s*)raw = os\.environ\.get\("TRUSTED_IPS", ""\)$'
        if len(re.findall(pattern,segment))!=1:return dict(ok=True,changed=False,installed=True,dynamic=False)
        modified=re.sub(pattern,lambda m:m.group(1)+'raw = ",".join(__import__("storypulse_trusted").policy().get("authorized_ips", []))  # '+DYNAMIC_MARKER,segment)
        result=text.replace(segment,modified,1)
    tree=ast.parse(result)
    notify=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='notify_ssh_success'),None)
    if notify is not None and SSH_POLICY_MARKER not in result:
        guards=[node for node in notify.body if isinstance(node,ast.If) and
                (any(isinstance(n,ast.Name) and n.id=='SSH_AUTHORIZED_IP' for n in ast.walk(node.test)) or
                 (isinstance(node.test,ast.Call) and isinstance(node.test.func,ast.Name) and node.test.func.id=='is_tailscale_address'))]
        assign=next((node for node in notify.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ip' for t in node.targets)),None)
        if len(guards)!=2 or assign is None:raise TrustedError('El formato del monitor SSH cambió; no se modificó.')
        lines=result.splitlines(keepends=True);edits=[]
        for guard in guards:
            start=guard.lineno-1
            while start>0 and lines[start-1].lstrip().startswith('#'):start-=1
            edits.append((start,guard.end_lineno,[]))
        edits.append((assign.end_lineno,assign.end_lineno,['    if ip in trusted_ip_addresses():  # '+SSH_POLICY_MARKER+'\n','        return\n']))
        for start,end,replacement in sorted(edits,reverse=True):lines[start:end]=replacement
        result=''.join(lines)
    result=result.replace('"Accepted publickey" in message','message.startswith("Accepted publickey ")').replace('"Accepted password" in message','message.startswith("Accepted password ")')
    ast.parse(result)
    backup=LEGACY.with_name('.storypulse-alerts.before-dynamic.py')
    if not backup.exists():atomic(backup,text.encode(),0o600)
    active=subprocess.run(['systemctl','is-active','storypulse-alerts.service'],capture_output=True,text=True,timeout=8).stdout.strip()=='active'
    try:
        atomic(LEGACY,result.encode(),info.st_mode&0o777)
        if active:subprocess.run(['systemctl','restart','storypulse-alerts.service'],check=True,capture_output=True,timeout=25)
    except Exception:
        atomic(LEGACY,text.encode(),info.st_mode&0o777)
        if active:subprocess.run(['systemctl','restart','storypulse-alerts.service'],capture_output=True,timeout=25)
        raise TrustedError('Se restauró el monitor anterior porque no pudo actualizarse.') from None
    return dict(ok=True,changed=True,installed=True,dynamic=True)

def change(body):
    import fcntl
    action=validate(body,apply=True)
    descriptor=os.open(LOCK,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0),0o600)
    with os.fdopen(descriptor,'a') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0:raise TrustedError('Archivo de bloqueo inseguro.')
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=plan(action)
        if current['revision']!=body['revision']:raise TrustedError('La lista cambió. Actualizá la vista previa.')
        path,text,values,info=read_setting()
        if action['action']=='add':values.append(action['ip'])
        else:values.remove(action['ip'])
        updated=SETTING.sub(lambda m:'TRUSTED_IPS="'+','.join(sorted(values))+'"',text)
        before=text.encode('utf-8')
        dynamic=LEGACY.is_file() and DYNAMIC_MARKER in LEGACY.read_text(encoding='utf-8')
        active=not dynamic and subprocess.run(['systemctl','is-active','storypulse-alerts.service'],capture_output=True,text=True,timeout=8).stdout.strip()=='active'
        if path.read_bytes()!=before:raise TrustedError('El archivo de entorno cambió durante la operación.')
        try:
            atomic(path,updated.encode('utf-8'),info.st_mode&0o777)
            if active:subprocess.run(['systemctl','restart','storypulse-alerts.service'],check=True,capture_output=True,timeout=25)
        except Exception:
            atomic(path,before,info.st_mode&0o777)
            if active:subprocess.run(['systemctl','restart','storypulse-alerts.service'],capture_output=True,timeout=25)
            raise TrustedError('No se pudo aplicar la autorización; se restauró la configuración anterior.') from None
        return dict(**status(),action=action['action'],ip=action['ip'])
