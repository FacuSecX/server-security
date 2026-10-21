"""Small server snapshots and one fixed, explicitly confirmed reboot operation."""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

PROC = Path('/proc')
MACHINE_ID = Path('/etc/machine-id')
STATE_DIR = Path('/run/storypulse-system')
STATE = STATE_DIR / 'reboot.json'
LOCK = Path('/run/lock/storypulse-system.lock')
BUSY_LOCKS = tuple(Path('/run/lock') / name for name in (
    'storypulse-securityctl.lock','storypulse-ftp.lock','storypulse-mysql.lock',
    'storypulse-cleanup.lock','storypulse-ssh-report.lock'))
REBOOT_COMMAND = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=storypulse-panel-reboot',
                  '--on-active=5s', '--timer-property=AccuracySec=1s',
                  '--property=Type=oneshot', '/usr/bin/systemctl', 'reboot']


class SystemError(RuntimeError):
    pass


def run(command, timeout=8):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=timeout,
                            env={**os.environ, 'LC_ALL':'C'})
    if result.returncode:
        raise SystemError(result.stderr.strip()[-500:] or 'No se pudo consultar el sistema.')
    return result.stdout


def identity():
    boot = (PROC/'sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    return {'server_id':hashlib.sha256(MACHINE_ID.read_bytes().strip()).hexdigest()[:32],
            'boot_id':boot, 'hostname':socket.gethostname()}


def public_ips(rows, preferred=''):
    values=[]
    for interface in rows:
        if interface.get('operstate') not in ('UP','UNKNOWN'):
            continue
        for item in interface.get('addr_info',[]):
            if item.get('scope') != 'global':continue
            try:address=ipaddress.ip_address(item.get('local',''))
            except ValueError:continue
            if address.is_global and str(address) not in values:values.append(str(address))
    return sorted(values,key=lambda value:(value!=preferred,ipaddress.ip_address(value).version,value))


def addresses():
    try:
        rows=json.loads(run(['/usr/sbin/ip','-j','address','show','up']))
        preferred=''
        try:
            route=json.loads(run(['/usr/sbin/ip','-j','route','get','1.1.1.1']))
            if route:preferred=route[0].get('prefsrc','')
        except (SystemError,ValueError):pass
        return public_ips(rows,preferred)
    except (SystemError,ValueError):return []


def load_state():
    try:
        value=json.loads(STATE.read_text(encoding='utf8'))
        if not isinstance(value,dict):raise ValueError('invalid state')
        return value
    except FileNotFoundError:return {}
    except (ValueError,OSError) as exc:raise SystemError('No se pudo leer el estado de reinicio.') from exc


def save_state(value):
    STATE_DIR.mkdir(mode=0o700,exist_ok=True)
    if STATE_DIR.is_symlink() or STATE.is_symlink():raise SystemError('Ruta de reinicio insegura.')
    fd,temporary=tempfile.mkstemp(prefix='.reboot-',dir=STATE_DIR)
    try:
        with os.fdopen(fd,'w',encoding='utf8') as output:
            os.fchmod(output.fileno(),0o600);json.dump(value,output);output.flush();os.fsync(output.fileno())
        os.replace(temporary,STATE)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


@contextlib.contextmanager
def lock(path):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(descriptor,'a') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise SystemError('Hay una operación del servidor en curso. Esperá su resultado.') from exc
        yield


def reboot_status(current):
    state=load_state()
    if state.get('boot_id')!=current['boot_id']:return {'status':'idle'}
    status=state.get('status','idle')
    if status in ('scheduled','scheduling'):
        age=time.time()-state.get('requested_at',time.time())
        if age>15:
            properties={}
            for line in run(['/usr/bin/systemctl','show','storypulse-panel-reboot.service',
                             '-p','LoadState','-p','ActiveState','-p','Result']).splitlines():
                key,separator,value=line.partition('=')
                if separator:properties[key]=value
            if properties.get('ActiveState')=='failed' or properties.get('LoadState')=='not-found' or age>120:
                return {'status':'error','message':'No se confirmó el reinicio del servidor. Revisá su estado antes de reintentar.'}
    return {'status':status if status in ('scheduled','scheduling','error') else 'idle',
            'requested_at':state.get('requested_at',0),'message':state.get('message','')}


def metrics():
    current=identity();cpu=(PROC/'stat').read_text(encoding='ascii').splitlines()[0].split()[1:9]
    ticks=[int(value) for value in cpu]
    if len(ticks)<5:raise SystemError('Muestra de CPU incompleta.')
    memory={}
    for line in (PROC/'meminfo').read_text(encoding='ascii').splitlines():
        name,_,value=line.partition(':')
        memory[name]=int(value.split()[0])*1024
    total=memory.get('MemTotal',0);available=memory.get('MemAvailable',0)
    disk=shutil.disk_usage('/')
    model='Procesador virtual'
    for line in (PROC/'cpuinfo').read_text(encoding='utf8',errors='replace').splitlines():
        key,_,value=line.partition(':')
        if key.strip() in ('model name','Hardware'):
            model=value.strip()[:180];break
    ips=addresses()
    return {'ok':True,**current,'distribution':distribution_info(),'generated_at':int(time.time()),'public_ip':ips[0] if ips else '',
            'public_ips':ips,'cpu':{'cores':os.cpu_count() or 1,'model':model,'total_ticks':sum(ticks),'idle_ticks':ticks[3]+ticks[4]},
            'memory':{'total':total,'used':max(0,total-available),'available':available},
            'disk':{'total':disk.total,'used':disk.used,'free':disk.free},
            'uptime_seconds':int(float((PROC/'uptime').read_text(encoding='ascii').split()[0])),
            'reboot':reboot_status(current)}


def distribution_info():
    import platform
    path=Path('/etc/os-release')
    if not path.is_file():return {'id':'unknown','version':'','name':'No disponible','architecture':platform.machine()}
    import storypulse_platform as linux
    result=linux.detect(path)
    return {'id':result['id'],'version':result['version'],'name':result['name'],
            'architecture':platform.machine(),'package_manager':result['family']}


def plan(body):
    if body!={}:raise SystemError('La preparación de reinicio no acepta comandos ni parámetros.')
    with lock(LOCK):
        current=identity()
        if reboot_status(current)['status'] in ('scheduled','scheduling'):raise SystemError('Ya hay un reinicio solicitado.')
        ticket=secrets.token_hex(32);expires=int(time.time())+120;ips=addresses()
        save_state({**current,'ticket':ticket,'expires_at':expires,'status':'planned'})
        return {'ok':True,**current,'public_ip':ips[0] if ips else '',
                'ticket':ticket,'expires_at':expires,'delay_seconds':5}


def reboot(body):
    if not isinstance(body,dict) or set(body)!={'ticket','confirm','server_id','boot_id'}:
        raise SystemError('Solicitud de reinicio inválida.')
    if body['confirm'] is not True or not isinstance(body['ticket'],str) or not re.fullmatch('[a-f0-9]{64}',body['ticket']):
        raise SystemError('Falta la confirmación de reinicio.')
    with contextlib.ExitStack() as stack:
        stack.enter_context(lock(LOCK))
        for path in BUSY_LOCKS:stack.enter_context(lock(path))
        current=identity();state=load_state()
        if state.get('status')!='planned' or state.get('expires_at',0)<=time.time() or not secrets.compare_digest(state.get('ticket',''),body['ticket']):
            raise SystemError('La confirmación venció o ya se utilizó. Revisá el reinicio de nuevo.')
        for key in ('server_id','boot_id'):
            if state.get(key)!=current[key] or body[key]!=current[key]:raise SystemError('El servidor o su arranque cambió. Confirmá nuevamente.')
        state.update(status='scheduling',ticket='',requested_at=int(time.time()));save_state(state)
        try:
            run(REBOOT_COMMAND,timeout=15)
        except (OSError,SystemError,subprocess.TimeoutExpired) as exc:
            state.update(status='error',message='No se pudo programar el reinicio.');save_state(state)
            raise SystemError(state['message']) from exc
        state['status']='scheduled';save_state(state)
        return {'ok':True,'status':'scheduled','delay_seconds':5,**current,'requested_at':state['requested_at']}
