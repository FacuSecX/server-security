"""Shared, fixed web-service prerequisites; no caller-selected ports or commands."""
import os,stat,time
from pathlib import Path
import storypulse_ports as ports
import storypulse_uninstall as removal

repair_monitors=lambda family:None

def web_preflight():
    import storypulse_cloudflare as cloudflare
    if cloudflare.enabled():
        cloudflare.assert_firewall();return
    snapshot=ports.read_snapshot()
    for port in (80,443):
        families=(4,6) if snapshot['ipv6'] else (4,)
        if all(ports.firewall_state(snapshot['rules'],port,'tcp',family,snapshot['default'],snapshot['active'])=='open' for family in families):continue
        reason=ports.mutation_error(snapshot,port,'tcp')
        if reason:raise RuntimeError('No se pudo preparar el puerto web '+str(port)+': '+reason)

def open_web_ports():
    import fcntl
    with removal.FIREWALL_LOCK.open('a') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Hay otro cambio de firewall en curso. Reintentá la instalación.') from None
        import storypulse_cloudflare as cloudflare
        if cloudflare.enabled():
            cloudflare.assert_firewall();return
        web_preflight()
        for port in (80,443):
            snapshot=ports.read_snapshot();families=(4,6) if snapshot['ipv6'] else (4,)
            if all(ports.firewall_state(snapshot['rules'],port,'tcp',family,snapshot['default'],snapshot['active'])=='open' for family in families):continue
            ports.apply(dict(port=port,protocol='tcp',action='open',revision=snapshot['revision'],confirm=True),repair_monitors)

def runtime_directory(name):
    if name not in ('server-monitor-webphp','server-monitor-webnginx'):raise RuntimeError('Directorio temporal no permitido.')
    path=Path('/run')/name;removal.safe_path(path)
    path.mkdir(parents=True,exist_ok=True,mode=0o755)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('El directorio temporal del servicio no es seguro.')
    path.chmod(0o755)
    return path

def php_flags(profile):
    return [item for module in ('mysqli','pdo_mysql','gd','intl','curl','zip') for item in ('-d','extension='+module)] if profile['family']=='arch' else []

def verify_php_modules(run,profile,binary):
    output=run([binary,*php_flags(profile),'-m']).stdout
    loaded={line.strip().lower() for line in output.splitlines()}
    required={'mysqli','pdo_mysql','mbstring','curl','dom','gd','intl','zip','openssl','json','session'}
    missing=sorted(required-loaded)
    if missing:raise RuntimeError('PHP-FPM no cargó las extensiones necesarias: '+', '.join(missing)+'.')

def wait_service(run,unit,*,socket=None):
    for attempt in range(30):
        active=run(['systemctl','is-active',unit],check=False).stdout.strip()=='active'
        if active and (socket is None or Path(socket).is_socket()):
            # Catch immediate crashes of Type=simple after systemctl has returned.
            time.sleep(.15)
            if run(['systemctl','is-active',unit],check=False).stdout.strip()=='active':return
        time.sleep(.2)
    detail=run(['systemctl','show',unit,'--property=Result,ExecMainStatus'],check=False).stdout.strip()
    raise RuntimeError('El servicio '+unit+' no quedó listo para responder. '+detail)
