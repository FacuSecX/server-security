# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

STATE_DIR = Path('/var/lib/storypulse-cleanup')
STATE_FILE = STATE_DIR / 'schedules.json'
MARKER_FILE = STATE_DIR / 'reset.json'
LOCK_FILE = Path('/run/lock/storypulse-cleanup.lock')
REPORT_LOCK = Path('/run/lock/storypulse-ssh-report.lock')
LOGS = tuple(Path(p) for p in (
    '/var/log/ufw.log', '/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log',
    '/var/log/nginx/access.log',
    '/var/log/storypulse-security-blocks.jsonl'))
REPORT_DIR = Path('/var/lib/storypulse-security/Informes/SSH/archivos')
MANAGED_REPORT_DIR = Path('/var/lib/storypulse-security/Informes/SSH/archivos')
LEGACY_REPORT_DIR = Path('/var/lib/storypulse-security/reports')
REPORT_RE = re.compile(r'^ssh_(?:reporte|eventos)_[A-Za-z0-9_-]+\.(?:txt|csv)$')
SUFFIX_RE = re.compile(r'^\.(?:[1-9][0-9]{0,3}(?:\.gz)?|[0-9]{8}(?:\.gz)?)$')
MAX_SCHEDULES = 100
SCOPE = 'system-journal-and-panel-history-v1'


class CleanupError(RuntimeError):
    pass


def run(args, timeout=90):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=timeout,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise CleanupError(f'{args[0]}: {result.stderr.strip()[-500:] or "falló la operación"}')
    return result.stdout


@contextlib.contextmanager
def locked(path=None):
    path = path or LOCK_FILE
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CleanupError('Hay una limpieza o un reporte en curso. Esperá su resultado.') from exc
        yield


def atomic_json(path, data, mode):
    STATE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    if STATE_DIR.is_symlink() or path.is_symlink():
        raise CleanupError('Ruta de estado insegura.')
    fd, temporary = tempfile.mkstemp(prefix='.cleanup-', dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            os.fchmod(output.fileno(), mode)
            json.dump(data, output, ensure_ascii=False, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load():
    if not STATE_FILE.exists():
        return {'version': 1, 'schedules': [], 'last_run': None}
    try:
        state = json.loads(STATE_FILE.read_text(encoding='utf-8'))
        if state.get('version') != 1 or not isinstance(state.get('schedules'), list):
            raise ValueError('formato inválido')
        return state
    except (ValueError, OSError) as exc:
        raise CleanupError('No se pudo leer la programación. No se borró ningún dato.') from exc


def marker():
    if not MARKER_FILE.exists():
        return None
    return json.loads(MARKER_FILE.read_text(encoding='utf-8'))


def regular(path):
    
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise CleanupError('Se encontró un enlace simbólico en un registro; limpieza cancelada.')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CleanupError('Se encontró un registro que no es un archivo regular independiente.')
    return info


def targets():
    found = []
    for base in LOGS:
        if base.exists() or base.is_symlink():
            regular(base)
            found.append((base, False))
        if base.parent.exists():
            for path in base.parent.glob(base.name + '.*'):
                if SUFFIX_RE.fullmatch(path.name[len(base.name):]):
                    regular(path)
                    found.append((path, True))
    for directory in dict.fromkeys((REPORT_DIR, MANAGED_REPORT_DIR, LEGACY_REPORT_DIR)):
        if directory.exists():
            for path in directory.iterdir():
                if REPORT_RE.fullmatch(path.name):
                    regular(path)
                    found.append((path, True))
    return found


def storage():
    files = targets()
    output = run(['journalctl', '--disk-usage'])
    match = re.search(r'take up\s+([0-9.]+)\s*([KMGTPE]?)B?', output)
    if not match:
        raise CleanupError('No se pudo medir el journal del servidor.')
    journal = int(float(match[1]) * 1024 ** (' KMGTPE'.index(match[2]) if match[2] else 0))
    disk = shutil.disk_usage('/')
    details = [{'path': str(path), 'bytes': regular(path).st_size, 'rotated_or_report': remove}
               for path, remove in files]
    other = sum(row['bytes'] for row in details)
    return {'journal_bytes': journal, 'files_bytes': other, 'total_bytes': journal + other,
            'files': details, 'disk': {'total': disk.total, 'used': disk.used, 'free': disk.free}}


def status():
    with locked():
        state = load()
        return {'ok': True, **state, 'storage': storage(), 'reset': marker(),
                'server_time': int(time.time()), 'scope': SCOPE,
                'timer_active': run(['systemctl', 'show', 'storypulse-cleanup.timer', '-p', 'ActiveState', '--value']).strip() == 'active'}


def payload(body, now=None):
    now = int(time.time()) if now is None else now
    if not isinstance(body, dict) or body.get('action') not in ('clean', 'schedule', 'cancel', 'delete'):
        raise CleanupError('Acción de limpieza no permitida.')
    result = {'action': body['action']}
    if body['action'] == 'schedule':
        when, interval = body.get('at'), body.get('interval_days', 0)
        if type(when) is not int or when < now + 60 or when > now + 5 * 366 * 86400:
            raise CleanupError('Elegí una fecha futura, al menos un minuto después de ahora.')
        if type(interval) is not int or interval not in (0, 1, 2, 3, 5, 7, 14, 30):
            raise CleanupError('Frecuencia de limpieza inválida.')
        result.update(at=when, interval_days=interval)
    elif body['action'] in ('cancel', 'delete'):
        identity = body.get('id')
        if not isinstance(identity, str) or not re.fullmatch('[a-f0-9]{32}', identity):
            raise CleanupError('Programación inválida.')
        result['id'] = identity
    return result


def revision(state, request):
    return hashlib.sha256(json.dumps({'scope': SCOPE, 'state': state, 'request': request}, sort_keys=True).encode()).hexdigest()


def make_plan(body, state):
    request = payload(body)
    if request['action'] == 'schedule' and len(state['schedules']) >= MAX_SCHEDULES:
        raise CleanupError('Se alcanzó el límite de 100 programaciones. Eliminá las antiguas.')
    if request['action'] in ('cancel', 'delete'):
        row = next((s for s in state['schedules'] if s['id'] == request['id']), None)
        if not row:
            raise CleanupError('La programación ya no existe.')
        if row['status'] == 'RUNNING':
            raise CleanupError('La limpieza ya empezó y no puede cancelarse.')
        if request['action'] == 'cancel' and row['status'] != 'PENDING':
            raise CleanupError('Sólo se pueden cancelar programaciones pendientes.')
    return {'ok': True, 'request': request, 'revision': revision(state, request), 'scope': SCOPE,
            'warning': 'Elimina el journal COMPLETO del sistema (todos los servicios), los logs de seguridad/web y los reportes SSH. Reinicia el historial y caché del panel. Es irreversible. Conserva reglas, servicios, usuarios, bases de datos y archivos de historias.',
            'storage': storage() if request['action'] in ('clean', 'schedule') else None}


def plan(body):
    with locked():
        return make_plan(body, load())


def counter_baseline():
    result = {}
    pattern = re.compile(r'^\[(\d+):(\d+)\].*--match-set uvp_(.+?)([46]) src .*--comment "UFW-VPS: [^"]+".*-j DROP\s*$')
    for binary in ('iptables-save', 'ip6tables-save'):
        for line in run([binary, '-c']).splitlines():
            match = pattern.search(line)
            if not match:
                continue
            item = result.setdefault(match[3], {'packets': 0, 'bytes': 0, 'ipv4_packets': 0, 'ipv6_packets': 0})
            item['packets'] += int(match[1]); item['bytes'] += int(match[2])
            item['ipv' + match[4] + '_packets'] += int(match[1])
    return result


@contextlib.contextmanager
def parent_descriptor(path):
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def clean():
    
    with locked(REPORT_LOCK):
        files = targets()  
        before = storage()['total_bytes']
        baseline = counter_baseline()
        run(['journalctl', '--sync'])
        
        run(['journalctl', '--rotate', '--vacuum-size=1'])
        for path, remove in files:
            previous = regular(path)
            with parent_descriptor(path) as directory:
                fd = os.open(path.name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    current = os.fstat(fd)
                    if (current.st_dev, current.st_ino) != (previous.st_dev, previous.st_ino) or current.st_nlink != 1 or not stat.S_ISREG(current.st_mode):
                        raise CleanupError('Un registro cambió durante la limpieza. Reintentá.')
                    if remove:
                        os.unlink(path.name, dir_fd=directory)
                    else:
                        os.ftruncate(fd, 0)
                        os.fsync(fd)
                finally:
                    os.close(fd)
        reset = {'id': uuid.uuid4().hex, 'cutoff': int(time.time()) + 1,
                 'completed_at': int(time.time()), 'providers': baseline,
                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        atomic_json(MARKER_FILE, reset, 0o644)
        after = storage()['total_bytes']
        return {'reset': reset, 'freed_bytes': max(0, before - after), 'remaining_bytes': after}


def execute(state, row):
    
    row.update(status='RUNNING', started_at=int(time.time()), error='')
    atomic_json(STATE_FILE, state, 0o600)
    try:
        result = clean()
        ended = int(time.time())
        row.update(status='COMPLETED', finished_at=ended, last_finished_at=ended,
                   runs=row.get('runs', 0) + 1, freed_bytes=result['freed_bytes'])
        state['last_run'] = {'id': row['id'], 'status': 'COMPLETED', 'finished_at': ended, **result}
        if row.get('interval_days'):
            step = row['interval_days'] * 86400
            row['at'] += max(1, (ended - row['at']) // step + 1) * step
            row.update(status='PENDING', finished_at=None)
    except Exception as exc:
        row.update(status='FAILED', finished_at=int(time.time()), error=str(exc)[:600])
        state['last_run'] = {'id': row['id'], 'status': 'FAILED', 'error': row['error'], 'finished_at': row['finished_at']}
    atomic_json(STATE_FILE, state, 0o600)


def change(body):
    with locked():
        state = load()
        reviewed = make_plan(body, state)
        if body.get('confirm') is not True or body.get('revision') != reviewed['revision']:
            raise CleanupError('La programación cambió o falta confirmación. Revisá de nuevo.')
        request = reviewed['request']; action = request['action']
        if action == 'clean':
            row = {'id': uuid.uuid4().hex, 'action': 'manual', 'status': 'PENDING', 'at': int(time.time()), 'interval_days': 0}
            
            state['schedules'].append(row)
            execute(state, row)
            state['schedules'].remove(row)
            atomic_json(STATE_FILE, state, 0o600)
            if row['status'] == 'FAILED':
                raise CleanupError(row['error'])
        elif action == 'schedule':
            if run(['systemctl', 'show', 'storypulse-cleanup.timer', '-p', 'ActiveState', '--value']).strip() != 'active':
                raise CleanupError('El temporizador del servidor no está activo. No se guardó la programación.')
            state['schedules'].append({'id': uuid.uuid4().hex, 'status': 'PENDING', 'at': request['at'],
                                      'interval_days': request['interval_days'], 'created_at': int(time.time()), 'runs': 0})
        elif action == 'cancel':
            next(s for s in state['schedules'] if s['id'] == request['id']).update(status='CANCELLED', cancelled_at=int(time.time()))
        elif action == 'delete':
            state['schedules'] = [s for s in state['schedules'] if s['id'] != request['id']]
        atomic_json(STATE_FILE, state, 0o600)
        return {'ok': True, 'action': action, 'reset': marker(), **state}


def tick():
    with locked():
        state = load()
        
        now = int(time.time())
        for row in state['schedules']:
            if row['status'] == 'RUNNING':
                row.update(status='FAILED', error='El servidor interrumpió la limpieza. Revisá antes de reintentar.', finished_at=now)
        due = [s for s in state['schedules'] if s['status'] == 'PENDING' and s['at'] <= now]
        if due:
            execute(state, due[0])
            for row in due[1:]:
                source = due[0]
                row.update(status='COMPLETED' if state['last_run']['status'] == 'COMPLETED' else 'FAILED',
                           finished_at=state['last_run']['finished_at'], error=state['last_run'].get('error', ''),
                           last_finished_at=state['last_run']['finished_at'], runs=row.get('runs', 0)+1)
                if row['status'] == 'COMPLETED' and row.get('interval_days'):
                    step = row['interval_days'] * 86400
                    row['at'] += max(1, (now - row['at']) // step + 1) * step
                    row.update(status='PENDING', finished_at=None)
        if due or any(s['status'] == 'FAILED' and s.get('finished_at') == now for s in state['schedules']):
            atomic_json(STATE_FILE, state, 0o600)
        return {'ok': True, 'executed': len(due)}
