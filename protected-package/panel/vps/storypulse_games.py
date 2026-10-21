# Server Security Monitor v3.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import contextlib
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import tarfile
import time
import urllib.request

import storypulse_platform as platform
import storypulse_ports as ports
import storypulse_uninstall as removal
import storypulse_game_ftp as game_ftp

BASE = Path('/opt/server-monitor/games/samp')
STATE = Path('/var/lib/storypulse-security/games/samp.json')
COOLDOWN = STATE.with_name('last-action.json')
UNIT = Path('/etc/systemd/system/server-monitor-samp.service')
ROTATE = Path('/etc/logrotate.d/server-monitor-samp')
SERVICE = 'server-monitor-samp.service'
USER = 'sm-samp'
VERSION = '0.3.7-R2-2-1'
URL = 'https://www.gta-multiplayer.cz/downloads/samp037svr_R2-2-1.tar.gz'
DOWNLOAD_URLS = frozenset((URL, URL.replace('://www.', '://')))
SHA256 = '83b274c214aa42331fa147ded69278658816e8f4fdce6f285e3bcd0198e1e596'
COMMENT = 'Server Monitor SAMP'
DEFAULT = dict(hostname='Servidor SA-MP', port=7777, maxplayers=50, gamemode='grandlarc', query=True, chatlogging=True, filterscripts=[], plugins=[])
INTERNAL_FS = 'sm_panel_stats'
STATS_SHA256 = '38b5383fd403e596874eb93644d9042fc3f06a0ce1d569f49039294c66bb5b32'
STATS_BASE64 = 'rwMAAODxCAgEAAgAfAEAAHQFAACABwAAgEcAAP////84AAAAUAAAAJgAAADAAAAAwAAAAMgAAADUAAAAygAAAAgAAADdAAAADAEAAPAAAAAAAAAAAAEAAAAAAAAIAQAAAAAAABEBAAAAAAAAGwEAAAAAAAApAQAAAAAAADsBAAAAAAAAQgEAAAAAAABIAQAAAAAAAE8BAAAAAAAAVgEAAAAAAABbAQAAAAAAAGEBAAAAAAAAZgEAAAAAAABrAQAABAAAQHMBAAAfAE9uRmlsdGVyU2NyaXB0RXhpdABPbkZpbHRlclNjcmlwdEluaXQAUGFuZWxXcml0ZVN0YXRzAGdldHRpbWUAU2V0VGltZXIAS2lsbFRpbWVyAEdldE1heFBsYXllcnMASXNQbGF5ZXJDb25uZWN0ZWQAZm9ybWF0AGZvcGVuAGZ3cml0ZQBmY2xvc2UAc2FtcABGbG9hdABGaWxlAFRpbWUAcGxheWVycwBGbG9hdAAAAACAeAAugQmAWS0EFyWAWS0EFyWAWS0EFyUnDIB7ACwQLXQPBIEJJwAxggyBCScBJ49QJwgnDIB7ASwQDwCBCQsBMC6BCSgAJwSAewIsCIEJCwEwLoEJJwAsfCcAgHsDLAQReCz7QIBZDvs4gHeEQIEJJwAzgwCBCYBu+zQD+zQEeIBAg1iBCSn7NCcEgHsELAg1g1CBCYBufDOCdCwEgQknBIBZLQQXJYBZLQQXJYBZLQQXJScMgHsALBAtdC0EFyWBBXiBBXwngEgngRCBBfs4JxyAewUsIC18gQksfCcBJ4IkJwiAewYsDBH7NIEJA/s0NYZAgQmBBfs4Kfs0JwiAewcsDIEJKfs0JwSAewgsCIEJLHwnASeDGCcIgHsGLAwR+zCBCQP7MDWHYIEJgQX7OCn7MCcIgHsHLAyBCSn7MCcEgHsILAiBCQsBLIRQMAAAgFCAYYBugGWAbIBXgHKAaYB0gGWAU4B0gGGAdIBzAIB7IoB2IjoxLCKAcIBsgGGAeYBlgHKAcyI6JYBkLCKAbYBhgHiAaYBtgHWAbSI6JYBkLCKAYYB0IjolgGQsIoBzgHSAYYBygHSAZYBkIjolgGSAfQCAc4BlgHKAdoBlgHKAX4BtgG+AboBpgHSAb4BygF+AcIBsgGGAeYBlgHKAc4BfMC6AZIBhgHQAgHOAZYBygHaAZYBygF+AbYBvgG6AaYB0gG+AcoBfgHCAbIBhgHmAZYBygHOAXzEugGSAYYB0AA=='
NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


class GameError(RuntimeError):
    pass


def safe_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise GameError('Ruta del juego no válida.')
    if path!=BASE and BASE not in path.parents:return removal.safe_path(path)
    removal.safe_path(BASE)
    record=checked_record()
    if BASE.exists() and not game_ftp.trusted_root(BASE.stat(),record):raise GameError('La raíz del juego tiene permisos inseguros.')
    for current in (path,*path.parents):
        if current==BASE:break
        try:info=current.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise GameError('El juego contiene una ruta no permitida.')
        if current!=path and not game_ftp.trusted(info,record):raise GameError('Una carpeta del juego tiene permisos inseguros.')
    return path


def run(args, *, timeout=35, check=True, input=None):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, env={'PATH': platform.SAFE_PATH, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
    if len(result.stdout) > 512 * 1024:
        raise GameError('La respuesta del sistema excedió el límite permitido.')
    if check and result.returncode:
        raise GameError('Falló '+args[0]+': '+result.stdout[-1800:])
    return result


def private_dir(path):
    removal.safe_path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != 0:
        raise GameError('La carpeta privada del juego tiene un propietario incorrecto.')
    path.chmod(0o700)


def read_json(path, default=None):
    removal.safe_path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return default
    with os.fdopen(descriptor) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 65536:
            raise GameError('El registro privado del juego no es seguro.')
        return json.load(handle)


def write_json(path, data):
    private_dir(path.parent)
    removal.safe_path(path)
    temporary = path.with_name(path.name+'.'+secrets.token_hex(8))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(data, handle); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def runtime_packages(profile):
    architecture = profile['architecture'].lower()
    if architecture not in ('x86_64', 'amd64', 'i386', 'i686'):
        raise GameError('SA-MP clásico requiere una CPU x86. No se instala el binario x86 en ARM.')
    if profile['family'] == 'apt':
        return ['libc6', 'libstdc++6', 'libgcc-s1'] if architecture in ('i386', 'i686') else ['libc6-i386', 'lib32stdc++6', 'lib32gcc-s1']
    if profile['family'] == 'rpm':
        if int(profile['version'].split('.')[0]) >= 10:
            raise GameError('CentOS Stream 10 no publica las bibliotecas i686 de SA-MP clásico. Usá un entorno x86 compatible; no se mezclan bibliotecas de otra distribución.')
        return ['glibc.i686', 'libstdc++.i686', 'libgcc.i686']
    return ['lib32-glibc', 'lib32-gcc-libs']


def payload(body, apply=False):
    if not isinstance(body, dict) or body.get('game') != 'samp':
        raise GameError('Juego no permitido.')
    action = body.get('action')
    if action not in ('install', 'uninstall', 'start', 'stop', 'restart', 'configure'):
        raise GameError('Acción de juego no permitida.')
    if apply and action == 'configure' and body.get('restart_confirmed') is not True:
        raise GameError('Confirmá el aviso de reinicio y desconexión de jugadores antes de guardar los cambios.')
    if 'ftp' in body:game_ftp.options(body['ftp'])
    allowed = {'game', 'action'} | ({'settings'} if action in ('install', 'configure') else set()) | ({'ftp'} if action=='install' and 'ftp' in body else set()) | ({'ftp_secret'} if apply and action=='install' and body.get('ftp',{}).get('enabled') else set()) | ({'erase_data'} if action == 'uninstall' else set()) | ({'revision', 'confirm'} if apply else set()) | ({'restart_confirmed'} if apply and action == 'configure' else set())
    if set(body) != allowed:
        raise GameError('Parámetros del juego no válidos.')
    result = {key: body[key] for key in allowed if key not in ('revision', 'confirm', 'restart_confirmed')}
    if 'ftp' in body:result['ftp']=game_ftp.options(body['ftp'])
    if action in ('install', 'configure'):
        settings = body['settings']
        if not isinstance(settings, dict) or set(settings) - set(DEFAULT) or not set(DEFAULT) - {'filterscripts', 'plugins'} <= set(settings):
            raise GameError('Configuración incompleta o no permitida.')
        settings = dict(settings)
        existing = settings_from_config(read_config()) if action == 'configure' and any(key not in settings for key in ('filterscripts', 'plugins')) else DEFAULT
        for key in ('filterscripts', 'plugins'):
            settings.setdefault(key, existing[key])
            names = settings[key]
            if not isinstance(names, list) or len(names) > (15 if key == 'filterscripts' else 32) or any(not asset_name(name, key) or name == INTERNAL_FS for name in names) or len(set(names)) != len(names):
                raise GameError('Selección de filterscripts o plugins no válida.')
        hostname = settings['hostname']
        if not isinstance(hostname, str) or not 1 <= len(hostname) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in hostname):
            raise GameError('El nombre debe tener entre 1 y 80 caracteres, sin saltos de línea.')
        try: hostname.encode('utf-8')
        except UnicodeEncodeError: raise GameError('El nombre contiene caracteres no válidos.') from None
        for key, low, high in (('port', 1024, 65535), ('maxplayers', 1, 1000)):
            if type(settings[key]) is not int or not low <= settings[key] <= high:
                raise GameError('Puerto o cantidad de jugadores fuera del intervalo permitido.')
        if not isinstance(settings['gamemode'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', settings['gamemode']):
            raise GameError('Gamemode no válido.')
        if any(type(settings[key]) is not bool for key in ('query', 'chatlogging')):
            raise GameError('Las opciones de registro deben estar activadas o desactivadas.')
        if action == 'install' and (settings['gamemode'] != 'grandlarc' or settings['filterscripts'] or settings['plugins']):
            raise GameError('La instalación inicial utiliza el gamemode grandlarc incluido en SA-MP.')
        result['settings'] = dict(settings)
    if action == 'uninstall' and body['erase_data'] is not True:
        raise GameError('Confirmá el borrado de los archivos del juego.')
    if apply and (body['confirm'] is not True or not isinstance(body['revision'], str) or not re.fullmatch('[a-f0-9]{64}', body['revision'])):
        raise GameError('Primero revisá y confirmá la operación.')
    return result


def checked_record():
    record = read_json(STATE)
    if record is not None and (record.get('game') != 'samp' or record.get('version') != VERSION or type(record.get('uid')) is not int or record['uid'] <= 0):
        raise GameError('El registro de instalación del juego es inválido.')
    if record and record.get('ftp'):
        value=record['ftp']
        if not isinstance(value,dict) or not re.fullmatch('[a-f0-9]{32}',str(value.get('id',''))) or type(value.get('uid')) is not int or value['uid']<=0 or type(record.get('gid')) is not int or record['gid']<=0 or value.get('permissions_ready') is not True:
            raise GameError('El registro FTP del juego no es válido.')
        game_ftp.options(dict(enabled=True,username=value.get('username')))
    return record


def unit_state():
    output = run(['systemctl', 'show', SERVICE, '--property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,LoadState,ExecMainStartTimestampMonotonic'], check=False).stdout
    values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    return dict(active=values.get('ActiveState') == 'active', state=values.get('ActiveState', 'inactive'),
        pid=int(values.get('MainPID', '0')) if values.get('MainPID', '0').isdigit() else 0,
        memory_bytes=int(values['MemoryCurrent']) if values.get('MemoryCurrent', '').isdigit() else None,
        started_at=time.time()-time.monotonic()+int(values['ExecMainStartTimestampMonotonic'])/1000000 if values.get('ExecMainStartTimestampMonotonic', '').isdigit() and int(values['ExecMainStartTimestampMonotonic']) > 0 else None)


def read_config():
    safe_path(BASE/'server.cfg')
    with os.fdopen(os.open(BASE/'server.cfg', os.O_RDONLY | NOFOLLOW)) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not game_ftp.trusted(info,checked_record()) or info.st_size > 16384:
            raise GameError('El archivo de configuración tiene permisos o tamaño no válidos.')
        values = {}
        for line in handle:
            parts = line.strip().split(None, 1)
            if len(parts) == 2: values[parts[0]] = parts[1]
    return values


def settings_from_config(values):
    try:
        return dict(hostname=values['hostname'], port=int(values['port']), maxplayers=int(values['maxplayers']),
            gamemode=values['gamemode0'].split()[0], query=values.get('query') == '1', chatlogging=values.get('chatlogging') == '1',
            filterscripts=[name for name in values.get('filterscripts', '').split() if name != INTERNAL_FS], plugins=values.get('plugins', '').split())
    except (KeyError, ValueError, IndexError):
        raise GameError('La configuración guardada del juego no es válida.') from None


def asset_name(name, kind):
    return isinstance(name, str) and '..' not in name and bool(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}' + (r'\.so' if kind == 'plugins' else ''), name))


def asset_inventory(kind):
    record=checked_record()
    directory = BASE/kind
    safe_path(directory)
    if not directory.exists(): return []
    if not directory.is_dir() or not game_ftp.trusted(directory.stat(),record):
        raise GameError('La carpeta de '+kind+' tiene permisos inseguros.')
    result = []
    for path in sorted(directory.iterdir()):
        if len(result) >= 200: break
        name = path.name if kind == 'plugins' else path.stem
        if kind == 'filterscripts' and name == INTERNAL_FS: continue
        if path.suffix != ('.so' if kind == 'plugins' else '.amx') or not asset_name(name, kind): continue
        reason = ''
        try:
            descriptor = os.open(path, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or not game_ftp.trusted(info,record) or not 0 < info.st_size <= 32*1024*1024:
                    reason = 'Archivo o permisos no válidos.'
                elif kind == 'plugins':
                    header = handle.read(20)
                    if len(header) != 20 or header[:7] != b'\x7fELF\x01\x01\x01' or header[16:20] != b'\x03\x00\x03\x00':
                        reason = 'Se necesita un plugin Linux x86 de 32 bits (.so).'
        except OSError:
            reason = 'No se puede leer el archivo o es un enlace.'
        result.append(dict(name=name, available=not reason, reason=reason))
    return result


def internal_stats(record, started_at=None):
    if not record: return None
    flags = os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK
    try:
        removal.safe_path(BASE)
        with contextlib.ExitStack() as stack:
            base = os.open(BASE, flags | os.O_DIRECTORY);stack.callback(os.close, base)
            if os.fstat(base).st_uid != 0 or os.fstat(base).st_mode & 0o022: return None
            directory = os.open('scriptfiles', flags | os.O_DIRECTORY, dir_fd=base);stack.callback(os.close, directory)
            if not game_ftp.trusted(os.fstat(directory),record,record['uid']): return None
            samples = []
            for name in ('server_monitor_players_0.dat', 'server_monitor_players_1.dat'):
                try:
                    with os.fdopen(os.open(name, flags, dir_fd=directory), 'rb') as handle:
                        info = os.fstat(handle.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != record['uid'] or info.st_mode & 0o022 or not 1 <= info.st_size <= 256: continue
                        data = json.loads(handle.read(257))
                    if not isinstance(data, dict) or set(data) != {'v','players','maximum','at','started'} or any(type(value) is not int for value in data.values()): continue
                    now = time.time()
                    if data['v'] != 1 or not 0 <= data['players'] <= data['maximum'] <= 1000 or data['maximum'] < 1: continue
                    if not 0 <= now-data['at'] <= 20 or not 0 <= now-info.st_mtime <= 20 or not 0 < data['started'] <= data['at']: continue
                    if started_at is not None and data['started'] < int(started_at)-1: continue
                    samples.append(data)
                except (OSError, ValueError, UnicodeError): continue
            if samples:
                sample = max(samples, key=lambda row:row['at'])
                return dict(connected=sample['players'], maximum=sample['maximum'], available=True, reason='', source='internal')
    except (OSError, ValueError): pass
    return None


def player_stats(settings, active, record=None, started_at=None):
    result = dict(connected=0 if not active else None, maximum=settings['maxplayers'], available=not active,
        reason='Servidor apagado.' if not active else '')
    if not active: return result
    private = internal_stats(record, started_at)
    if private is not None: return private
    if not settings['query']:
        result['reason'] = 'Esperando las estadísticas internas del juego.'
        return result
    header = b'SAMP'+socket.inet_aton('127.0.0.1')+struct.pack('<H', settings['port'])+b'i'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.4)
            client.connect(('127.0.0.1', settings['port']))
            client.send(header)
            data = client.recv(4096)
        if len(data) < 28 or data[:11] != header: raise ValueError()
        connected, maximum = struct.unpack_from('<HH', data, 12)
        if not 0 <= connected <= maximum <= 1000 or maximum < 1: raise ValueError()
        offset = 16
        for _ in range(3):
            length = struct.unpack_from('<I', data, offset)[0];offset += 4
            if length > 1024 or offset+length > len(data): raise ValueError()
            offset += length
        if offset != len(data): raise ValueError()
        result.update(connected=connected, maximum=maximum, available=True)
    except (OSError, ValueError, struct.error):
        result['reason'] = 'Sin respuesta a la consulta de jugadores.'
    return result


def status(body):
    if body != {}: raise GameError('La consulta no acepta parámetros.')
    profile = platform.detect()
    try: packages = runtime_packages(profile); compatible = True; notice = ''
    except GameError as error: packages = []; compatible = False; notice = str(error)
    record = checked_record()
    foreign = not record and any(p.exists() or p.is_symlink() for p in (BASE, UNIT, ROTATE))
    result = dict(ok=True, game='samp', distribution=profile['name'], architecture=profile['architecture'],
        compatible=compatible, notice=notice, installed=bool(record), managed=bool(record), conflict=bool(foreign),
        version=record.get('version') if record else None, phase=record.get('phase') if record else None,
        packages=packages, defaults=DEFAULT, settings=None, gamemodes=[], filterscripts=[], plugins=[], players=None, active=False, state='inactive', memory_bytes=None,ftp=game_ftp.status(record))
    if foreign: result['notice'] = 'Hay archivos sin registro de propiedad del panel. No se reemplazarán ni eliminarán.'
    if record:
        result.update(unit_state())
        if (BASE/'server.cfg').exists():
            try: result['settings'] = settings_from_config(read_config())
            except GameError:
                if record.get('phase') == 'ready': raise
        directory = BASE/'gamemodes'
        safe_path(directory)
        if directory.is_dir():
            result['gamemodes'] = sorted(p.stem for p in directory.glob('*.amx') if re.fullmatch(r'[A-Za-z0-9_-]{1,48}', p.stem) and not p.is_symlink() and p.is_file())[:100]
        for kind in ('filterscripts', 'plugins'): result[kind] = asset_inventory(kind)
        if result['settings']: result['players'] = player_stats(result['settings'], result['active'], record, result.get('started_at'))
    return result


def port_check(port, record, current):
    snapshot = ports.read_snapshot()
    if not snapshot['active']: raise GameError('UFW debe estar activo antes de abrir el puerto UDP del juego.')
    if snapshot.get('ssh_error'): raise GameError('No se pudo verificar la protección del acceso SSH.')
    if (port, 'udp') in snapshot['protected'] or (port, 'tcp') in snapshot['protected']: raise GameError('El puerto elegido pertenece a un servicio protegido.')
    forward = read_forwarding()
    if any(item.get('enabled', True) and item.get('port') == port and item.get('protocol') == 'udp' for item in forward):
        raise GameError('El puerto '+str(port)+'/UDP tiene una redirección activa. Elegí otro puerto o eliminá primero esa redirección desde Port Forwarding.')
    own_port = current.get('port') if record else None
    for item in snapshot['sockets']:
        if item.get('port') == port and item.get('protocol') == 'udp':
            owned = own_port == port and 'samp03svr' in ' '.join(item.get('processes', []))
            if not owned: raise GameError('El puerto UDP está ocupado por otro proceso. Elegí otro puerto.')
    matching = [rule for rule in snapshot['rules'] if ports.rule_matches(rule, port, 'udp')]
    for rule in matching:
        if rule['action'] != 'ALLOW' and rule.get('any_source') and not ports.exact_global(rule, port, 'udp'):
            raise GameError('Una regla general o un intervalo afecta ese puerto. Elegí otro puerto para conservar esa política del firewall.')
    return snapshot


def read_forwarding():
    path = Path('/etc/storypulse-security/forwarding.json')
    removal.safe_path(path)
    if not path.exists(): return []
    if path.stat().st_size > 1024 * 1024: raise GameError('El registro de redirecciones excede su tamaño permitido.')
    value = json.loads(path.read_text())
    return value.get('entries', []) if isinstance(value, dict) else value


def plan(body):
    request = payload(body)
    row = status({}); action = request['action']; record = checked_record()
    ftp_revision=None
    if action == 'install':
        if row['installed'] or row['conflict']: raise GameError('Ya existe una instalación o archivos del juego. No se reemplazará.')
        if not row['compatible']: raise GameError(row['notice'])
        if run(['systemctl', 'is-system-running'], check=False).stdout.strip() not in ('running', 'degraded', 'starting'):
            raise GameError('Esta instalación requiere systemd activo.')
        if shutil.disk_usage('/opt').free < 128 * 1024 * 1024: raise GameError('Se requieren al menos 128 MB libres para preparar SA-MP.')
        try: pwd.getpwnam(USER)
        except KeyError: pass
        else: raise GameError('El usuario reservado del juego ya existe sin una instalación administrada.')
        if request.get('ftp',{}).get('enabled'):
            config=game_ftp.preflight(request['ftp']['username']);ftp_revision=game_ftp.ftp.revision(config)
    elif not row['managed']:
        raise GameError('No hay una instalación del juego administrada por el panel.')
    if action in ('install', 'configure', 'start', 'restart'):
        if action != 'install' and record.get('phase') != 'ready': raise GameError('La instalación está incompleta. Eliminá sus archivos antes de reinstalar.')
        settings = request.get('settings') or row['settings']
        if not settings: raise GameError('Falta la configuración del juego.')
        if action == 'configure' and settings['gamemode'] not in row['gamemodes']: raise GameError('El gamemode elegido no está instalado.')
        if action != 'install':
            for kind in ('filterscripts', 'plugins'):
                available = {item['name'] for item in row[kind] if item['available']}
                if any(name not in available for name in settings[kind]):
                    raise GameError('Hay '+kind+' seleccionados que faltan o no son compatibles. Revisá la selección.')
        port_check(settings['port'], record, row['settings'] or {})
    identity = dict(request=request, distribution=row['distribution'], architecture=row['architecture'],
        record=record, config=hashlib.sha256((BASE/'server.cfg').read_bytes()).hexdigest() if record and (BASE/'server.cfg').exists() else None,ftp_revision=ftp_revision)
    revision = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    settings = request.get('settings') or row['settings'] or DEFAULT
    warning = 'Se borrarán el juego, sus gamemodes, scriptfiles y registros. Se conservan las bibliotecas compartidas del sistema.' if action == 'uninstall' else 'Se abrirá '+str(settings['port'])+'/UDP; no se necesita TCP. Se conservan las reglas y servicios ajenos.'
    if action == 'configure': warning += ' Si el juego está encendido, se reiniciará para aplicar la configuración.'
    if action=='install' and request.get('ftp',{}).get('enabled'):
        warning += ' Se creará un usuario FTPS exclusivo, encerrado en la carpeta SA-MP. Se abrirán 21/TCP y 50000–50019/TCP para las transferencias. Su contraseña se guardará cifrada en este panel y sólo se mostrará con Windows Hello.'
        row['packages']=list(dict.fromkeys(row['packages']+platform.ftp_packages(platform.detect())))
    if action=='uninstall' and record.get('ftp'):warning += ' Se revocará la cuenta FTP del juego; el servicio FTP compartido y sus otras cuentas se conservan.'
    if row['architecture'] and platform.detect()['family'] == 'arch' and action == 'install': warning += ' Arch requiere sincronizar y actualizar el sistema para evitar una actualización parcial.'
    return dict(ok=True, game='samp', action=action, version=VERSION, distribution=row['distribution'], packages=row['packages'],
        settings=settings, warning=warning, revision=revision, directory=str(BASE), request=request)


def ensure_stats_script():
    directory = BASE/'filterscripts';safe_path(directory)
    directory.mkdir(mode=0o755, exist_ok=True)
    if not game_ftp.trusted(directory.stat(),checked_record()): raise GameError('La carpeta de filterscripts tiene permisos inseguros.')
    path = directory/(INTERNAL_FS+'.amx');safe_path(path)
    data = base64.b64decode(STATS_BASE64, validate=True)
    if hashlib.sha256(data).hexdigest() != STATS_SHA256: raise GameError('El lector interno de jugadores no supera la verificación.')
    if path.exists():
        with os.fdopen(os.open(path, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size != len(data) or handle.read(len(data)+1) != data:
                raise GameError('Existe un archivo distinto con el nombre del lector interno. No se reemplazó.')
        return
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o644), 'wb') as handle:
        handle.write(data);handle.flush();os.fchmod(handle.fileno(), 0o644);os.fsync(handle.fileno())


def prepare_admin_stats():
    values = read_config();names = values.get('filterscripts','').split()
    if len([name for name in names if name != INTERNAL_FS]) > 15: raise GameError('Se necesita un espacio de filterscript para las estadísticas del panel. Seleccioná hasta 15 FS adicionales.')
    ensure_stats_script()
    if INTERNAL_FS in names: return
    path = BASE/'server.cfg';text = path.read_text();line = 'filterscripts '+' '.join([INTERNAL_FS]+names)
    updated, count = re.subn(r'^filterscripts(?:[ \t]+[^\r\n]*)?$', line, text, flags=re.M)
    if count > 1: raise GameError('El archivo tiene varias entradas de filterscripts. Revisá la configuración.')
    if not count: updated = text.rstrip()+'\n'+line+'\n'
    temporary = BASE/('server.cfg.'+secrets.token_hex(8))
    mode=0o660 if (checked_record() or {}).get('ftp') else 0o640
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode), 'w') as handle:
            handle.write(updated);handle.flush();os.fchmod(handle.fileno(),mode);os.fchown(handle.fileno(), 0, path.stat().st_gid);os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally: temporary.unlink(missing_ok=True)


def write_config(settings, password, gid):
    ensure_stats_script()
    lines = ['# Server Security Monitor v3.0', '# Created by FacuSecX', '# https://github.com/FacuSecX/',
        'echo Executing Server Config...', 'lanmode 0', 'rcon_password '+password,
        'hostname '+settings['hostname'], 'port '+str(settings['port']), 'maxplayers '+str(settings['maxplayers']),
        'gamemode0 '+settings['gamemode']+' 1', 'filterscripts '+' '.join([INTERNAL_FS]+settings['filterscripts']),
        'plugins' + (' '+' '.join(settings['plugins']) if settings['plugins'] else ''), 'announce 0', 'query '+str(int(settings['query'])),
        'chatlogging '+str(int(settings['chatlogging'])), 'output 1', 'maxnpc 0', 'onfoot_rate 40', 'incar_rate 40',
        'weapon_rate 40', 'stream_distance 300.0', 'stream_rate 1000']
    temporary = BASE/('server.cfg.'+secrets.token_hex(8))
    mode=0o660 if (checked_record() or {}).get('ftp') else 0o640
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode), 'w') as handle:
            handle.write('\n'.join(lines)+'\n'); handle.flush();os.fchmod(handle.fileno(),mode); os.fsync(handle.fileno()); os.fchown(handle.fileno(), 0, gid)
        os.replace(temporary, BASE/'server.cfg')
    finally: temporary.unlink(missing_ok=True)


def extract_archive(data, target):
    if hashlib.sha256(data).hexdigest() != SHA256: raise GameError('La descarga de SA-MP no coincide con la huella verificada. No se ejecutó.')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers(); total = 0; seen = set()
        if len(members) > 1500: raise GameError('El archivo contiene demasiadas entradas.')
        for item in members:
            name = item.name.rstrip('/'); path = Path(name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'samp03' or name in seen or not (item.isdir() or item.isfile()):
                raise GameError('La descarga contiene una ruta o entrada insegura.')
            seen.add(name); total += item.size
            if item.size > 16 * 1024 * 1024 or total > 64 * 1024 * 1024: raise GameError('La descarga supera el tamaño permitido.')
            relative = Path(*path.parts[1:]); destination = target/relative
            if item.isdir(): destination.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, destination.open('xb') as output: shutil.copyfileobj(source, output)
                destination.chmod(0o755 if relative.name in ('samp03svr', 'samp-npc', 'announce') else 0o644)
    if not (target/'samp03svr').is_file() or not (target/'gamemodes/grandlarc.amx').is_file(): raise GameError('Faltan componentes del paquete de SA-MP.')
    (target/'plugins').mkdir(mode=0o755, exist_ok=True)


class VerifiedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if newurl not in DOWNLOAD_URLS:
            raise GameError('La descarga redirige a un destino no autorizado. No se descargó ese destino.')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def download():
    request = urllib.request.Request(URL, headers={'User-Agent': 'ServerSecurityMonitor/2.0'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), VerifiedRedirect())
    with opener.open(request, timeout=45) as response:
        if response.url not in DOWNLOAD_URLS: raise GameError('El proveedor cambió el destino de descarga a uno no autorizado.')
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024: raise GameError('La descarga supera el límite permitido.')
    if hashlib.sha256(data).hexdigest() != SHA256: raise GameError('La descarga de SA-MP no coincide con la huella verificada. No se ejecutó.')
    return data


def open_port(port, record):
    snapshot = ports.read_snapshot()
    own = [rule for rule in snapshot['rules'] if rule.get('comment') == COMMENT and ports.exact_global(rule, port, 'udp') and rule['action'] == 'ALLOW']
    if any(rule['family'] == 4 for rule in own): return
    existing = [rule for rule in snapshot['rules'] if ports.exact_global(rule, port, 'udp') and rule['action'] == 'ALLOW' and rule['family'] == 4]
    if existing: return
    suspended = [dict(port=port, family=rule['family'], number=rule['number'], action=rule['action'], comment=rule.get('comment', '')) for rule in snapshot['rules'] if ports.exact_global(rule, port, 'udp') and rule['action'] in ('DENY', 'REJECT')]
    record['owned_ports'] = sorted(set(record.get('owned_ports', [])+[port]))
    record['suspended_rules'] = record.get('suspended_rules', [])+suspended
    write_json(STATE, record)
    for rule in sorted(suspended, key=lambda row: row['number'], reverse=True): run(['ufw', '--force', 'delete', str(rule['number'])])
    run(['ufw', 'allow', str(port)+'/udp', 'comment', COMMENT])


def close_owned_ports(record, keep=None):
    allowed = set(record.get('owned_ports', [])) - ({keep} if keep else set())
    snapshot = ports.read_snapshot()
    rows = [rule for rule in snapshot['rules'] if rule.get('comment') == COMMENT and rule['action'] == 'ALLOW' and any(ports.exact_global(rule, port, 'udp') for port in allowed)]
    for rule in sorted(rows, key=lambda row: row['number'], reverse=True): run(['ufw', '--force', 'delete', str(rule['number'])])
    suspended = record.get('suspended_rules', [])
    for rule in sorted((rule for rule in suspended if rule['port'] in allowed), key=lambda row: row['number']):
        snapshot = ports.read_snapshot()
        if any(ports.exact_global(row, rule['port'], 'udp') and row['family'] == rule['family'] and row['action'] == rule['action'] for row in snapshot['rules']): continue
        numbers = [row['number'] for row in snapshot['rules'] if row['family'] == rule['family']]
        number = max(min(numbers), min(rule['number'], max(numbers)+1)) if numbers else len(snapshot['rules'])+1 if rule['family'] == 6 else 1
        address = '::/0' if rule['family'] == 6 else '0.0.0.0/0'
        command = ['ufw', 'insert', str(number), rule['action'].lower(), 'in', 'proto', 'udp', 'from', address, 'to', address, 'port', str(rule['port'])]
        if rule['comment']: command += ['comment', rule['comment']]
        run(command)
    record['suspended_rules'] = [rule for rule in suspended if rule['port'] not in allowed]
    record['owned_ports'] = [p for p in record.get('owned_ports', []) if p == keep]
    write_json(STATE, record)


def write_unit():
    text = f'''# Server Security Monitor v3.0
# Created by FacuSecX
# https://github.com/FacuSecX/
[Unit]
Description=Server Monitor - SA-MP
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=simple
User={USER}
Group={USER}
WorkingDirectory={BASE}
ExecStart={BASE}/samp03svr
Restart=on-failure
RestartSec=5
KillSignal=SIGINT
TimeoutStopSec=20
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths={BASE}/scriptfiles {BASE}/server_log.txt
MemoryMax=512M
TasksMax=64
UMask=0027
[Install]
WantedBy=multi-user.target
'''
    for path, value in ((UNIT, text), (ROTATE, f'{BASE}/server_log.txt {{\n daily\n maxsize 10M\n rotate 3\n compress\n copytruncate\n missingok\n notifempty\n}}\n')):
        removal.safe_path(path); path.write_text(value); path.chmod(0o644)
    run(['systemctl', 'daemon-reload'])


def start_game():
    prepare_admin_stats()
    run(['systemctl', 'reset-failed', SERVICE], check=False)
    run(['systemctl', 'start', SERVICE])
    time.sleep(2)
    if not unit_state()['active']:
        raise GameError('SA-MP no pudo iniciar. Revisá su consola; la instalación se conserva para poder eliminarla o corregirla.')


def install(request):
    profile = platform.detect(); packages = runtime_packages(profile)
    with removal.package_lock(): platform.install_packages(run, profile, packages)
    data = download()
    removal.safe_path(BASE); BASE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(BASE), '--shell', '/usr/sbin/nologin', USER])
    account = pwd.getpwnam(USER)
    record = dict(game='samp', version=VERSION, uid=account.pw_uid, gid=account.pw_gid, owned_ports=[], phase='installing')
    try: write_json(STATE, record)
    except Exception:
        run(['userdel', USER], check=False)
        raise
    try:
        BASE.mkdir(mode=0o755); extract_archive(data, BASE)
        for directory, dirs, files in os.walk(BASE/'scriptfiles'):
            os.chown(directory, account.pw_uid, account.pw_gid); os.chmod(directory, 0o750)
            for name in files: os.chown(Path(directory)/name, account.pw_uid, account.pw_gid); os.chmod(Path(directory)/name, 0o640)
        log = BASE/'server_log.txt'; log.touch(mode=0o660); os.chown(log, 0, account.pw_gid); log.chmod(0o660)
        write_config(request['settings'], secrets.token_urlsafe(32), account.pw_gid)
        run(['ldd', str(BASE/'samp03svr')])
        write_unit(); open_port(request['settings']['port'], record)
        run(['systemctl', 'enable', SERVICE]); start_game()
        if request.get('ftp',{}).get('enabled'):
            game_ftp.create(request['ftp'],request['ftp_secret'],record,lambda:write_json(STATE,record))
        record['phase'] = 'ready'; write_json(STATE, record)
    except Exception:
        if record.get('ftp'):
            try:game_ftp.remove(record)
            except Exception:pass
        record['phase'] = 'error'; write_json(STATE, record)
        run(['systemctl', 'disable', '--now', SERVICE], check=False)
        close_owned_ports(record)
        raise
    return 'SA-MP '+VERSION+' instalado y encendido. Puerto '+str(request['settings']['port'])+'/UDP habilitado.'+(' Cuenta FTP aislada creada; 21/TCP y 50000–50019/TCP habilitados.' if record.get('ftp') else '')


def uninstall(record):
    paths = [BASE, UNIT, ROTATE]
    removal.validate_paths(paths)
    run(['systemctl', 'disable', '--now', SERVICE], check=False)
    if unit_state()['active']: raise GameError('No se pudo detener el juego. No se borró su instalación.')
    game_ftp.remove(record)
    close_owned_ports(record)
    for path in paths:
        if path.is_dir(): shutil.rmtree(path)
        else: path.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload']); run(['systemctl', 'reset-failed', SERVICE], check=False)
    try:
        account = pwd.getpwnam(USER)
        if account.pw_uid == record['uid']: run(['userdel', USER])
    except KeyError: pass
    STATE.unlink()
    return 'SA-MP eliminado. Se retiraron sus archivos y sus propias reglas UDP; se conservaron las bibliotecas compartidas.'


def apply(body):
    request = payload(body, True)
    previous = read_json(COOLDOWN, {})
    if time.time() - previous.get('finished', 0) < 3: raise GameError('Esperá tres segundos después de la respuesta antes de enviar otra acción.')
    review = plan({key:value for key,value in request.items() if key!='ftp_secret'})
    if not secrets.compare_digest(review['revision'], body['revision']): raise GameError('La configuración cambió. Revisá nuevamente antes de confirmar.')
    record = checked_record(); action = request['action']
    try:
        if action == 'install': message = install(request)
        elif action == 'uninstall': message = uninstall(record)
        elif action == 'configure':
            config = read_config(); old_settings = settings_from_config(config); active = unit_state()['active']
            if request['settings'] == old_settings:
                message = 'La configuración ya está actualizada. No se reinició SA-MP.'
            else:
                try:
                    if active: run(['systemctl', 'stop', SERVICE])
                    open_port(request['settings']['port'], record)
                    write_config(request['settings'], config['rcon_password'], record['gid'])
                    if active: start_game()
                except Exception:
                    write_config(old_settings, config['rcon_password'], record['gid'])
                    close_owned_ports(record, old_settings['port'])
                    if active: start_game()
                    raise
                close_owned_ports(record, request['settings']['port']); message = 'Configuración de SA-MP guardada.'
        else:
            if action == 'stop': run(['systemctl', 'stop', SERVICE])
            else:
                open_port(review['settings']['port'], record)
                if action == 'restart': run(['systemctl', 'stop', SERVICE])
                start_game()
            message = {'start': 'SA-MP encendido.', 'stop': 'SA-MP apagado.', 'restart': 'SA-MP reiniciado.'}[action]
        return dict(ok=True, game='samp', action=action, message=message)
    finally:
        write_json(COOLDOWN, {'finished': time.time()})


def console(body):
    if not isinstance(body, dict) or set(body) != {'cursor'} or not isinstance(body['cursor'], str) or not re.fullmatch(r'(?:[0-9]{1,20}:[0-9]{1,20})?', body['cursor']):
        raise GameError('Posición de consola no válida.')
    record = checked_record()
    if not record: return dict(ok=True, text='', cursor='', reset=True)
    path = BASE/'server_log.txt'; safe_path(path)
    try: descriptor = os.open(path, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError: return dict(ok=True, text='', cursor='', reset=True)
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        trusted_log=(game_ftp.trusted(info,record) or game_ftp.trusted(info,record,record['uid'])) if record.get('ftp') else info.st_uid==0 and not info.st_mode&0o002
        if not stat.S_ISREG(info.st_mode) or not trusted_log: raise GameError('El registro del juego no es seguro.')
        previous = body['cursor'].split(':') if body['cursor'] else []
        reset = not previous or int(previous[0]) != info.st_ino or int(previous[1]) > info.st_size
        offset = max(0, info.st_size-32768) if reset else int(previous[1])
        handle.seek(offset); data = handle.read(32768); next_offset = handle.tell()
    try: text = data.decode('utf-8')
    except UnicodeDecodeError: text = data.decode('cp1252', errors='replace')
    if (BASE/'server.cfg').exists():
        password = read_config().get('rcon_password', '')
        if password: text = text.replace(password, '[protegido]')
    return dict(ok=True, text=text, cursor=str(info.st_ino)+':'+str(next_offset), reset=reset)
