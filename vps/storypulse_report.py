# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import base64
import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import tempfile

from storypulse_platform import detect

DIRECTORY = Path('/var/lib/storypulse-security/Informes/SSH/archivos')
CACHE = Path('/var/cache/storypulse-security')
SCRIPT = Path('/usr/local/lib/storypulse-security/ssh_security.ssh')
SCRIPT_SHA256 = '543cf0e2055edda59a2a7c1c9913d35867cd524a872f3aa3f5e12750c215d07a'
MAX_FILE = 16 * 1024 * 1024
TIMEOUT = 30 * 60
NAME = re.compile(r'^ssh_reporte_[A-Za-z0-9_-]+\.txt$')
OUTPUT_NAME = re.compile(r'^ssh_(?:reporte|eventos)_[A-Za-z0-9_-]+\.(?:txt|csv)$')


class ReportError(RuntimeError):
    pass


def secure_directory(path=None):
    path = DIRECTORY if path is None else path
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ReportError('El almacenamiento de informes contiene un enlace simbólico.')
        if parent.exists():
            info = parent.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ReportError('El almacenamiento de informes debe pertenecer a root y no ser modificable por otros usuarios.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)


def verified_script():
    
    for parent in SCRIPT.parents:
        if parent.is_symlink():
            raise ReportError('La ruta del generador original no es segura.')
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ReportError('El generador original debe estar instalado y protegido por root.')
    descriptor = os.open(SCRIPT, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ReportError('El generador original no es un archivo seguro.')
        if hashlib.sha256(source.read(128 * 1024)).hexdigest() != SCRIPT_SHA256:
            raise ReportError('El generador original no coincide con la copia revisada. Reinstalá el controlador.')
    return SCRIPT


def child_limits():
    
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def run_original(arguments, work):
    environment = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root',
                   'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8', 'TZ':'America/Argentina/Buenos_Aires',
                   'XDG_CACHE_HOME':str(CACHE), 'TMPDIR':str(work)}
    
    with tempfile.TemporaryFile(dir=work) as log:
        process = subprocess.Popen(['/usr/bin/bash', '--noprofile', '--norc', str(verified_script()), *arguments],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=work,
                                   env=environment, start_new_session=True, preexec_fn=child_limits)
        try:
            result = process.wait(timeout=TIMEOUT)
        except BaseException:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
            raise
        if result:
            log.seek(max(0, log.tell() - 1500))
            detail = re.sub(r'[\x00-\x1f\x7f]', ' ', log.read().decode('utf-8', errors='replace'))
            raise ReportError('El generador original falló: ' + detail)


def generate(payload):
    if not isinstance(payload, dict) or set(payload) != {'minutes'} or type(payload['minutes']) is not int or not 1 <= payload['minutes'] <= 10080:
        raise ReportError('El reporte admite un período entero de 1 minuto a 7 días.')
    secure_directory()
    secure_directory(CACHE)
    minutes = payload['minutes']
    period = ['--hours', str(minutes // 60)] if minutes % 60 == 0 else ['--since', str(minutes) + ' minutes ago']
    published = []
    try:
        
        with tempfile.TemporaryDirectory(prefix='.generando-', dir=DIRECTORY) as temporary:
            work = Path(temporary)
            run_original([*period, '--all', '--unit', detect()['ssh_service'],
                          '--output-dir', str(work), '--timezone', 'America/Argentina/Buenos_Aires'], work)
            outputs = sorted(work.iterdir())
            if not outputs:
                return {'ok':True, 'minutes':minutes, 'days':minutes/1440, 'files':[],
                        'no_findings':True, 'warning':'', 'detail':'No se encontraron fallos de autenticación SSH.'}
            if len(outputs) != 3 or any(not OUTPUT_NAME.fullmatch(p.name) or p.is_symlink() or not p.is_file()
                                      or p.stat().st_size > MAX_FILE for p in outputs):
                raise ReportError('El generador original produjo archivos inesperados o demasiado grandes.')
            
            for path in outputs:
                destination = DIRECTORY / path.name
                os.link(path, destination)
                published.append(destination)
        files = sorted(published, key=lambda p:(p.suffix != '.txt', p.name))
        return {'ok':True, 'minutes':minutes, 'days':minutes/1440,
                'files':[{'name':p.name, 'type':p.suffix[1:], 'size':p.stat().st_size} for p in files],
                'no_findings':False, 'warning':'', 'detail':'Informe original: TXT, ranking CSV y cronología CSV.'}
    except subprocess.TimeoutExpired as exc:
        raise ReportError('El informe superó 30 minutos. Elegí un período más corto; no se publicaron archivos incompletos.') from exc
    except Exception:
        for path in published: path.unlink(missing_ok=True)
        raise


def download(payload):
    if payload != {}: raise ReportError('La descarga no acepta rutas ni comandos.')
    secure_directory()
    candidates = [p for p in DIRECTORY.iterdir() if NAME.fullmatch(p.name) and not p.is_symlink() and p.is_file()]
    if not candidates: raise ReportError('Todavía no hay un reporte TXT. Generá uno primero.')
    path = max(candidates, key=lambda p:p.stat().st_mtime_ns)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_size > MAX_FILE:
            raise ReportError('El reporte no es un archivo seguro o supera 16 MB.')
        content = source.read(MAX_FILE + 1)
    if len(content) > MAX_FILE: raise ReportError('El reporte supera 16 MB.')
    return {'ok':True, 'name':path.name, 'size':len(content), 'content':base64.b64encode(content).decode('ascii')}
