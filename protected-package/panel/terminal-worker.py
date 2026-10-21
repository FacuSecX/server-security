import json
import os
import selectors
import signal
import subprocess
import sys
import time

LIMIT = 128 * 1024
TIMEOUT = 60

def run(command):
    started = time.monotonic()
    child = subprocess.Popen(
        ['/bin/sh', '-c', command], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    for stream, name in [(child.stdout, 'stdout'), (child.stderr, 'stderr')]:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    timed_out = truncated = False
    size = 0
    try:
        while selector.get_map():
            if time.monotonic() - started >= TIMEOUT:
                timed_out = True
                break
            for key, _ in selector.select(.15):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = LIMIT - size
                streams[key.data].extend(chunk[:room])
                size += min(len(chunk), room)
                if len(chunk) > room:
                    truncated = True
                    break
            if truncated:
                break
        if not timed_out and not truncated:
            try:
                child.wait(timeout=max(.01, TIMEOUT - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        selector.close()
        child.stdout.close()
        child.stderr.close()
    return dict(ok=True, stdout=streams['stdout'].decode('utf-8', 'replace'),
                stderr=streams['stderr'].decode('utf-8', 'replace'),
                exit_code=child.returncode, timed_out=timed_out, truncated=truncated,
                duration_ms=round((time.monotonic() - started) * 1000))

def main():
    body = sys.stdin.buffer.read(16385)
    if len(body) > 16384:
        raise ValueError('Solicitud demasiado grande.')
    payload = json.loads(body)
    if not isinstance(payload, dict) or set(payload) != {'command'}:
        raise ValueError('Solicitud no valida.')
    command = payload['command']
    if not isinstance(command, str) or not command.strip() or len(command.encode('utf-8')) > 8192:
        raise ValueError('Comando no valido.')
    if any(ord(c) < 32 and c not in '\n\t' for c in command) or '\x7f' in command:
        raise ValueError('Caracteres de control no permitidos.')
    print(json.dumps(run(command), ensure_ascii=True), flush=True)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps(dict(ok=False, error='No se pudo ejecutar el comando de terminal.')))
        sys.exit(1)