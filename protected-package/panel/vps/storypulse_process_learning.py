# ==========================================
# Panel Seguridad Monitor v4
# Created by FacuSecX
# https://github.com/FacuSecX/
# ==========================================
"""Persistent, server-local baselines. No commands, credentials or packet contents."""
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

DB_PATH = Path('/var/lib/storypulse-security/process-history/learning.sqlite3')
METRICS = ('cpu_percent', 'rss_bytes', 'rx_bps', 'tx_bps')
FLOORS = dict(cpu_percent=20.0, rss_bytes=128*1024**2, rx_bps=1024**2, tx_bps=1024**2)
LEARNING_SECONDS = 7*86400
MIN_SAMPLES = 360
SUSTAIN_SECONDS = 60
MAX_GAP = 25
COOLDOWN = 6*3600
RETENTION = 30*86400
HEX = re.compile(r'[a-f0-9]{32}')


def valid_number(value):
    return type(value) in (float, int) and math.isfinite(value) and value >= 0


def metadata(pid, name, unit='', proc=Path('/proc'), start_ticks=None):
    try:
        status = (proc/str(pid)/'status').read_text(encoding='ascii', errors='replace')
        uid = int(next(line for line in status.splitlines() if line.startswith('Uid:')).split()[2])
        executable = os.readlink(proc/str(pid)/'exe')
        if executable.endswith(' (deleted)'):
            executable = executable[:-10]
        if len(executable) > 4096 or not executable.startswith('/'):
            return None
        if start_ticks is not None:
            current = (proc/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
            if int(current[19]) != start_ticks:
                return None
        return dict(uid=uid, executable=executable, unit=unit, name=str(name)[:128])
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def identity(meta):
    if not meta:
        return None
    stable = [meta['unit'], meta['executable'], meta['uid']]
    if not meta['unit']:
        stable.append(meta['name'])
    return hashlib.sha256(json.dumps(stable, separators=(',', ':')).encode()).hexdigest()[:32]


def checked_path(path):
    path = Path(path)
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise RuntimeError('El almacenamiento de aprendizaje no es seguro.')
    if path.exists():
        st = path.stat()
        if not path.is_file() or (os.name != 'nt' and (st.st_uid != os.geteuid() or st.st_mode & 0o077)):
            raise RuntimeError('El almacenamiento de aprendizaje no es seguro.')
    return path


def reader(path=DB_PATH):
    path = checked_path(path)
    if not path.exists():
        return None
    db = sqlite3.connect('file:'+str(path)+'?mode=ro', uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    return db


def public_profile(row, now):
    stats = decode_stats(row['stats'])
    decode_streak(row['streak'])
    return dict(profile_id=row['id'], generation=row['generation'], state=row['state'],
                started_at=row['started'], ends_at=row['started']+LEARNING_SECONDS,
                last_seen=row['last_seen'], samples=row['samples'], min_samples=MIN_SAMPLES,
                progress=min(100, max(0, (now-row['started'])*100/LEARNING_SECONDS)),
                thresholds={m: threshold(s, m) for m, s in stats.items() if s.get('ready') and s['n'] >= MIN_SAMPLES},
                metric_states={m: 'monitoring' if s.get('ready') else 'learning' for m,s in stats.items()},
                grouped=True)


def decode_stats(raw):
    stats=json.loads(raw)
    if not isinstance(stats,dict):
        raise ValueError('Patrón de proceso no válido.')
    for metric,base in stats.items():
        if (metric not in METRICS or not isinstance(base,dict) or type(base.get('n')) is not int or base['n']<1 or
            not valid_number(base.get('mean')) or not valid_number(base.get('m2')) or not isinstance(base.get('bins'),dict)):
            raise ValueError('Métrica de aprendizaje no válida.')
        if any(not re.fullmatch(r'-?\d{1,4}',str(k)) or not -4300<int(k)<4096 or type(v) is not int or v<1 for k,v in base['bins'].items()):
            raise ValueError('Distribución de aprendizaje no válida.')
        if sum(base['bins'].values())!=base['n']:
            raise ValueError('Muestras de aprendizaje inconsistentes.')
    return stats


def decode_streak(raw):
    streak=json.loads(raw)
    if not isinstance(streak,dict):
        raise ValueError('Continuidad no válida.')
    for metric,value in streak.items():
        if (metric not in METRICS or not isinstance(value,dict) or
            any(type(value.get(k)) is not int for k in ('since','last','count')) or
            value['since']>value['last'] or value['count']<1):
            raise ValueError('Continuidad de métrica no válida.')
    return streak


def threshold(stats, metric):
    deviation = math.sqrt(max(0, stats['m2']/max(1, stats['n']-1)))
    rank, total, p99 = math.ceil(stats['n']*.99), 0, 0
    for key, count in sorted(stats['bins'].items(), key=lambda item: int(item[0])):
        total += count
        if total >= rank:
            p99 = 0 if key == '-999' else 2**(int(key)/4)
            break
    return max(FLOORS[metric], stats['mean']+6*deviation, p99*1.5, p99+FLOORS[metric])


def update_stat(stats, value):
    stats = stats or dict(n=0, mean=0, m2=0, bins={})
    stats['n'] += 1
    delta = value-stats['mean']
    stats['mean'] += delta/stats['n']
    stats['m2'] += delta*(value-stats['mean'])
    key = str(math.ceil(math.log2(value)*4)) if value else '-999'
    stats['bins'][key] = stats['bins'].get(key, 0)+1
    return stats


class Learning:
    def __init__(self, path=DB_PATH):
        self.path = checked_path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), timeout=5)
        os.chmod(self.path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=WAL;
          PRAGMA synchronous=NORMAL;
          CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY,metadata TEXT NOT NULL,
           generation TEXT NOT NULL,state TEXT NOT NULL,started INTEGER NOT NULL,
           last_seen INTEGER NOT NULL,samples INTEGER NOT NULL,stats TEXT NOT NULL,
           streak TEXT NOT NULL,last_alert INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,
           id TEXT UNIQUE NOT NULL,timestamp INTEGER NOT NULL,profile_id TEXT NOT NULL,
           generation TEXT NOT NULL,payload TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS event_stamp ON events(timestamp);''')
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('server_id',?)", (secrets.token_hex(16),))
        self.db.commit()
        self.server_id = self.db.execute("SELECT value FROM meta WHERE key='server_id'").fetchone()[0]

    def close(self):
        self.db.close()

    def record(self, rows, now=None):
        now = int(time.time()) if now is None else int(now)
        unique={}
        for row in rows:
            instance=(row.get('pid'),row.get('start_ticks'))
            if instance in unique:
                if unique[instance]!=row:unique[instance]=None
            else:unique[instance]=row
        grouped = {}
        for row in unique.values():
            if row is None:continue
            meta = row.get('learning_meta')
            key = identity(meta)
            if not key:
                continue
            group = grouped.setdefault(key, dict(meta=meta, values={m: [] for m in METRICS}))
            for metric in METRICS:
                group['values'][metric].append(row.get(metric))
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            for key, group in grouped.items():
                old = self.db.execute('SELECT * FROM profiles WHERE id=?', (key,)).fetchone()
                if old and (now <= old['last_seen'] or now < old['started']):
                    continue
                if not old:
                    if self.db.execute('SELECT COUNT(*) FROM profiles').fetchone()[0] >= 10000:
                        continue
                    self.db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (key, json.dumps(group['meta']), secrets.token_hex(16), 'learning', now, now-1, 0, '{}', '{}', 0))
                    old = self.db.execute('SELECT * FROM profiles WHERE id=?', (key,)).fetchone()
                try:
                    stats, streak = decode_stats(old['stats']), decode_streak(old['streak'])
                except (ValueError,TypeError,KeyError,OverflowError):
                    continue
                state, samples = old['state'], old['samples']
                values = {m: sum(v) if v and all(valid_number(x) for x in v) else None for m, v in group['values'].items()}
                if state == 'learning' and now-old['started'] >= LEARNING_SECONDS and stats.get('cpu_percent', {}).get('n', 0) >= MIN_SAMPLES:
                    state, streak = 'monitoring', {}
                    for base in stats.values():
                        base['ready'] = base['n'] >= MIN_SAMPLES
                if state == 'learning':
                    for metric, value in values.items():
                        if valid_number(value):
                            stats[metric] = update_stat(stats.get(metric), value)
                    if valid_number(values['cpu_percent']):
                        samples += 1
                abnormal = {}
                if state == 'monitoring':
                    for metric, value in values.items():
                        base = stats.get(metric)
                        # A metric unavailable in the initial week gets its own silent learning window.
                        if not base or not base.get('ready'):
                            if valid_number(value):
                                base = stats.get(metric) or dict(n=0, mean=0, m2=0, bins={}, started=now)
                                base.setdefault('started', now)
                                base = update_stat(base, value)
                                base['ready'] = base['n'] >= MIN_SAMPLES and now-base['started'] >= LEARNING_SECONDS
                                stats[metric] = base
                            streak.pop(metric, None)
                            continue
                        limit = threshold(base, metric)
                        if not valid_number(value) or value <= limit:
                            streak.pop(metric, None)
                            continue
                        prior = streak.get(metric)
                        if not prior or now-prior['last'] > MAX_GAP:
                            prior = dict(since=now, count=0)
                        prior.update(last=now, count=prior['count']+1)
                        streak[metric] = prior
                        if now-prior['since'] >= SUSTAIN_SECONDS and prior['count'] >= 3:
                            abnormal[metric] = dict(value=value, threshold=limit, mean=base['mean'])
                last_alert = old['last_alert']
                if abnormal and (not last_alert or now-last_alert >= COOLDOWN):
                    payload = dict(kind='process_anomaly', id=secrets.token_hex(16), timestamp=now,
                                   server_id=self.server_id, profile_id=key, generation=old['generation'],
                                   name=group['meta']['name'], unit=group['meta']['unit'], metrics=abnormal)
                    self.db.execute('INSERT INTO events(id,timestamp,profile_id,generation,payload) VALUES(?,?,?,?,?)',
                        (payload['id'], now, key, old['generation'], json.dumps(payload)))
                    last_alert = now
                self.db.execute('UPDATE profiles SET state=?,last_seen=?,samples=?,stats=?,streak=?,last_alert=? WHERE id=?',
                    (state, now, samples, json.dumps(stats), json.dumps(streak), last_alert, key))
            self.db.execute('DELETE FROM events WHERE timestamp<?', (now-RETENTION,))
            self.db.execute('DELETE FROM events WHERE seq <= (SELECT COALESCE(MAX(seq),0)-50000 FROM events)')

    def change(self, key, action, now=None):
        now = int(time.time()) if now is None else int(now)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT * FROM profiles WHERE id=?', (key,)).fetchone()
            if not row:
                raise RuntimeError('Esperá la primera muestra del recolector para gestionar el aprendizaje.')
            if action == 'learning_restart':
                self.db.execute("UPDATE profiles SET state='learning',started=?,last_seen=?,generation=?,samples=0,stats='{}',streak='{}',last_alert=0 WHERE id=?",
                                (now, now, secrets.token_hex(16), key))
            elif action == 'learning_finish':
                stats = decode_stats(row['stats'])
                if row['state'] != 'learning' or stats.get('cpu_percent', {}).get('n', 0) < MIN_SAMPLES:
                    raise RuntimeError('Se necesitan al menos 360 muestras válidas de CPU antes de finalizar el aprendizaje.')
                for base in stats.values():
                    base['ready'] = base['n'] >= MIN_SAMPLES
                self.db.execute("UPDATE profiles SET state='monitoring',stats=?,streak='{}',last_alert=0 WHERE id=?", (json.dumps(stats), key))
            else:
                raise ValueError('Acción de aprendizaje no válida.')
        return dict(ok=True, action=action, learning=public_profile(self.db.execute('SELECT * FROM profiles WHERE id=?', (key,)).fetchone(), now))


def enrich(processes, path=DB_PATH, now=None):
    now = int(time.time()) if now is None else int(now)
    contexts=[(row,row.pop('learning_meta',None)) for row in processes]
    profiles={};server_id=None;error=''
    try:
        db=reader(path)
        if db is None:
            error='Esperando la primera muestra de aprendizaje.'
        else:
            with closing(db):
                server_id=db.execute("SELECT value FROM meta WHERE key='server_id'").fetchone()[0]
                needed=list({identity(meta) for row,meta in contexts if meta})
                for offset in range(0,len(needed),200):
                    batch=needed[offset:offset+200]
                    for stored in db.execute('SELECT * FROM profiles WHERE id IN ('+','.join('?' for _ in batch)+')',batch):
                        try:profile=public_profile(stored,now)
                        except (ValueError,TypeError,KeyError,OverflowError):
                            profile=dict(profile_id=stored['id'],generation=stored['generation'],state='error',
                                started_at=stored['started'],ends_at=stored['started']+LEARNING_SECONDS,
                                last_seen=stored['last_seen'],samples=stored['samples'],min_samples=MIN_SAMPLES,
                                progress=0,thresholds={},metric_states={},grouped=True)
                        profiles[stored['id']]=profile
    except (OSError,RuntimeError,sqlite3.Error,TypeError):
        profiles={};error='No se pudo leer el aprendizaje de este VPS.';server_id=None
    for row,meta in contexts:
        profile=profiles.get(identity(meta)) if meta else None
        row['learning']=profile
        if row.get('learning_status')=='kernel':
            status='kernel';reason='Hilo interno del kernel: no tiene un ejecutable de usuario. Sus métricas se muestran, pero queda fuera del aprendizaje y de sus alertas.'
        elif not meta:
            status='unavailable';reason='No se pudo identificar el ejecutable. El proceso puede haber terminado o cambiado durante la lectura.'
        elif error and server_id is None:
            status='waiting' if 'primera muestra' in error else 'error';reason=error
        elif not profile:
            status='waiting';reason='Esperando la primera muestra del recolector para este proceso.'
        elif profile['state']=='error':
            status='error';reason='El patrón guardado de este proceso no es válido. Podés reiniciar su aprendizaje sin afectar los demás.'
        elif now-profile['last_seen']>120:
            status='stale';reason='El recolector lleva más de dos minutos sin actualizar este patrón. No se reinicia el aprendizaje automáticamente.'
        else:
            status=profile['state'];reason=''
        row['learning_status']=status;row['learning_reason']=reason
    return dict(learning_server_id=server_id,learning_error=error)


def event_feed(after=0, server_id='', path=DB_PATH):
    if type(after) is not int or not 0 <= after <= 2**53-1 or not isinstance(server_id, str) or (server_id and not HEX.fullmatch(server_id)):
        raise ValueError('Cursor de aprendizaje no válido.')
    db = reader(path)
    if db is None:
        return dict(ok=True, server_id=None, events=[], next_after=0, more=False)
    with closing(db):
        current = db.execute("SELECT value FROM meta WHERE key='server_id'").fetchone()[0]
        if current != server_id:
            after = 0
        rows = db.execute('SELECT seq,payload FROM events WHERE seq>? ORDER BY seq LIMIT 201', (after,)).fetchall()
        return dict(ok=True, server_id=current, events=[dict(json.loads(row['payload']), seq=row['seq']) for row in rows[:200]],
                    next_after=rows[min(199,len(rows)-1)]['seq'] if rows else after, more=len(rows)>200)


def event_active(event, path=DB_PATH):
    db = reader(path)
    if db is None:
        return False
    with closing(db):
        server_id = db.execute("SELECT value FROM meta WHERE key='server_id'").fetchone()[0]
        row = db.execute('SELECT state,generation FROM profiles WHERE id=?', (event.get('profile_id'),)).fetchone()
        return bool(row and row['state']=='monitoring' and row['generation']==event.get('generation') and server_id==event.get('server_id'))


def alert_text(event, server):
    labels = dict(cpu_percent='CPU', rss_bytes='RAM', rx_bps='TCP recibido', tx_bps='TCP enviado')
    def format_value(metric, value):
        return f'{value:.1f} %' if metric=='cpu_percent' else f'{value/1024**2:.2f} MiB'+('/s' if metric.endswith('bps') else '')
    lines = ['⚠️ ACTIVIDAD ANORMAL DE PROCESO', '', 'Servidor: '+str(server)[:128],
             'Proceso: '+str(event.get('name',''))[:128], 'Servicio: '+str(event.get('unit') or 'Sin unidad systemd')[:160]]
    for metric, value in event['metrics'].items():
        if metric in METRICS:
            lines.append(labels[metric]+': '+format_value(metric,value['value'])+' · Umbral aprendido: '+format_value(metric,value['threshold']))
    lines.extend(['','Aumento sostenido durante al menos 60 segundos. Revisá el proceso; esta alerta no confirma una intrusión.', 'Evento: '+event['id'][:12]])
    return '\n'.join(lines)


def change_request(body, processes, path=DB_PATH):
    if (not isinstance(body,dict) or set(body)!={'pid','start_ticks','boot_id','action','confirm'} or
        type(body['pid']) is not int or not 0<body['pid']<=2**31-1 or type(body['start_ticks']) is not int or body['start_ticks']<0 or
        not isinstance(body['boot_id'],str) or not processes.BOOT_ID.fullmatch(body['boot_id']) or
        body['action'] not in ('learning_finish','learning_restart') or body['confirm'] is not True):
        raise ValueError('Solicitud de aprendizaje no válida.')
    if body['boot_id'] != processes.boot_id():
        raise RuntimeError('El servidor se reinició. Actualizá la lista.')
    row = processes.process_stat(body['pid'])
    if row['start_ticks'] != body['start_ticks']:
        raise RuntimeError('El proceso cambió. Actualizá la lista.')
    meta = metadata(body['pid'], row['name'], processes.process_unit(body['pid']), processes.PROC, row['start_ticks'])
    key = identity(meta)
    if not key:
        raise RuntimeError('No se puede identificar este ejecutable para aprender su comportamiento.')
    with closing(Learning(path)) as engine:
        return engine.change(key, body['action'])
