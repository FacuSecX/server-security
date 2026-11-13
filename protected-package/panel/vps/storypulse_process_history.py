#!/usr/bin/python3 -I
# ==========================================
# Panel Seguridad Monitor v4
# Created by FacuSecX
# https://github.com/FacuSecX/
# ==========================================
"""Collect and retain per-process resource peaks independently of the panel."""

from contextlib import closing
from dataclasses import dataclass
import math
import os
from pathlib import Path
import sqlite3
import sys
import time
from typing import Optional

# Python isolated mode does not add the script's directory to the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import storypulse_processes as linux


HISTORY_DB = Path("/var/lib/storypulse-security/process-history/history.sqlite3")
PERIODS = {24: 300, 168: 1800, 720: 7200}
DETAIL_DB = HISTORY_DB.with_name('detail.sqlite3')
DETAIL_PERIODS = {2: 10, 48: 60}
DETAIL_MAX_ROWS = 600_000
DETAIL_MAX_DB_BYTES = 160 * 1024 * 1024
DETAIL_WINDOWS = {'15m': (900, 10), '1h': (3600, 10), '6h': (21600, 60),
                  '24h': (86400, 60), '48h': (172800, 60), '7d': (604800, 1800)}
METRICS = ("cpu_percent", "rss_bytes", "rx_bps", "tx_bps")
SAMPLE_SECONDS = 10
MAX_RATE_GAP_SECONDS = 25
PRUNE_INTERVAL_MS = 60_000
MAX_ROWS = 400_000
MAX_CONNECTIONS = 100_000
CONNECTIONS_PER_PAGE = 40
CONNECTION_RETENTION_MS = 30 * 24 * 3_600_000
MAX_DB_BYTES = 192 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS process_peaks (
    bucket_seconds INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    start_ticks INTEGER NOT NULL,
    at_ms INTEGER NOT NULL,
    first_at_ms INTEGER NOT NULL,
    cpu_percent REAL,
    rss_bytes INTEGER,
    rx_bps REAL,
    tx_bps REAL,
    PRIMARY KEY (bucket_seconds, boot_id, pid, start_ticks, at_ms)
);
CREATE INDEX IF NOT EXISTS process_peaks_expiry
    ON process_peaks (bucket_seconds, at_ms);
CREATE TABLE IF NOT EXISTS process_connections (
    boot_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    start_ticks INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    local_port INTEGER NOT NULL,
    state TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    PRIMARY KEY (boot_id, pid, start_ticks, protocol, ip, port, local_port)
);
CREATE INDEX IF NOT EXISTS process_connections_by_process
    ON process_connections (boot_id, pid, start_ticks, last_seen_ms);
CREATE INDEX IF NOT EXISTS process_connections_expiry
    ON process_connections (last_seen_ms);
"""
UPSERT = """
INSERT INTO process_peaks
    (bucket_seconds, boot_id, pid, start_ticks, at_ms, first_at_ms,
     cpu_percent, rss_bytes, rx_bps, tx_bps)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (bucket_seconds, boot_id, pid, start_ticks, at_ms)
DO UPDATE SET
    first_at_ms = min(process_peaks.first_at_ms, excluded.first_at_ms),
""" + ",\n".join(
    f"    {metric} = max(coalesce(process_peaks.{metric}, excluded.{metric}), "
    f"coalesce(excluded.{metric}, process_peaks.{metric}))" for metric in METRICS
) + "\nWHERE excluded.first_at_ms < process_peaks.first_at_ms OR " + " OR ".join(
    f"(excluded.{metric} IS NOT NULL AND "
    f"(process_peaks.{metric} IS NULL OR excluded.{metric} > process_peaks.{metric}))"
    for metric in METRICS
)
UPSERT_CONNECTION = """
INSERT INTO process_connections
    (boot_id, pid, start_ticks, protocol, ip, port, local_port, state, first_seen_ms, last_seen_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (boot_id, pid, start_ticks, protocol, ip, port, local_port)
DO UPDATE SET
    state = CASE WHEN excluded.last_seen_ms >= process_connections.last_seen_ms
                 THEN excluded.state ELSE process_connections.state END,
    first_seen_ms = min(process_connections.first_seen_ms, excluded.first_seen_ms),
    last_seen_ms = max(process_connections.last_seen_ms, excluded.last_seen_ms)
"""


def bucket_start(at_ms, seconds):
    step = seconds * 1000
    return at_ms // step * step


def current_time_ms():
    return time.time_ns() // 1_000_000


def measurement(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


class ProcessHistory:
    def __init__(self, path=HISTORY_DB, *, max_rows=MAX_ROWS, max_connections=MAX_CONNECTIONS, periods=None, max_db_bytes=MAX_DB_BYTES):
        self.periods = dict(PERIODS if periods is None else periods)
        self.max_rows = max_rows
        self.max_connections = max_connections
        self.next_prune_ms = 0
        self.db = sqlite3.connect(path, timeout=1)
        try:
            self.db.execute("PRAGMA auto_vacuum = INCREMENTAL")
            self.db.execute("PRAGMA journal_mode = WAL")
            self.db.execute("PRAGMA synchronous = NORMAL")
            self.db.execute("PRAGMA journal_size_limit = 4194304")
            self.db.execute("PRAGMA wal_autocheckpoint = 512")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count = {max_db_bytes // page_size}")
            self.db.executescript(SCHEMA)
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def prune(self, observed_ms):
        for hours, seconds in self.periods.items():
            cutoff = bucket_start(observed_ms - hours * 3_600_000, seconds)
            self.db.execute("DELETE FROM process_peaks WHERE bucket_seconds=? AND at_ms<?",
                            (seconds, cutoff))
        excess = self.db.execute("SELECT count(*) FROM process_peaks").fetchone()[0] - self.max_rows
        if excess > 0:
            self.db.execute(
                """DELETE FROM process_peaks WHERE rowid IN (
                       SELECT rowid FROM process_peaks ORDER BY at_ms, rowid LIMIT ?
                   )""", (excess,),
            )
        self.db.execute("DELETE FROM process_connections WHERE last_seen_ms<?",
                        (observed_ms - CONNECTION_RETENTION_MS,))
        excess = self.db.execute("SELECT count(*) FROM process_connections").fetchone()[0] - self.max_connections
        if excess > 0:
            self.db.execute(
                """DELETE FROM process_connections WHERE rowid IN (
                       SELECT rowid FROM process_connections ORDER BY last_seen_ms, rowid LIMIT ?
                   )""", (excess,),
            )

    def record(self, boot_id, rows, observed_ms, connections=()):
        windows = [(seconds, bucket_start(observed_ms, seconds)) for seconds in self.periods.values()]
        prune_now = observed_ms >= self.next_prune_ms
        with self.db:
            self.db.executemany(UPSERT, (
                (seconds, boot_id, row["pid"], row["start_ticks"], at_ms, observed_ms,
                 *(measurement(row.get(metric)) for metric in METRICS))
                for row in rows
                for seconds, at_ms in windows
            ))
            self.db.executemany(UPSERT_CONNECTION, (
                (boot_id, pid, start_ticks, protocol, ip, port, local_port, state, observed_ms, observed_ms)
                for pid, start_ticks, protocol, ip, port, local_port, state in connections
            ))
            if prune_now:
                self.prune(observed_ms)
        if prune_now:
            self.next_prune_ms = observed_ms + PRUNE_INTERVAL_MS
            self.db.execute("PRAGMA incremental_vacuum(64)")


def read_history(pid, start_ticks, boot_id, hours, connection_offset=0, *, db_path=HISTORY_DB, now_ms=None):
    if (type(pid) is not int or not 0 < pid <= 2**31 - 1
            or type(start_ticks) is not int or not 0 <= start_ticks <= 2**53 - 1
            or not isinstance(boot_id, str) or not linux.BOOT_ID.fullmatch(boot_id)
            or type(hours) is not int or hours not in PERIODS
            or type(connection_offset) is not int or not 0 <= connection_offset <= MAX_CONNECTIONS):
        raise ValueError("Selección o período de proceso no válido.")
    seconds = PERIODS[hours]
    result = {"hours": hours, "bucket_seconds": seconds, "points": [], "started_at_ms": None,
              "connections": [], "connections_total": 0, "connections_offset": connection_offset}
    path = Path(db_path)
    if not path.is_file():
        return result
    now_ms = current_time_ms() if now_ms is None else now_ms
    cutoff_ms = now_ms - hours * 3_600_000
    first_bucket = bucket_start(cutoff_ms, seconds)
    last_bucket = bucket_start(now_ms, seconds)
    identity = (boot_id, pid, start_ticks)
    with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        result["points"] = [dict(row) for row in db.execute(
            """SELECT at_ms, cpu_percent, rss_bytes, rx_bps, tx_bps FROM process_peaks
               WHERE bucket_seconds=? AND boot_id=? AND pid=? AND start_ticks=?
                   AND at_ms BETWEEN ? AND ?
               ORDER BY at_ms""", (seconds, *identity, first_bucket, last_bucket),
        )]
        result["started_at_ms"] = db.execute(
            """SELECT min(first_at_ms) FROM process_peaks
               WHERE bucket_seconds IN (300, 1800, 7200)
                   AND boot_id=? AND pid=? AND start_ticks=? AND first_at_ms<=?""",
            (*identity, now_ms),
        ).fetchone()[0]
        connection_params = (*identity, cutoff_ms, now_ms)
        result["connections_total"] = db.execute(
            """SELECT count(*) FROM process_connections
               WHERE boot_id=? AND pid=? AND start_ticks=? AND last_seen_ms BETWEEN ? AND ?""",
            connection_params,
        ).fetchone()[0]
        result["connections"] = [dict(row) for row in db.execute(
            """SELECT protocol, ip, nullif(port, -1) AS port, nullif(local_port, -1) AS local_port,
                      state, first_seen_ms, last_seen_ms FROM process_connections
               WHERE boot_id=? AND pid=? AND start_ticks=? AND last_seen_ms BETWEEN ? AND ?
               ORDER BY last_seen_ms DESC, protocol, ip, port, local_port
               LIMIT ? OFFSET ?""",
            (*connection_params, CONNECTIONS_PER_PAGE, connection_offset),
        )]
    return result


def read_detail(pid, start_ticks, boot_id, window, *, db_path=DETAIL_DB, history_path=HISTORY_DB, now_ms=None):
    if (type(pid) is not int or not 0 < pid <= 2**31-1 or
        type(start_ticks) is not int or not 0 <= start_ticks <= 2**53-1 or
        not isinstance(boot_id,str) or not linux.BOOT_ID.fullmatch(boot_id) or
        not isinstance(window,str) or window not in DETAIL_WINDOWS):
        raise ValueError('Selección o ventana de proceso no válida.')
    duration, seconds = DETAIL_WINDOWS[window]
    now_ms = current_time_ms() if now_ms is None else now_ms
    result = dict(window=window, window_ms=duration*1000, bucket_seconds=seconds,
                  generated_at_ms=now_ms, started_at_ms=None, points=[])
    path = Path(history_path if window=='7d' else db_path)
    if not path.is_file():
        return result
    identity = (boot_id,pid,start_ticks)
    with closing(sqlite3.connect(path.absolute().as_uri()+'?mode=ro',uri=True,timeout=1)) as db:
        db.row_factory=sqlite3.Row
        result['points']=[dict(row) for row in db.execute(
            'SELECT at_ms,cpu_percent,rss_bytes,rx_bps,tx_bps FROM process_peaks '
            'WHERE bucket_seconds=? AND boot_id=? AND pid=? AND start_ticks=? AND at_ms BETWEEN ? AND ? '
            'ORDER BY at_ms LIMIT 3001',
            (seconds,*identity,bucket_start(now_ms-duration*1000,seconds),bucket_start(now_ms,seconds)))]
        result['started_at_ms']=db.execute(
            'SELECT min(first_at_ms) FROM process_peaks WHERE bucket_seconds=? AND boot_id=? AND pid=? AND start_ticks=?',
            (seconds,*identity)).fetchone()[0]
    return result


def memory_total_bytes():
    try:
        for line in (linux.PROC / "meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024 or None
    except (OSError, ValueError, IndexError):
        pass
    return None


@dataclass(frozen=True)
class Sample:
    boot_id: str
    at: float
    observed_ms: int
    clock_ticks: int
    processes: list
    tcp: Optional[list]
    udp: Optional[list] = None


def verified_socket_owners(processes, tcp, udp):
    expected = {row["pid"]: row["start_ticks"] for row in processes}
    observed = {pid for sockets in (tcp, udp) for socket in (sockets or ()) for pid in socket["pids"]}
    valid = set()
    for pid in observed:
        try:
            if pid in expected and linux.process_stat(pid)["start_ticks"] == expected[pid]:
                valid.add(pid)
        except (OSError, ValueError, IndexError):
            continue
    for sockets in (tcp, udp):
        if sockets is not None:
            for socket in sockets:
                socket["pids"] = [pid for pid in socket["pids"] if pid in valid]
            sockets[:] = [socket for socket in sockets if socket["pids"]]


def collect_sample():
    boot = linux.boot_id()
    netns = os.readlink(linux.PROC / "self/ns/net")
    processes, in_host_network = [], []
    for path in linux.PROC.iterdir():
        if not path.name.isdecimal():
            continue
        try:
            row = linux.process_stat(int(path.name))
        except (OSError, ValueError, IndexError):
            continue
        row["host_network"] = False
        if not row["flags"] & linux.KERNEL_THREAD:
            try:
                row["host_network"] = os.readlink(path / "ns/net") == netns
            except OSError:
                pass
        if row["host_network"]:
            in_host_network.append(row)
        from storypulse_process_learning import metadata
        row['learning_meta'] = None if row['flags'] & linux.KERNEL_THREAD else metadata(row['pid'], row['name'], linux.process_unit(row['pid']), linux.PROC, row['start_ticks'])
        processes.append(row)
    owners = linux.socket_owners(in_host_network)
    at, observed_ms = time.monotonic(), current_time_ms()
    tcp = linux.socket_sample("TCP", owners)
    udp = linux.socket_sample("UDP", owners)
    verified_socket_owners(processes, tcp, udp)
    return Sample(boot, at, observed_ms, os.sysconf("SC_CLK_TCK"), processes, tcp, udp)


def process_identity(row):
    return row["pid"], row["start_ticks"]


def connection_endpoints(sample):
    identities = {row["pid"]: row["start_ticks"] for row in sample.processes}
    seen = set()
    for sockets in (sample.tcp, sample.udp):
        for socket in sockets or ():
            if not socket["ip"]:
                continue
            port = socket["port"] if socket["port"] is not None else -1
            local_port = socket["local_port"] if socket["local_port"] is not None else -1
            for pid in socket["pids"]:
                if pid not in identities:
                    continue
                endpoint = (pid, identities[pid], socket["protocol"], socket["ip"], port, local_port)
                if endpoint not in seen:
                    seen.add(endpoint)
                    yield (*endpoint, socket["state"])


def tcp_rates(sample, previous, interval, prior_processes):
    prior_sockets = {socket["key"]: socket for socket in previous.tcp if socket["key"]}
    identities = {row["pid"]: process_identity(row) for row in sample.processes}
    connected, rates = set(), {}
    for socket in sample.tcp:
        if not socket["ip"]:
            continue
        connected.update(socket["pids"])
        old = prior_sockets.get(socket["key"])
        if not old or len(socket["pids"]) != 1 or socket["pids"] != old["pids"]:
            continue
        pid = socket["pids"][0]
        identity = identities.get(pid)
        if identity not in prior_processes:
            continue
        rx_delta = socket["rx_bytes"] - old["rx_bytes"]
        tx_delta = socket["tx_bytes"] - old["tx_bytes"]
        if rx_delta < 0 or tx_delta < 0:
            continue
        rx_bps, tx_bps = rates.get(identity, (0, 0))
        rates[identity] = (rx_bps + rx_delta / interval, tx_bps + tx_delta / interval)
    return connected, rates


def metrics(sample, previous):
    interval = sample.at - previous.at if previous and previous.boot_id == sample.boot_id else 0
    comparable = 0 < interval <= MAX_RATE_GAP_SECONDS
    prior = {process_identity(row): row for row in previous.processes} if comparable else {}
    tcp_available = comparable and sample.tcp is not None and previous.tcp is not None
    connected, rates = tcp_rates(sample, previous, interval, prior) if tcp_available else (set(), {})
    for row in sample.processes:
        identity = process_identity(row)
        older = prior.get(identity)
        cpu_percent = None
        if older and row["cpu_ticks"] >= older["cpu_ticks"]:
            cpu_percent = (row["cpu_ticks"] - older["cpu_ticks"]) * 100 / sample.clock_ticks / interval
        rx_bps, tx_bps = rates.get(identity, (None, None))
        if tcp_available and older and row["host_network"] and row["pid"] not in connected:
            rx_bps, tx_bps = 0, 0
        yield {
            "pid": row["pid"], "start_ticks": row["start_ticks"],
            "cpu_percent": cpu_percent, "rss_bytes": row["rss_bytes"],
            "rx_bps": rx_bps, "tx_bps": tx_bps, "learning_meta": row.get("learning_meta"),
        }


def main():
    os.umask(0o077)
    previous = None
    learning = None
    detail = None
    with closing(ProcessHistory()) as history:
        next_sample = time.monotonic()
        while True:
            try:
                sample = collect_sample()
                measured = list(metrics(sample, previous))
                history.record(sample.boot_id, measured, sample.observed_ms, connection_endpoints(sample))
                try:
                    if detail is None:
                        detail = ProcessHistory(DETAIL_DB, periods=DETAIL_PERIODS, max_rows=DETAIL_MAX_ROWS,
                                                max_connections=0, max_db_bytes=DETAIL_MAX_DB_BYTES)
                    detail.record(sample.boot_id, measured, sample.observed_ms)
                except (OSError,ValueError,sqlite3.Error) as error:
                    print(f'Historial detallado no disponible: {type(error).__name__}',file=sys.stderr,flush=True)
                try:
                    if learning is None:
                        from storypulse_process_learning import Learning
                        learning = Learning()
                    learning.record(measured, sample.observed_ms // 1000)
                except (ImportError, OSError, ValueError, sqlite3.Error, RuntimeError) as error:
                    print(f"Aprendizaje no disponible: {type(error).__name__}", file=sys.stderr, flush=True)
                previous = sample
            except (OSError, ValueError, sqlite3.Error) as error:
                print(f"No se pudo registrar una muestra de procesos: {error}", file=sys.stderr, flush=True)
                previous = None
            next_sample += SAMPLE_SECONDS
            now = time.monotonic()
            if next_sample <= now:
                next_sample = now + SAMPLE_SECONDS
            time.sleep(next_sample - now)


if __name__ == "__main__":
    main()
