# ==========================================
# Panel Seguridad Monitor v4
# Created by FacuSecX
# https://github.com/FacuSecX/
# ==========================================
"""Sample Linux process resources and control an identified process or systemd service."""

import ipaddress
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import time

PROC = Path("/proc")
TCP_RX = re.compile(r"\bbytes_received:(\d+)")
TCP_TX = re.compile(r"\bbytes_acked:(\d+)")
SOCKET_COOKIE = re.compile(r"\bsk:([0-9a-f]+)\b")
SOCKET_INODE = re.compile(r"\bino:(\d+)\b")
FD_SOCKET = re.compile(r"socket:\[(\d+)\]")
UNIT_NAME = re.compile(r"[A-Za-z0-9_.@:\\-]{1,240}\.service")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
PROTECTED_NAMES = {"sshd", "sshd-session", "sshd-auth", "systemd", "tailscaled",
                   "NetworkManager", "systemd-network", "systemd-resolve"}
PROTECTED_UNITS = {"ssh.service", "sshd.service", "tailscaled.service", "NetworkManager.service",
                   "networking.service", "systemd-networkd.service", "systemd-resolved.service"}
KERNEL_THREAD = 0x00200000


def boot_id():
    return (PROC / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def process_stat(pid):
    raw = (PROC / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    start, end = raw.index("("), raw.rindex(")")
    fields = raw[end + 2:].split()
    return {"pid": pid, "name": raw[start + 1:end], "state": fields[0], "parent": int(fields[1]),
            "flags": int(fields[6]), "cpu_ticks": int(fields[11]) + int(fields[12]),
            "start_ticks": int(fields[19]), "rss_bytes": max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE")}


def process_unit(pid):
    groups = (PROC / str(pid) / "cgroup").read_text(encoding="ascii", errors="replace")
    for line in groups.splitlines():
        _, _, group = line.partition(":/")
        if not group.startswith("system.slice/"):
            continue
        for item in reversed(group.split("/")):
            if UNIT_NAME.fullmatch(item):
                return item
    return ""


def command(args, timeout=5, check=True):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, check=check,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def service_pids(units):
    if not units:
        return {}
    output = command(["/usr/bin/systemctl", "show", "--property=Id", "--property=MainPID",
                      "--", *sorted(units)], check=False).stdout
    result = {}
    for block in output.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        pid = fields.get("MainPID", "")
        if fields.get("Id") in units and pid.isdecimal() and int(pid) > 0:
            result[fields["Id"]] = int(pid)
    return result


def protected(row):
    name, unit = row["name"], row["unit"]
    return (row["pid"] <= 2 or row["flags"] & KERNEL_THREAD or row["state"] in {"Z", "X"}
            or name in PROTECTED_NAMES or unit in PROTECTED_UNITS
            or unit.startswith(("ssh@", "sshd@")))


def command_ancestors():
    result = set()
    pid = os.getpid()
    while pid > 0 and pid not in result:
        result.add(pid)
        try:
            pid = process_stat(pid)["parent"]
        except (OSError, ValueError, IndexError):
            break
    return result


def endpoint(value):
    ip, _, port = value.rpartition(":")
    ip = ip.strip("[]")
    address = ip.split("%", 1)[0]
    try:
        ip = address if not ipaddress.ip_address(address).is_unspecified else ""
    except ValueError:
        ip = ""
    return ip, int(port) if port.isdecimal() else None


def parse_sockets(output, protocol, owners):
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 5)
        if len(parts) != 6:
            continue
        state, _, _, local, remote, info = parts
        inode = SOCKET_INODE.search(info)
        pids = sorted(owners.get(inode[1], ())) if inode else []
        if not pids:
            continue
        local_ip, local_port = endpoint(local)
        remote_ip, remote_port = endpoint(remote)
        cookie = SOCKET_COOKIE.search(info)
        tcp = protocol == "TCP" and remote_ip and cookie and cookie[1] != "0"
        sent, received = TCP_TX.search(info), TCP_RX.search(info)
        rows.append({"pids": pids, "protocol": protocol, "state": state,
                     "local_ip": local_ip, "local_port": local_port,
                     "ip": remote_ip, "port": remote_port,
                     "key": cookie[1] if tcp else None,
                     "tx_bytes": int(sent[1]) if tcp and sent else 0 if tcp else None,
                     "rx_bytes": int(received[1]) if tcp and received else 0 if tcp else None})
    return rows


def socket_sample(protocol, owners):
    args = ["/usr/bin/ss", "-H", "-n", "-a", "-e", "-O"]
    args.extend(["-t", "-i"] if protocol == "TCP" else ["-u"])
    try:
        return parse_sockets(command(args).stdout, protocol, owners)
    except (OSError, subprocess.SubprocessError):
        return None


def socket_owners(processes):
    owners = {}
    for row in processes:
        try:
            with os.scandir(PROC / str(row["pid"]) / "fd") as entries:
                for entry in entries:
                    try:
                        socket = FD_SOCKET.fullmatch(os.readlink(entry.path))
                    except OSError:
                        continue
                    if socket:
                        owners.setdefault(socket[1], set()).add(row["pid"])
        except OSError:
            continue
    return owners


def snapshot(body):
    if body != {}:
        raise RuntimeError("La consulta de procesos no acepta parámetros.")
    boot = boot_id()
    netns = os.readlink(PROC / "self/ns/net")
    users = {user.pw_uid: user.pw_name for user in pwd.getpwall()}
    ancestors = command_ancestors()
    processes = []
    for directory in PROC.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            row = process_stat(int(directory.name))
            # procfs directory ownership can change on setuid and non-dumpable processes.
            status = (directory / "status").read_text(encoding="ascii", errors="replace")
            uid = int(next(line for line in status.splitlines() if line.startswith("Uid:")).split()[2])
            row["user"] = users.get(uid, str(uid))
            row["unit"] = process_unit(row["pid"])
        except (OSError, ValueError, IndexError, StopIteration):
            continue
        try:
            row["host_network"] = os.readlink(directory / "ns/net") == netns
        except OSError:
            row["host_network"] = False
        row["can_stop"] = not protected(row) and row["pid"] not in ancestors
        processes.append(row)
    from storypulse_process_learning import metadata
    for row in processes:
        row['learning_status'] = 'kernel' if row['flags'] & KERNEL_THREAD else 'waiting'
        row['learning_meta'] = None if row['learning_status']=='kernel' else metadata(row['pid'], row['name'], row['unit'], PROC, row['start_ticks'])
    owners = socket_owners(processes)
    at = time.monotonic()
    tcp = socket_sample("TCP", owners)
    udp = socket_sample("UDP", owners)
    try:
        units = service_pids({row["unit"] for row in processes if row["can_stop"] and row["unit"]})
    except (OSError, subprocess.SubprocessError):
        units = {}
    for row in processes:
        row["can_restart"] = row["can_stop"] and units.get(row["unit"]) == row["pid"]
        del row["flags"], row["parent"]
    return {"ok": True, "boot_id": boot, "sample_at": at, "clock_ticks": os.sysconf("SC_CLK_TCK"),
            "tcp_available": tcp is not None, "udp_available": udp is not None,
            "processes": processes, "sockets": (tcp or []) + (udp or [])}


def change(body):
    if (not isinstance(body, dict) or set(body) != {"pid", "start_ticks", "boot_id", "action", "confirm"}
            or type(body["pid"]) is not int or not 2 < body["pid"] <= 2**31 - 1
            or type(body["start_ticks"]) is not int or body["start_ticks"] < 0
            or not isinstance(body["boot_id"], str) or not BOOT_ID.fullmatch(body["boot_id"])
            or body["action"] not in ("stop", "restart") or body["confirm"] is not True):
        raise RuntimeError("Revisá el proceso y confirmá la acción.")
    pid = body["pid"]
    try:
        if body["boot_id"] != boot_id():
            raise RuntimeError("El servidor se reinició. Actualizá la lista de procesos.")
        process = os.pidfd_open(pid)
        try:
            row = process_stat(pid)
            if row["start_ticks"] != body["start_ticks"]:
                raise RuntimeError("El proceso cambió. Actualizá la lista de procesos.")
            row["unit"] = process_unit(pid)
            if protected(row) or pid in command_ancestors():
                raise RuntimeError("Este proceso está protegido.")
            unit = row["unit"]
            main = unit and service_pids({unit}).get(unit) == pid
            action = body["action"]
            if action == "restart" and not main:
                raise RuntimeError("El proceso no es el principal de un servicio administrado por systemd.")
            if main:
                signal.pidfd_send_signal(process, 0)
                command(["/usr/bin/systemctl", action, "--", unit], timeout=30)
            else:
                signal.pidfd_send_signal(process, signal.SIGTERM)
        finally:
            os.close(process)
    except (FileNotFoundError, ProcessLookupError):
        raise RuntimeError("El proceso ya no está activo. Actualizá la lista de procesos.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("El servicio aún puede estar procesando la acción. Actualizá antes de reintentar.") from None
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        raise RuntimeError("No se pudo ejecutar la acción sobre este proceso.") from None
    return {"ok": True, "pid": pid, "action": action, "unit": unit if main else ""}
