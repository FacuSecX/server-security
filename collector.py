#!/usr/bin/env python3
"""Recolector efimero de solo lectura ejecutado por SSH en el VPS."""

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys


SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S",
    1433: "Microsoft SQL Server", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP alternativo", 8080: "HTTP alternativo",
    8443: "HTTPS alternativo", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

FAILED_SSH = re.compile(
    r"\bFailed\s+(?:password|publickey|keyboard-interactive(?:/pam)?|none|"
    r"hostbased|gssapi-with-mic)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9A-Fa-f:.]+)", re.I,
)
INVALID_SSH = re.compile(
    r"\bInvalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)", re.I,
)
ACCEPTED_SSH = re.compile(
    r"\bAccepted\s+(?P<method>publickey|password|keyboard-interactive(?:/pam)?)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)", re.I,
)
ACCESS_LOG = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^]]+)]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^\"]*\"\s+(?P<status>\d{3})"
)
UFW_ACTION = re.compile(
    r"\[UFW\s+(?P<action>ALLOW|BLOCK|REJECT|LIMIT\s+BLOCK)\]", re.I
)


def run(command, timeout=35):
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout,
        check=False,
    )
    return result.stdout


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def event_id(timestamp, kind, message):
    raw = f"{timestamp}|{kind}|{message}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:32]


def firewall_event(timestamp, message, provider_names):
    """Convierte un registro final del firewall en un evento del panel.

    Se ignoran deliberadamente los mensajes ``UFW AUDIT``: describen que una
    conexión nueva fue observada, pero no su decisión final. Contarlos como
    permitidos produciría falsos positivos.
    """
    provider_prefix = re.search(r"\bUFWVPS:(?P<slug>[a-z0-9_]+)\s", message)
    manual_prefix = re.search(r"\bSSMANUAL[46]:\s", message)
    reviewed_provider_prefix = re.search(r"\bSSPROVIDER[46]:\s", message)
    accepted_prefix = re.search(r"\bSSALLOW[46]:\s", message)
    ufw_match = UFW_ACTION.search(message)
    if not provider_prefix and not manual_prefix and not reviewed_provider_prefix and not accepted_prefix and not ufw_match:
        return None

    fields = dict(re.findall(r"\b([A-Z][A-Z0-9_]*)=([^\s]+)", message))
    ip = valid_ip(fields.get("SRC", ""))
    if not ip:
        return None

    protocol = fields.get("PROTO", "OTRO").upper()
    if protocol in ("TCP", "UDP"):
        port = fields.get("DPT", "-")
        try:
            service = SERVICE_NAMES.get(int(port), "Servicio desconocido")
        except ValueError:
            service = "Servicio desconocido"
    elif protocol in ("ICMP", "ICMPV6"):
        code = fields.get("TYPE", "-")
        port = f"tipo-{code}"
        is_echo = (protocol == "ICMP" and code == "8") or (protocol == "ICMPV6" and code == "128")
        service = "ICMP echo-request" if is_echo else "ICMP"
    else:
        port = "-"
        service = protocol

    if provider_prefix:
        slug = provider_prefix.group("slug")
        provider = provider_names.get(slug, slug)
        kind, decision = "firewall_block", "Bloqueado"
    elif manual_prefix:
        slug = "manual"
        provider = ""
        kind, decision = "firewall_block", "Bloqueado"
    elif reviewed_provider_prefix:
        slug = "reviewed_provider"
        provider = ""
        kind, decision = "firewall_block", "Bloqueado"
    elif accepted_prefix:
        slug = ""
        provider = ""
        kind, decision = "firewall_allow", "Permitido"
    else:
        action = re.sub(r"\s+", " ", ufw_match.group("action").upper())
        allowed = action == "ALLOW"
        slug = ""
        provider = ""
        kind = "firewall_allow" if allowed else "firewall_block"
        decision = "Permitido" if allowed else "Bloqueado"

    # Mantiene el identificador histórico de UFW-VPS para no duplicar en la
    # base local los últimos segundos que se solapan entre dos recolecciones.
    id_kind = "firewall" if provider_prefix else kind
    return {
        "id": event_id(timestamp, id_kind, message),
        "timestamp": timestamp,
        "kind": kind,
        "ip": ip,
        "provider_slug": slug,
        "provider": provider,
        "protocol": protocol,
        "port": str(port),
        "service": service,
        "decision": decision,
        "ssh_user": "",
        "auth_method": "",
        "details": f"{protocol}/{port} — {service}",
    }


def provider_snapshots():
    providers = {}
    entry_counts = {}
    rule_pattern = re.compile(
        r"^\[(?P<packets>\d+):(?P<bytes>\d+)]\s+.*?"
        r"--match-set\s+uvp_(?P<set>\S+)\s+src\s+.*?"
        r"--comment\s+\"UFW-VPS:\s*(?P<name>[^\"]+)\".*?-j\s+DROP\s*$"
    )
    set_pattern = re.compile(r"^(?P<slug>.+?)(?P<family>[46])$")

    for binary in ("iptables-save", "ip6tables-save"):
        if not shutil.which(binary):
            continue
        for line in run([binary, "-c"]).splitlines():
            match = rule_pattern.search(line)
            if not match:
                continue
            set_match = set_pattern.match(match.group("set"))
            if not set_match:
                continue
            slug = set_match.group("slug")
            item = providers.setdefault(slug, {
                "slug": slug,
                "name": match.group("name").strip(),
                "packets": 0,
                "bytes": 0,
                "ipv4_packets": 0,
                "ipv6_packets": 0,
                "ipv4_entries": 0,
                "ipv6_entries": 0,
                "entries": 0,
            })
            packets = int(match.group("packets"))
            item["packets"] += packets
            item["bytes"] += int(match.group("bytes"))
            item[f"ipv{set_match.group('family')}_packets"] += packets

    # Una sola lectura de ipset permite mostrar cuántos rangos/direcciones
    # componen realmente cada proveedor, sin ejecutar un comando por regla.
    if shutil.which("ipset"):
        add_pattern = re.compile(r"^add\s+uvp_(?P<slug>.+?)(?P<family>[46])\s+\S+")
        for line in run(["ipset", "save"], 60).splitlines():
            match = add_pattern.match(line)
            if not match:
                continue
            key = (match.group("slug"), match.group("family"))
            entry_counts[key] = entry_counts.get(key, 0) + 1

    for slug, item in providers.items():
        item["ipv4_entries"] = entry_counts.get((slug, "4"), 0)
        item["ipv6_entries"] = entry_counts.get((slug, "6"), 0)
        item["entries"] = item["ipv4_entries"] + item["ipv6_entries"]

    return sorted(providers.values(), key=lambda row: row["packets"], reverse=True)


def journal_events(since_epoch, provider_names):
    events = []
    since = f"@{max(0, int(since_epoch))}"

    kernel = run(["journalctl", "-k", "--since", since, "-o", "json", "--no-pager"], 60)
    for raw in kernel.splitlines():
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        message = str(row.get("MESSAGE", ""))
        timestamp = int(row.get("__REALTIME_TIMESTAMP", "0") or 0) // 1_000_000
        event = firewall_event(timestamp, message, provider_names)
        if event:
            events.append(event)

    ssh = run(["journalctl", "-u", "ssh.service", "--since", since, "-o", "json", "--no-pager"], 60)
    for raw in ssh.splitlines():
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        message = str(row.get("MESSAGE", ""))
        timestamp = int(row.get("__REALTIME_TIMESTAMP", "0") or 0) // 1_000_000
        match = ACCEPTED_SSH.search(message)
        if match:
            kind, decision = "ssh_success", "Permitido"
        else:
            match = FAILED_SSH.search(message)
            if match:
                kind, decision = "ssh_failure", "Fallido"
            else:
                match = INVALID_SSH.search(message)
                if not match:
                    continue
                kind, decision = "ssh_invalid_user", "Fallido"
        ip = valid_ip(match.group("ip"))
        if not ip:
            continue
        method = match.groupdict().get("method", "") or ""
        user = match.groupdict().get("user", "") or ""
        events.append({
            "id": event_id(timestamp, kind, message),
            "timestamp": timestamp,
            "kind": kind,
            "ip": ip,
            "provider_slug": "",
            "provider": "",
            "protocol": "TCP",
            "port": "22",
            "service": "SSH",
            "decision": decision,
            "ssh_user": user,
            "auth_method": method,
            "details": f"SSH {decision.lower()} — usuario {user}",
        })

    return events


def nginx_events(since_epoch):
    events = []
    sources = (
        ("/var/log/nginx/access.log", "Acceso Nginx"),
    )
    for path, label in sources:
        if not os.path.isfile(path):
            continue
        for line in run(["tail", "-n", "2500", path]).splitlines():
            match = ACCESS_LOG.search(line)
            if not match:
                continue
            try:
                when = dt.datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                timestamp = int(when.timestamp())
            except ValueError:
                continue
            if timestamp < since_epoch:
                continue
            ip = valid_ip(match.group("ip"))
            if not ip:
                continue
            status = int(match.group("status"))
            decision = "Permitido" if status < 400 else "Rechazado"
            detail = f"{label}: {match.group('method')} {match.group('path')} — HTTP {status}"
            events.append({
                "id": event_id(timestamp, "web", line),
                "timestamp": timestamp,
                "kind": "web",
                "ip": ip,
                "provider_slug": "",
                "provider": "",
                "protocol": "TCP",
                "port": "443",
                "service": "HTTPS",
                "decision": decision,
                "ssh_user": "",
                "auth_method": "",
                "details": detail,
            })
    return events


def service_states():
    units = (
        "ssh.service", "nginx.service", "ufw.service",
        "server-security-manual-blocks.service", "ufw-vps-providers.service",
        "ufw-vps-providers.timer", "tailscaled.service",
    )
    states = []
    for unit in units:
        output = run([
            "systemctl", "show", unit, "--no-page",
            "--property=LoadState", "--property=ActiveState",
            "--property=SubState", "--property=Type", "--property=Result",
        ])
        properties = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key] = value

        active = properties.get("ActiveState", "unknown")
        state = active
        if properties.get("LoadState") == "not-found":
            state = "missing"
        elif unit == "ufw.service" and re.search(
            r"^Status:\s+active\s*$", run(["ufw", "status"]), re.MULTILINE | re.IGNORECASE
        ):
            state = "active"
        elif (
            properties.get("Type") == "oneshot"
            and properties.get("Result") == "success"
            and active == "inactive"
        ):
            state = "completed"

        states.append({
            "unit": unit,
            "state": state or "unknown",
            "active_state": active,
            "sub_state": properties.get("SubState", ""),
            "result": properties.get("Result", ""),
        })
    return states


def system_snapshot(provider_count):
    disk = shutil.disk_usage("/")
    try:
        uptime = int(float(open("/proc/uptime", encoding="ascii").read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = 0

    memory_total = memory_available = 0
    try:
        values = {}
        with open("/proc/meminfo", encoding="ascii") as source:
            for line in source:
                key, value = line.split(":", 1)
                values[key] = int(value.strip().split()[0]) * 1024
        memory_total = values.get("MemTotal", 0)
        memory_available = values.get("MemAvailable", 0)
    except (OSError, ValueError, IndexError):
        pass

    tailscale_ip = run(["tailscale", "ip", "-4"]).strip() if shutil.which("tailscale") else ""
    ufw_verbose = run(["ufw", "status", "verbose"]) if shutil.which("ufw") else ""
    logging_match = re.search(
        r"^Logging:\s+(?P<state>on|off)(?:\s+\((?P<level>[^)]+)\))?",
        ufw_verbose,
        re.MULTILINE | re.IGNORECASE,
    )
    ufw_logging = {
        "enabled": bool(logging_match and logging_match.group("state").lower() == "on"),
        "level": (logging_match.group("level") or "off").lower() if logging_match else "unknown",
    }
    accept_monitor_counts = {"ipv4": 0, "ipv6": 0}
    for family, binary in (("ipv4", "iptables-save"), ("ipv6", "ip6tables-save")):
        if shutil.which(binary):
            accept_monitor_counts[family] = sum(
                1 for line in run([binary]).splitlines()
                if "Server Security accepted LOG" in line and "SSALLOW" in line
            )
    return {
        "hostname": socket.gethostname(),
        "uptime_seconds": uptime,
        "disk_total": disk.total,
        "disk_used": disk.used,
        "disk_percent": round((disk.used / disk.total) * 100, 1) if disk.total else 0,
        "memory_total": memory_total,
        "memory_used": max(0, memory_total - memory_available),
        "memory_percent": round(((memory_total - memory_available) / memory_total) * 100, 1) if memory_total else 0,
        "tailscale_ip": tailscale_ip,
        "provider_rules": provider_count,
        "ufw_logging": ufw_logging,
        "accept_monitor": {
            **accept_monitor_counts,
            "rules": accept_monitor_counts["ipv4"] + accept_monitor_counts["ipv6"],
            "enabled": (accept_monitor_counts["ipv4"] + accept_monitor_counts["ipv6"]) > 0,
        },
        "services": service_states(),
    }


def main():
    try:
        since_epoch = int(sys.argv[1]) if len(sys.argv) > 1 else int(dt.datetime.now().timestamp()) - 86400
        providers = provider_snapshots()
        names = {row["slug"]: row["name"] for row in providers}
        events = journal_events(since_epoch, names)
        events.extend(nginx_events(since_epoch))
        events.sort(key=lambda row: row["timestamp"])
        now = int(dt.datetime.now().timestamp())
        payload = {
            "ok": True,
            "generated_at": now,
            "since": since_epoch,
            "collector_ip": (valid_ip(sys.argv[2]) or "") if len(sys.argv) > 2 else "",
            "providers": providers,
            "events": events,
            "system": system_snapshot(len(providers)),
        }
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        raise


if __name__ == "__main__":
    main()
