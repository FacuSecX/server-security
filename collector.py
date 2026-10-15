#!/usr/bin/env python3
# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import csv
import importlib.util
from pathlib import Path
import base64
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile


MAX_EVENTS = 100000


def append_event(events, event):
    if len(events) >= MAX_EVENTS:
        raise RuntimeError("COLLECTION_TOO_LARGE: acortá el período de recolección")
    events.append(event)


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
    r"^\s*Accepted\s+(?P<method>publickey|password|keyboard-interactive(?:/pam)?|gssapi-with-mic|hostbased|none)\s+"
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
    
    provider_prefix = re.search(r"\bUFWVPS:(?P<slug>[a-z0-9_]+)\s", message)
    manual_prefix = re.search(r"\bSPMANUAL[46]:\s", message)
    reviewed_provider_prefix = re.search(r"\bSPPROVIDER[46]:\s", message)
    accepted_prefix = re.search(r"\bSPALLOW[46]:\s", message)
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


def provider_snapshots(firewall_text=None):
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
        for line in (firewall_text[binary] if firewall_text is not None else run([binary, "-c"])).splitlines():
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


def journal_lines(command, timeout=60):
    
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as output:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"journalctl terminó con código {result.returncode}")
        output.seek(0)
        yield from output


def journal_identity(event, row):
    
    event["legacy_id"] = event["id"]
    identity = row.get("__CURSOR") or f"{row['__REALTIME_TIMESTAMP']}|{row['MESSAGE']}"
    event["id"] = event_id(identity, event["kind"], "journal-v2")
    return event


def journal_events(since_epoch, provider_names, until_epoch=None):
    events = []
    since = f"@{max(0, int(since_epoch))}"

    options = ["--since", since, "-o", "json", "--no-pager",
               "--output-fields=MESSAGE,__REALTIME_TIMESTAMP,__CURSOR,_UID"]
    if until_epoch is not None:
        options.extend(["--until", f"@{max(0, int(until_epoch))}"])

    
    for raw in journal_lines(["journalctl", "_TRANSPORT=kernel", *options]):
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not isinstance(row.get("MESSAGE"), str):
            continue
        message = row["MESSAGE"]
        try:
            timestamp = int(row.get("__REALTIME_TIMESTAMP", "0") or 0) // 1_000_000
        except (TypeError, ValueError):
            continue
        if timestamp <= 0:
            continue
        event = firewall_event(timestamp, message, provider_names)
        if event:
            append_event(events, journal_identity(event, row))

    for raw in journal_lines(["journalctl", *options, "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session"]):
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not isinstance(row.get("MESSAGE"), str):
            continue
        message = row["MESSAGE"]
        try:
            timestamp = int(row.get("__REALTIME_TIMESTAMP", "0") or 0) // 1_000_000
        except (TypeError, ValueError):
            continue
        if timestamp <= 0:
            continue
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
        if kind=="ssh_success" and str(row.get("_UID","0"))!="0":continue
        ip = valid_ip(match.group("ip"))
        if not ip:
            continue
        method = match.groupdict().get("method", "") or ""
        user = match.groupdict().get("user", "") or ""
        append_event(events, journal_identity({
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
        }, row))

    return events


def nginx_events(since_epoch, until_epoch=None):
    events = []
    sources = (
        ("/var/log/nginx/access.log", "Acceso web"),
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
            if timestamp < since_epoch or (until_epoch is not None and timestamp > until_epoch):
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


def ssh_service():
    path=__import__('pathlib').Path('/etc/os-release')
    if path.is_file():
        values=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
        if values.get('ID','').strip('"') in ('centos','arch'):return 'sshd.service'
    return 'ssh.service'

def service_states():
    units = (
        ssh_service(), "nginx.service", "ufw.service",
        "storypulse-alerts.service", "ufw-vps-providers.service",
        "ufw-vps-providers.timer", "tailscaled.service",
        "storypulse-ftp.service", "vsftpd.service", "mysql.service",
        "mysqld.service", "mariadb.service",
    )
    
    output = run(["systemctl", "show", *units, "--no-page",
                  "--property=Id,LoadState,ActiveState,SubState,Type,Result"])
    by_unit = {}
    for block in output.strip().split("\n\n"):
        properties = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if properties.get("Id"): by_unit[properties["Id"]] = properties
    states = []
    ufw_active = bool(re.search(r"^Status:\s+active\s*$", run(["ufw","status"]), re.MULTILINE | re.IGNORECASE))
    for unit in units:
        properties = by_unit.get(unit, {})
        active = properties.get("ActiveState", "unknown")
        state = active
        if properties.get("LoadState") == "not-found":
            state = "missing"
        elif unit == "ufw.service" and ufw_active:
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


def system_snapshot(provider_count, firewall_text=None, services=None):
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
                1 for line in (firewall_text[binary] if firewall_text is not None else run([binary])).splitlines()
                if "StoryPulse accepted LOG" in line and "SPALLOW" in line
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
        "services": service_states() if services is None else services,
    }



ALERT_ENV_FILES = ("/etc/storypulse-alerts/telegram.env", "/etc/storypulse-security/alerts.env")


def sibling_module(name):
    directory=Path(__file__).resolve().parent
    if not (directory/(name+'.py')).is_file():directory=directory/'vps'
    
    if str(directory) not in sys.path:sys.path.insert(0,str(directory))
    spec=importlib.util.spec_from_file_location(name,directory/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def alert_policy(paths=None):
    module=sibling_module('storypulse_trusted')
    value=module.policy(ALERT_ENV_FILES if paths is None else paths)
    return value,[ipaddress.ip_network(ip,strict=False) for ip in value.get('authorized_ips',[])]


def monitored_services(states, listeners):
    
    active = {row['unit'] for row in states if row['state'] == 'active'}
    catalog = {'SSH': {'service': 'SSH', 'active': True, 'ports': []}}
    candidates = (
        ('FTP', ('storypulse-ftp.service', 'vsftpd.service'), r'"vsftpd"'),
        ('MySQL', ('mysql.service', 'mysqld.service'), r'"mysqld"'),
        ('MariaDB', ('mariadb.service',), r'"mariadbd"'),
    )
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        endpoint = fields[3] if fields[0] == 'LISTEN' else fields[4] if fields[0] == 'tcp' else ''
        try:
            port = int(endpoint.rsplit(':', 1)[1])
            if not 1 <= port <= 65535: continue
        except (IndexError, ValueError):
            continue
        if re.search(r'"sshd(?:-session)?"', line):
            catalog['SSH']['ports'].append(port)
        for name, units, process in candidates:
            if re.search(process, line) and (active.intersection(units) or 'users:(' in line):
                
                if name == 'MySQL' and 'mariadb.service' in active:
                    name = 'MariaDB'
                item = catalog.setdefault(name, {'service': name, 'active': True, 'ports': []})
                item['ports'].append(port)
                item.setdefault('pids',[]).extend(int(v) for v in re.findall(r'pid=(\d+)',line))
    for item in catalog.values(): item['ports'] = sorted(set(item['ports']))
    return list(catalog.values())


def classify_security_alerts(events, catalog, policy, networks):
    if not policy.get('ready'):return
    services={'ssh_success':'SSH','ftp_success':'FTP','mysql_success':'MySQL','mariadb_success':'MariaDB'}
    for event in events:
        event.pop('security_alert',None)
        service=services.get(event.get('kind'))
        if not service:continue  
        try:
            ip=ipaddress.ip_address(event['ip'])
            if getattr(ip,'ipv4_mapped',None):ip=ip.ipv4_mapped
        except (ValueError,KeyError):continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or any(ip in net for net in networks):continue
        event['security_alert']={'service':service,'type':'login'}


def service_auth_event(row):
    message=row.get('MESSAGE');identifier=row.get('SYSLOG_IDENTIFIER','');comm=row.get('_COMM','')
    if not isinstance(message,str):return None
    try:timestamp=int(row.get('__REALTIME_TIMESTAMP',0))//1000000
    except (TypeError,ValueError):return None
    if timestamp<1:return None
    service=kind=user=address=method=''
    if identifier=='vsftpd' or comm=='vsftpd':
        match=re.fullmatch(r'(?:\[pid \d+\] )?\[([^]\r\n"]{1,128})\] OK LOGIN: Client "([0-9A-Fa-f:.]+)"',message)
        if not match:return None
        user,address=match.groups();service,kind,method='FTP','ftp_success','ftp-login'
    elif identifier in ('storypulse-db-audit','mysql-server_auditing'):
        try:
            fields=next(csv.reader([message],quotechar="'"))
            
            if len(fields)==10:fields=fields[2:]
            if len(fields)!=8 or fields[4]!='CONNECT' or fields[7].strip()!='0':return None
            user,address=fields[0],fields[1]
            service,kind,method='MariaDB','mariadb_success','audit-connect'
        except (csv.Error,StopIteration):return None
    else:return None
    if method=='audit-connect' and fields[6].startswith('TLS'):
        host,sep,port=address.rpartition(':')
        if sep and port.isdigit():address=host.strip('[]')
    if '_UID' in row:
        import pwd
        allowed={0}
        for name in (('ftp','vsftpd','spftp') if service=='FTP' else ('mysql',)):
            try:allowed.add(pwd.getpwnam(name).pw_uid)
            except KeyError:pass
        try:
            if int(row['_UID']) not in allowed:return None
        except (TypeError,ValueError):return None
    ip=valid_ip(address)
    if not ip:return None
    return journal_identity(dict(id=event_id(timestamp,kind,message),timestamp=timestamp,kind=kind,ip=ip,
        provider_slug='',provider='',protocol='TCP',port='21' if service=='FTP' else '3306',service=service,
        decision='Permitido',ssh_user=user[:128],auth_method=method,details=service+' — inicio de sesión confirmado'),row)


def service_auth_events(since_epoch,until_epoch):
    args=['journalctl','--since','@'+str(since_epoch),'--until','@'+str(until_epoch),'-o','json','--no-pager',
          '--output-fields=MESSAGE,__REALTIME_TIMESTAMP,__CURSOR,SYSLOG_IDENTIFIER,_COMM,_UID',
          'SYSLOG_IDENTIFIER=vsftpd','+','_COMM=vsftpd','+','SYSLOG_IDENTIFIER=storypulse-db-audit','+','SYSLOG_IDENTIFIER=mysql-server_auditing']
    events=[]
    for raw in journal_lines(args):
        try:row=json.loads(raw)
        except ValueError:continue
        if not isinstance(row,dict):continue
        event=service_auth_event(row)
        if event and since_epoch<=event['timestamp']<=until_epoch:append_event(events,event)
    return events


def database_session_events(rows,service,instance,timestamp):
    events=[]
    for row in rows:
        user=str(row.get('USER') or '');command=str(row.get('COMMAND') or '')
        if not user or user.lower() in ('system user','unauthenticated user','event_scheduler') or command.lower() in ('connect','daemon','', 'connecting'):continue
        raw=str(row.get('HOST') or '');host,sep,port=raw.rpartition(':')
        ip=valid_ip(host.strip('[]')) if sep and port.isdigit() else valid_ip(raw.strip('[]'))
        if not ip:continue
        if ipaddress.ip_address(ip).is_loopback:continue
        try:connection_id=int(row['ID'])
        except (KeyError,ValueError,TypeError):continue
        if connection_id<1:continue
        kind='mariadb_success' if service=='MariaDB' else 'mysql_success'
        identity=hashlib.sha256((instance+'|'+str(connection_id)+'|'+user+'|'+ip).encode()).hexdigest()[:32]
        events.append(dict(id=identity,timestamp=timestamp,kind=kind,ip=ip,provider_slug='',provider='',protocol='TCP',
            port='3306',service=service,decision='Permitido',ssh_user=user[:128],auth_method='session-observed',
            details=service+' — sesión autenticada observada'))
    return events


def database_access_snapshot(catalog):
    databases=[item for item in catalog if item['service'] in ('MySQL','MariaDB')]
    if not databases:return [],[]
    try:
        module=sibling_module('storypulse_mysql');module.configure_platform()
        with module.connect(read_timeout=3) as connection:
            audit=module.query(connection,"SHOW GLOBAL VARIABLES WHERE Variable_name IN ('server_audit_logging','server_audit_events','server_audit_output_type','server_audit_syslog_ident')")
            settings={r['Variable_name'].lower():str(r['Value']) for r in audit}
            if (settings.get('server_audit_logging','').upper()=='ON' and 'CONNECT' in settings.get('server_audit_events','').upper().split(',') and
                settings.get('server_audit_output_type','').upper()=='SYSLOG' and settings.get('server_audit_syslog_ident') in ('storypulse-db-audit','mysql-server_auditing')):
                return [],[dict(service=item['service'],mode='audit',ready=True) for item in databases]
            rows=module.query(connection,"SELECT ID,USER,HOST,COMMAND FROM information_schema.PROCESSLIST WHERE USER IS NOT NULL LIMIT 1000")
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        instance=[]
        for item in databases:
            for pid in sorted(set(item.get('pids',[]))):
                raw=Path('/proc/'+str(pid)+'/stat').read_text();ticks=raw[raw.rfind(')')+2:].split()[19]
                instance.append(str(pid)+':'+ticks)
        if not instance:raise RuntimeError('Falta identidad de la instancia SQL')
        events=database_session_events(rows,databases[0]['service'],boot+'|'+','.join(instance),int(dt.datetime.now().timestamp()))
        return events,[dict(service=item['service'],mode='authenticated-sessions',ready=True,
            note='Sólo se notifican sesiones autenticadas observadas; las conexiones muy breves pueden no registrarse.') for item in databases]
    except Exception:
        return [],[dict(service=item['service'],mode='unavailable',ready=False,
            note='No hay una fuente disponible para confirmar autenticaciones. No se generan alertas por tráfico.') for item in databases]


def ftp_access_source(catalog):
    if not any(item['service']=='FTP' for item in catalog):return []
    ready=False
    for path in ('/etc/storypulse-ftp/vsftpd.conf','/etc/vsftpd.conf','/etc/vsftpd/vsftpd.conf'):
        try:text=Path(path).read_text()
        except (OSError,UnicodeError):continue
        settings=dict(re.findall(r'^([a-z_]+)=(\S+)\s*$',text,re.M))
        if settings.get('syslog_enable')=='YES' and (settings.get('dual_log_enable')=='YES' or settings.get('xferlog_std_format','NO')=='NO'):ready=True
    return [dict(service='FTP',mode='journal-auth',ready=ready,
                 note='' if ready else 'FTP debe registrar sus inicios de sesión en syslog; no se infiere acceso desde paquetes.')]


CLEANUP_MARKER = "/var/lib/storypulse-cleanup/reset.json"


def cleanup_marker():
    try:
        with open(CLEANUP_MARKER, encoding="utf-8") as source:
            value = json.load(source)
        if not isinstance(value, dict) or not isinstance(value.get("cutoff"), int) or not re.fullmatch(r"[a-f0-9]{32}", str(value.get("id", ""))):
            raise RuntimeError("Marcador de limpieza inválido")
        return value
    except FileNotFoundError:
        return None


def adjusted_providers(providers, reset):
    if not reset:
        return providers
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
        same_boot = source.read().strip() == reset.get("boot_id")
    for row in providers:
        base = reset.get("providers", {}).get(row["slug"], {}) if same_boot else {}
        for key in ("packets", "bytes", "ipv4_packets", "ipv6_packets"):
            row[key] = max(0, row[key] - base.get(key, 0))
    return providers


def main():
    try:
        since_epoch = int(sys.argv[1]) if len(sys.argv) > 1 else int(dt.datetime.now().timestamp()) - 86400
        
        
        until_epoch = int(sys.argv[3]) if len(sys.argv) > 3 else int(dt.datetime.now().timestamp())
        reset = cleanup_marker()
        effective_since = max(since_epoch, reset["cutoff"] if reset else 0)
        firewall_text = {binary:run([binary,"-c"]) if shutil.which(binary) else "" for binary in ("iptables-save","ip6tables-save")}
        providers = adjusted_providers(provider_snapshots(firewall_text), reset)
        names = {row["slug"]: row["name"] for row in providers}
        events = journal_events(effective_since, names, until_epoch) if effective_since <= until_epoch else []
        if effective_since <= until_epoch:
            events.extend(nginx_events(effective_since, until_epoch))
            events.extend(service_auth_events(effective_since, until_epoch))
        events.sort(key=lambda row: row["timestamp"])
        services = service_states()
        policy, networks = alert_policy()
        catalog = monitored_services(services, run(['ss', '-H', '-ltnp'], timeout=10))
        database_events,coverage=database_access_snapshot(catalog) if until_epoch>=int(dt.datetime.now().timestamp())-60 else ([],[])
        events.extend(database_events)
        classify_security_alerts(events, catalog, policy, networks)
        policy['access_sources']=[dict(service='SSH',mode='journal-auth',ready=True),*ftp_access_source(catalog),*coverage]
        if cleanup_marker() != reset:
            raise RuntimeError("Los registros se limpiaron durante la lectura; se reintentará")
        now = int(dt.datetime.now().timestamp())
        system = system_snapshot(len(providers), firewall_text, services)
        policy['network_logging'] = bool(system.get('accept_monitor', {}).get('enabled'))
        payload = {
            "cleanup_reset": reset,
            "ok": True,
            "generated_at": now,
            "since": since_epoch,
            "collected_until": until_epoch,
            "collector_ip": (valid_ip(sys.argv[2]) or "") if len(sys.argv) > 2 else "",
            "providers": providers,
            "events": events,
            "system": {**system,
                       "security_monitor": {**policy, "services": catalog}},
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(sys.argv) > 4 and sys.argv[4] == "gzip":
            packed = gzip.compress(encoded.encode("utf-8"), compresslevel=1, mtime=0)
            print("SPGZIP1:" + base64.b64encode(packed).decode("ascii"))
        else:
            print(encoded)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        raise


if __name__ == "__main__":
    main()
