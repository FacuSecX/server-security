#!/usr/bin/python3 -I
# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
import argparse
import datetime as dt
import fcntl
from functools import lru_cache
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))


CONFIG_DIR = pathlib.Path("/etc/storypulse-security")
CONFIG_PATH = CONFIG_DIR / "manual-blocks.json"
PROVIDER_CONFIG_PATH = CONFIG_DIR / "provider-blocks.json"
AUDIT_PATH = pathlib.Path("/var/log/storypulse-security-blocks.jsonl")
LOCK_PATH = pathlib.Path("/run/lock/storypulse-securityctl.lock")
REPORT_LOCK_PATH = pathlib.Path("/run/lock/storypulse-ssh-report.lock")
REPORT_OUTPUT_DIR = pathlib.Path("/var/lib/storypulse-security/Informes/SSH/archivos")
REPORT_MAX_MINUTES = 7 * 24 * 60
REPORT_TIMEOUT = 30 * 60

SETS = {4: "sp_manual4", 6: "sp_manual6"}
PROVIDER_SETS = {4: "sp_provider4", 6: "sp_provider6"}
CHAINS = {4: "ufw-before-input", 6: "ufw6-before-input"}
BINARIES = {4: "iptables", 6: "ip6tables"}
FAMILIES = {4: "inet", 6: "inet6"}
USER_CHAINS = {4: "ufw-user-input", 6: "ufw6-user-input"}
SAVE_BINARIES = {4: "iptables-save", 6: "ip6tables-save"}
ACCEPT_MONITOR_COMMENT = "StoryPulse accepted LOG"



PROTECTED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "100.64.0.0/10",          
    "fd7a:115c:a1e0::/48",    
    
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
))


class ControlError(RuntimeError):
    pass


def run(command, *, check=True):
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
        timeout=30,
    )
    if check and result.returncode:
        message = (result.stderr or result.stdout or "comando fallido").strip()
        raise ControlError(f"{command[0]}: {message}")
    return result


def emit(payload, status=0):
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    raise SystemExit(status)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sanitized_reason(value):
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > 160:
        raise ControlError("El motivo no puede superar 160 caracteres")
    return text or "Bloqueo manual desde el panel local"


@lru_cache(maxsize=1)
def read_protected_networks(path, identity):
    try:
        values=json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        if not isinstance(values,list) or len(values)>256 or any(not isinstance(value,str) for value in values): raise ValueError()
        return PROTECTED_NETWORKS+tuple(ipaddress.ip_network(value,strict=True) for value in values)
    except (ValueError,TypeError,OSError) as exc:
        raise ControlError("La configuración de redes protegidas no es válida; no se modificó el firewall.") from exc


def protected_networks():
    path=CONFIG_DIR / "protected-networks.json"
    try: info=path.stat()
    except FileNotFoundError:return PROTECTED_NETWORKS
    except OSError as exc:raise ControlError("No se pudieron leer las redes protegidas.") from exc
    if path.is_symlink() or info.st_size>65536 or (os.name=='posix' and (info.st_uid!=0 or info.st_mode&0o022)):
        raise ControlError("El archivo de redes protegidas no tiene permisos seguros.")
    
    return read_protected_networks(str(path),(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_size))


def parse_public_ip(value):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ControlError("La dirección IP no es válida") from exc
    if not address.is_global or address.is_multicast or address.is_reserved or getattr(address, "ipv4_mapped", None) is not None or "%" in str(address):
        raise ControlError("Sólo se pueden bloquear direcciones públicas globales")
    if any(address in network for network in protected_networks()):
        raise ControlError("La dirección pertenece a una red protegida y no puede bloquearse")
    return address


def parse_public_network(value):
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=True)
    except ValueError as exc:
        raise ControlError("El prefijo de red no es válido o no está normalizado") from exc
    if not network.is_global or network.is_multicast or network.is_reserved:
        raise ControlError("Sólo se pueden bloquear prefijos públicos globales")
    if any(network.overlaps(protected) for protected in protected_networks() if protected.version == network.version):
        raise ControlError("El prefijo se superpone con una red protegida")
    return network


def parse_asn(value):
    match = re.fullmatch(r"(?:AS)?([0-9]{1,10})", str(value or "").strip(), re.IGNORECASE)
    if not match:
        raise ControlError("El ASN no es válido")
    number = int(match.group(1))
    if number < 1 or number > 4294967295:
        raise ControlError("El ASN está fuera del rango permitido")
    return f"AS{number}"


def sanitized_provider_name(value):
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    text = re.sub(r"\s+", " ", text)
    if not text or len(text) > 120:
        raise ControlError("El nombre del proveedor no es válido")
    return text


def prefix_digest(asn, prefixes):
    canonical = sorted(str(parse_public_network(value)) for value in prefixes)
    material = json.dumps({"asn": parse_asn(asn), "prefixes": canonical}, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def locked():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LOCK_PATH.open("a+", encoding="utf-8")
    try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | getattr(fcntl,"LOCK_NB",4))
    except BlockingIOError as exc:
        handle.close(); raise ControlError("Hay otra operación de red en curso. Reintentá en un momento.") from exc
    return handle


def report_locked():
    
    REPORT_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = REPORT_LOCK_PATH.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | getattr(fcntl, "LOCK_NB", 4))
    except BlockingIOError as exc:
        handle.close()
        raise ControlError("Ya hay un reporte SSH en proceso") from exc
    return handle


def report_minutes(payload):
    value = payload.get("minutes")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ControlError("El período del reporte debe indicarse en minutos enteros")
    if value < 1 or value > REPORT_MAX_MINUTES:
        raise ControlError("El período permitido es de 1 minuto a 7 días")
    return value


def report_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("storypulse_report", pathlib.Path(__file__).with_name("storypulse_report.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def generate_ssh_report(payload):
    report_minutes(payload)
    try: return report_module().generate(payload)
    except RuntimeError as exc: raise ControlError(str(exc)) from exc


def collect_request(payload):
    if not isinstance(payload,dict) or set(payload) != {"since","until"}:
        raise ControlError("La recolección sólo admite los límites de fecha.")
    since,until = payload["since"],payload["until"]
    if type(since) is not int or type(until) is not int or since<0 or until<since or until-since>86400:
        raise ControlError("La recolección admite un intervalo de hasta 24 horas.")
    source = os.environ.get("SSH_CONNECTION", "").split(" ")[0]
    try: source = str(ipaddress.ip_address(source))
    except ValueError: source = ""
    return ["/usr/bin/python3", "-I", str(pathlib.Path(__file__).with_name("storypulse_collector.py")), str(since),source,str(until),"gzip"]


def load_entries():
    if not CONFIG_PATH.exists():
        return []
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(f"No se pudo leer {CONFIG_PATH}: {exc}") from exc
    if not isinstance(raw, list):
        raise ControlError("El archivo de bloqueos manuales no contiene una lista válida")
    result = []
    seen = set()
    for item in raw:
        try:
            address = parse_public_ip(item.get("ip", ""))
        except (AttributeError, ControlError) as exc:
            raise ControlError("Hay un bloqueo manual inválido guardado; no se modificó el firewall") from exc
        canonical = str(address)
        if canonical in seen:
            continue
        seen.add(canonical)
        result.append({
            "ip": canonical,
            "family": address.version,
            "reason": sanitized_reason(item.get("reason", "")),
            "created_at": str(item.get("created_at", "")) or utc_now(),
        })
    return sorted(result, key=lambda item: (item["family"], item["ip"]))


def save_entries(entries):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="manual-blocks-", suffix=".json", dir=CONFIG_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(entries, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, CONFIG_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_provider_entries():
    if not PROVIDER_CONFIG_PATH.exists():
        return []
    try:
        raw = json.loads(PROVIDER_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(f"No se pudo leer {PROVIDER_CONFIG_PATH}: {exc}") from exc
    if not isinstance(raw, list):
        raise ControlError("El archivo de proveedores bloqueados no contiene una lista válida")
    result = []
    seen = set()
    for item in raw:
        try:
            asn = parse_asn(item.get("asn", ""))
            name = sanitized_provider_name(item.get("name", ""))
            prefixes = sorted({str(parse_public_network(value)) for value in item.get("prefixes", [])})
            digest = prefix_digest(asn, prefixes)
        except (AttributeError, TypeError, ControlError) as exc:
            raise ControlError("Hay un proveedor inválido guardado; no se modificó el firewall") from exc
        if not prefixes:
            raise ControlError("Hay un proveedor guardado sin prefijos; no se modificó el firewall")
        if asn in seen:
            continue
        seen.add(asn)
        result.append({
            "asn": asn,
            "name": name,
            "prefixes": prefixes,
            "ipv4": sum(1 for value in prefixes if ipaddress.ip_network(value).version == 4),
            "ipv6": sum(1 for value in prefixes if ipaddress.ip_network(value).version == 6),
            "prefix_digest": digest,
            "reason": sanitized_reason(item.get("reason", "Proveedor confirmado desde el panel local")),
            "created_at": str(item.get("created_at", "")) or utc_now(),
        })
    return sorted(result, key=lambda item: int(item["asn"][2:]))


def save_provider_entries(entries):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="provider-blocks-", suffix=".json", dir=CONFIG_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(entries, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, PROVIDER_CONFIG_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def audit(action, target, reason, changed):
    record = {
        "timestamp": utc_now(),
        "action": action,
        "target": str(target),
        "reason": reason,
        "changed": bool(changed),
    }
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(AUDIT_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)


def rule_specs(version):
    set_name = SETS[version]
    family = "IPv4" if version == 4 else "IPv6"
    common = ["-m", "set", "--match-set", set_name, "src"]
    log = common + [
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "limit", "--limit", "10/minute", "--limit-burst", "20",
        "-m", "comment", "--comment", f"StoryPulse manual LOG {family}",
        "-j", "LOG", "--log-prefix", f"SPMANUAL{version}: ", "--log-level", "4",
    ]
    drop = common + [
        "-m", "comment", "--comment", f"StoryPulse manual DROP {family}",
        "-j", "DROP",
    ]
    return log, drop


def provider_rule_specs(version):
    set_name = PROVIDER_SETS[version]
    family = "IPv4" if version == 4 else "IPv6"
    common = ["-m", "set", "--match-set", set_name, "src"]
    log = common + [
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "limit", "--limit", "10/minute", "--limit-burst", "20",
        "-m", "comment", "--comment", f"StoryPulse provider LOG {family}",
        "-j", "LOG", "--log-prefix", f"SPPROVIDER{version}: ", "--log-level", "4",
    ]
    drop = common + [
        "-m", "comment", "--comment", f"StoryPulse provider DROP {family}",
        "-j", "DROP",
    ]
    return log, drop


def rule_exists(version, spec):
    result = run([BINARIES[version], "-C", CHAINS[version], *spec], check=False)
    return result.returncode == 0


def insertion_position(version):
    output = run([BINARIES[version], "-L", CHAINS[version], "-n", "--line-numbers"]).stdout
    admin_set = f"uvp_admin{version}"
    for line in output.splitlines():
        if admin_set in line and "ACCEPT" in line:
            try:
                return int(line.split()[0]) + 1
            except (ValueError, IndexError):
                break
    return 1


def ensure_rules(version):
    binary = BINARIES[version]
    chain = CHAINS[version]
    log_spec, drop_spec = rule_specs(version)
    log_present = rule_exists(version, log_spec)
    drop_present = rule_exists(version, drop_spec)
    if log_present and drop_present:
        return
    
    if log_present:
        run([binary, "-D", chain, *log_spec])
    if drop_present:
        run([binary, "-D", chain, *drop_spec])
    position = insertion_position(version)
    run([binary, "-I", chain, str(position), *drop_spec])
    run([binary, "-I", chain, str(position), *log_spec])


def ensure_provider_rules(version):
    binary = BINARIES[version]
    chain = CHAINS[version]
    log_spec, drop_spec = provider_rule_specs(version)
    log_present = rule_exists(version, log_spec)
    drop_present = rule_exists(version, drop_spec)
    if log_present and drop_present:
        return
    if log_present:
        run([binary, "-D", chain, *log_spec])
    if drop_present:
        run([binary, "-D", chain, *drop_spec])
    position = insertion_position(version)
    run([binary, "-I", chain, str(position), *drop_spec])
    run([binary, "-I", chain, str(position), *log_spec])


def saved_chain_rules(version, chain):
    prefix = f"-A {chain} "
    rules = []
    for line in run([SAVE_BINARIES[version]]).stdout.splitlines():
        if not line.startswith(prefix):
            continue
        tokens = shlex.split(line)
        if len(tokens) >= 3:
            rules.append(tokens[2:])
    return rules


def is_accept_monitor_rule(spec):
    return ACCEPT_MONITOR_COMMENT in spec


def strip_comment_matches(spec):
    
    clean = []
    index = 0
    while index < len(spec):
        if index + 1 < len(spec) and spec[index:index + 2] == ["-m", "comment"]:
            index += 2
            if index + 1 < len(spec) and spec[index] == "--comment":
                index += 2
            continue
        if spec[index] == "--comment" and index + 1 < len(spec):
            index += 2
            continue
        clean.append(spec[index])
        index += 1
    return clean


def remove_accept_monitor_rules(version):
    chain = USER_CHAINS[version]
    for spec in saved_chain_rules(version, chain):
        if is_accept_monitor_rule(spec):
            run([BINARIES[version], "-D", chain, *spec])


def sync_accept_monitor(version):
    
    chain = USER_CHAINS[version]
    binary = BINARIES[version]
    remove_accept_monitor_rules(version)
    rules = saved_chain_rules(version, chain)
    position = 1
    installed = 0
    for spec in rules:
        try:
            jump = len(spec) - 1 - spec[::-1].index("-j")
        except ValueError:
            position += 1
            continue
        if jump + 1 >= len(spec) or spec[jump + 1] != "ACCEPT":
            position += 1
            continue
        match = strip_comment_matches(spec[:jump])
        log_spec = match + [
            "-m", "conntrack", "--ctstate", "NEW",
            "-m", "limit", "--limit", "10/minute", "--limit-burst", "20",
            "-m", "comment", "--comment", ACCEPT_MONITOR_COMMENT,
            "-j", "LOG", "--log-prefix", f"SPALLOW{version}: ", "--log-level", "4",
        ]
        run([binary, "-I", chain, str(position), *log_spec])
        installed += 1
        position += 2
    return installed


def accept_monitor_status():
    counts = {}
    for version in (4, 6):
        counts[version] = sum(
            1 for spec in saved_chain_rules(version, USER_CHAINS[version])
            if is_accept_monitor_rule(spec)
        )
    return {
        "enabled": (counts[4] + counts[6]) > 0,
        "rules": counts[4] + counts[6],
        "ipv4": counts[4],
        "ipv6": counts[6],
    }


def sync_sets(entries):
    for version in (4, 6):
        target = SETS[version]
        stage = f"{target}_stage"
        family = FAMILIES[version]
        commands = [
            f"create {target} hash:ip family {family} maxelem 65536 -exist",
            f"create {stage} hash:ip family {family} maxelem 65536 -exist",
            f"flush {stage}",
        ]
        commands.extend(f"add {stage} {item['ip']} -exist" for item in entries if item["family"] == version)
        commands.extend((f"swap {stage} {target}", f"destroy {stage}"))
        restore_ipsets(commands)
        ensure_rules(version)


def restore_ipsets(commands):
    result = subprocess.run(
        ["ipset", "restore", "-exist"], input="\n".join(commands) + "\n",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LC_ALL": "C"}, check=False, timeout=90,
    )
    if result.returncode:
        raise ControlError(f"ipset: {(result.stderr or result.stdout or 'sincronización fallida').strip()}")


def sync_provider_sets(entries):
    for version in (4, 6):
        target = PROVIDER_SETS[version]
        stage = f"{target}_stage"
        family = FAMILIES[version]
        commands = [
            f"create {target} hash:net family {family} maxelem 262144 -exist",
            f"create {stage} hash:net family {family} maxelem 262144 -exist",
            f"flush {stage}",
        ]
        for item in entries:
            for prefix in item["prefixes"]:
                network = ipaddress.ip_network(prefix)
                if network.version == version:
                    commands.append(f"add {stage} {network} -exist")
        commands.extend((f"swap {stage} {target}", f"destroy {stage}"))
        restore_ipsets(commands)
        ensure_provider_rules(version)


def sync_all(entries, provider_entries):
    sync_sets(entries)
    sync_provider_sets(provider_entries)
    for version in (4, 6):
        sync_accept_monitor(version)


def apply_change(previous, current, *, provider=False):
    
    sync = sync_provider_sets if provider else sync_sets
    save = save_provider_entries if provider else save_entries
    saving = False
    try:
        sync(current)
        if previous != current:
            saving = True
            save(current)
    except (ControlError, OSError, subprocess.TimeoutExpired) as exc:
        recovery_errors = []
        try:
            sync(previous)
        except (ControlError, OSError, subprocess.TimeoutExpired) as recovery:
            recovery_errors.append(str(recovery))
        if saving:
            try:
                save(previous)
            except (ControlError, OSError) as recovery:
                recovery_errors.append(str(recovery))
        if recovery_errors:
            raise ControlError(f"Cambio fallido: {exc}. Restauración incompleta; revisar el firewall: {'; '.join(recovery_errors)}") from exc
        raise ControlError(f"Cambio no aplicado; se restauró el estado anterior: {exc}") from exc


def controller_status(entries, provider_entries):
    return {
        "ok": True,
        "installed": True,
        "count": len(entries),
        "ipv4": sum(1 for item in entries if item["family"] == 4),
        "ipv6": sum(1 for item in entries if item["family"] == 6),
        "rules": {
            "ipv4": all(rule_exists(4, spec) for spec in rule_specs(4)),
            "ipv6": all(rule_exists(6, spec) for spec in rule_specs(6)),
        },
        "entries": entries,
        "provider_count": len(provider_entries),
        "provider_prefixes": sum(len(item["prefixes"]) for item in provider_entries),
        "provider_rules": {
            "ipv4": all(rule_exists(4, spec) for spec in provider_rule_specs(4)),
            "ipv6": all(rule_exists(6, spec) for spec in provider_rule_specs(6)),
        },
        "provider_blocks": provider_entries,
        "ufw_logging": ufw_logging_status(),
        "accept_monitor": accept_monitor_status(),
    }


def ufw_logging_status():
    result = run(["ufw", "status", "verbose"], check=False)
    match = re.search(
        r"^Logging:\s+(?P<state>on|off)(?:\s+\((?P<level>[^)]+)\))?",
        result.stdout,
        re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        return {"enabled": False, "level": "unknown"}
    enabled = match.group("state").lower() == "on"
    return {"enabled": enabled, "level": (match.group("level") or "off").lower()}


def request_payload(args):
    if getattr(args, "json_input", False):
        try:
            raw = sys.stdin.buffer.read(2*1024*1024 + 1)
            if len(raw)>2*1024*1024: raise ControlError("El cuerpo JSON supera 2 MB.")
            payload = json.loads(raw)
        except (json.JSONDecodeError,UnicodeError) as exc:
            raise ControlError("El cuerpo JSON no es válido") from exc
        if not isinstance(payload, dict):
            raise ControlError("El cuerpo JSON debe ser un objeto")
        return payload
    return {"ip": getattr(args, "ip", ""), "reason": getattr(args, "reason", "")}


def provider_payload(payload):
    asn = parse_asn(payload.get("asn", ""))
    name = sanitized_provider_name(payload.get("name", ""))
    if asn == "AS16276" or re.search(r"\bOVH\b", name, re.IGNORECASE):
        raise ControlError("OVH aloja este servidor y no puede bloquearse como proveedor")
    raw_prefixes = payload.get("prefixes", [])
    if not isinstance(raw_prefixes, list) or not raw_prefixes:
        raise ControlError("El proveedor no contiene prefijos revisados")
    if len(raw_prefixes) > 50000:
        raise ControlError("El proveedor supera el límite de 50.000 prefijos")
    prefixes = sorted({str(parse_public_network(value)) for value in raw_prefixes})
    expected_digest = prefix_digest(asn, prefixes)
    supplied_digest = str(payload.get("approval_digest", "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_digest) or supplied_digest != expected_digest:
        raise ControlError("La aprobación no corresponde a estos prefijos")
    return {
        "asn": asn,
        "name": name,
        "prefixes": prefixes,
        "ipv4": sum(1 for value in prefixes if ipaddress.ip_network(value).version == 4),
        "ipv6": sum(1 for value in prefixes if ipaddress.ip_network(value).version == 6),
        "prefix_digest": expected_digest,
        "reason": sanitized_reason(payload.get("reason", "Proveedor confirmado desde el panel local")),
        "created_at": utc_now(),
    }


def forwarding_action(command, payload):
    import importlib.util
    spec = importlib.util.spec_from_file_location("storypulse_forwarding", pathlib.Path(__file__).with_name("storypulse_forwarding.py"))
    forwarding = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(forwarding)
    try:
        if command == "forwarding-sync": return forwarding.sync()
        if command == "forwarding-status":
            extra = payload.get("port")
            if extra is not None: forwarding.ports.validate_port(extra)
            return forwarding.status(extra)
        if command == "forwarding-plan": return forwarding.plan(forwarding.snapshot(), forwarding.load(), payload)
        result = forwarding.change(payload)
        audit("forwarding-" + result["action"], result["id"], "Cambio confirmado desde el panel", True)
        return result
    except (forwarding.ForwardError, forwarding.ports.PortsError) as exc:
        raise ControlError(str(exc)) from exc


def mysql_action(command, payload):
    import importlib.util
    spec=importlib.util.spec_from_file_location("storypulse_mysql",pathlib.Path(__file__).with_name("storypulse_mysql.py"))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.configure_platform()
    try:
        if command=="mysql-status":return module.status()
        if command=="mysql-plan":return module.plan(payload)
        if command=="mysql-data":return module.data(payload)
        if command=="mysql-structure":return module.structure(payload)
        with pathlib.Path('/run/lock/storypulse-mysql.lock').open('a') as handle:
            fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=module.change(payload,sync_accept_monitor)
            audit('mysql-'+result['action'],'mysql','Cambio confirmado de MySQL',True)
            return result
    except BlockingIOError as exc:raise ControlError('Hay otro cambio MySQL en curso.') from exc
    except RuntimeError as exc:raise ControlError(str(exc)) from exc


def services_action(command, payload):
    import importlib.util
    spec = importlib.util.spec_from_file_location("storypulse_services", pathlib.Path(__file__).with_name("storypulse_services.py"))
    services = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(services)
    services.configure_platform()
    try:
        if command == "services-status": return services.status()
        if command == "services-plan": return services.plan(payload)
        with pathlib.Path('/run/lock/storypulse-ftp.lock').open('a') as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = services.change(payload, sync_accept_monitor)
            audit("ftp-" + result["action"], result.get("username", "ftp"), "Cambio confirmado de servicio FTP", True)
            return result
    except BlockingIOError as exc:
        raise ControlError("Hay otro cambio de FTP en curso. Esperá su resultado.") from exc
    except services.ServiceError as exc:
        raise ControlError(str(exc)) from exc


def cleanup_action(command, body):
    import importlib.util
    spec = importlib.util.spec_from_file_location("storypulse_cleanup", pathlib.Path(__file__).with_name("storypulse_cleanup.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    try:
        if command == "cleanup-status": return module.status()
        if command == "cleanup-plan": return module.plan(body)
        if command == "cleanup-tick": return module.tick()
        return module.change(body)
    except RuntimeError as exc:
        raise ControlError(str(exc)) from exc


def system_action(command, body):
    import importlib.util
    spec = importlib.util.spec_from_file_location("storypulse_system", pathlib.Path(__file__).with_name("storypulse_system.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    try:
        if command == "system-metrics":
            if body != {}: raise ControlError("La consulta de hardware no acepta parámetros.")
            return module.metrics()
        if command == "system-plan": return module.plan(body)
        return module.reboot(body)
    except RuntimeError as exc:
        raise ControlError(str(exc)) from exc


def secure_process_environment():
    
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    for key in ("BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "SHELLOPTS", "BASHOPTS", "PS4",
                "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH"):
        os.environ.pop(key, None)


def main():
    secure_process_environment()
    parser = argparse.ArgumentParser(description="Bloqueos manuales StoryPulse")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("list")
    subparsers.add_parser("sync")
    for name in ("ports-status", "ports-plan", "ports-apply"):
        port_parser = subparsers.add_parser(name)
        port_parser.add_argument("--json-input", action="store_true", required=True)
    for name in ("forwarding-status", "forwarding-plan", "forwarding-apply"):
        forwarding_parser = subparsers.add_parser(name)
        forwarding_parser.add_argument("--json-input", action="store_true", required=True)
    forwarding_sync = subparsers.add_parser("forwarding-sync")
    forwarding_sync.add_argument("--from-hook", action="store_true")
    for name in ("services-status", "services-plan", "services-apply", "mysql-status", "mysql-plan", "mysql-apply", "mysql-data", "mysql-structure"):
        service_parser = subparsers.add_parser(name)
        service_parser.add_argument("--json-input", action="store_true", required=True)
    block = subparsers.add_parser("block")
    block.add_argument("ip", nargs="?")
    block.add_argument("--reason", default="")
    block.add_argument("--json-input", action="store_true")
    unblock = subparsers.add_parser("unblock")
    unblock.add_argument("ip", nargs="?")
    unblock.add_argument("--json-input", action="store_true")
    provider_block = subparsers.add_parser("provider-block")
    provider_block.add_argument("--json-input", action="store_true", required=True)
    provider_unblock = subparsers.add_parser("provider-unblock")
    provider_unblock.add_argument("--json-input", action="store_true", required=True)
    report_ssh = subparsers.add_parser("report-ssh")
    report_ssh.add_argument("--json-input", action="store_true", required=True)
    for name in ("cleanup-status", "cleanup-plan", "cleanup-apply"):
        cleanup_parser = subparsers.add_parser(name)
        cleanup_parser.add_argument("--json-input", action="store_true", required=True)
    subparsers.add_parser("cleanup-tick")
    for name in ("system-metrics", "system-plan", "system-reboot"):
        system_parser = subparsers.add_parser(name)
        system_parser.add_argument("--json-input", action="store_true", required=True)
    for name in ("collect", "report-download"):
        subparsers.add_parser(name).add_argument("--json-input",action="store_true",required=True)
    for name in ("trusted-status", "trusted-plan", "trusted-apply", "trusted-setup"):
        subparsers.add_parser(name).add_argument("--json-input",action="store_true",required=True)
    for name in ("alerts-status", "alerts-configure"):
        subparsers.add_parser(name).add_argument("--json-input",action="store_true",required=True)
    args = parser.parse_args()
    if args.command.startswith("alerts-"):
        import storypulse_panel_alerts as panel_alerts
        body=request_payload(args)
        try:
            if args.command=="alerts-status":
                if body!={}:raise panel_alerts.AlertError("La consulta no admite parámetros.")
                emit(panel_alerts.status())
            emit(panel_alerts.change(body))
        except (panel_alerts.AlertError,OSError,ValueError) as exc:
            raise ControlError(str(exc) if isinstance(exc,panel_alerts.AlertError) else "No se pudo acceder a la configuración del bot del panel.") from None
    if args.command.startswith("trusted-"):
        import storypulse_trusted as trusted
        body=request_payload(args)
        try:
            if args.command=="trusted-setup":
                if body!={}:raise trusted.TrustedError("La preparación no acepta parámetros.")
                emit(trusted.prepare_monitor())
            if args.command=="trusted-status":
                if body!={}:raise trusted.TrustedError("La consulta no acepta parámetros.")
                emit(trusted.status())
            if args.command=="trusted-plan":emit(trusted.plan(body))
            result=trusted.change(body)
            audit("authorized-"+result["action"],result["ip"],"Cambio de IP autorizadas confirmado",True)
            emit(result)
        except (trusted.TrustedError,BlockingIOError) as exc:raise ControlError(str(exc)) from exc
    if args.command == "collect":
        completed = subprocess.run(collect_request(request_payload(args)),stdin=subprocess.DEVNULL,timeout=85,check=False)
        raise SystemExit(completed.returncode)
    if args.command == "report-download":
        with report_locked():
            try: emit(report_module().download(request_payload(args)))
            except RuntimeError as exc: raise ControlError(str(exc)) from exc
    if args.command.startswith("system-"):
        emit(system_action(args.command, request_payload(args)))
    if args.command.startswith("cleanup-"):
        emit(cleanup_action(args.command, {} if args.command == "cleanup-tick" else request_payload(args)))
    if args.command.startswith("mysql-"):
        emit(mysql_action(args.command, request_payload(args)))
    if args.command.startswith("services-"):
        emit(services_action(args.command, request_payload(args)))

    if args.command == "report-ssh":
        with report_locked():
            emit(generate_ssh_report(request_payload(args)))

    if args.command == "forwarding-sync" and args.from_hook:
        
        
        with LOCK_PATH.open("a") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                emit({"ok": True, "deferred": True})
            emit(forwarding_action("forwarding-sync", {}))

    with locked():
        if args.command.startswith("forwarding-"):
            emit(forwarding_action(args.command, {} if args.command == "forwarding-sync" else request_payload(args)))
        if args.command.startswith("ports-"):
            import importlib.util
            spec = importlib.util.spec_from_file_location("storypulse_ports", pathlib.Path(__file__).with_name("storypulse_ports.py"))
            ports = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ports)
            payload = request_payload(args)
            try:
                if args.command == "ports-status":
                    extra = payload.get("port")
                    if extra is not None:
                        ports.validate_port(extra)
                    emit(ports.inventory(ports.read_snapshot(), extra))
                if args.command == "ports-plan":
                    emit(ports.plan(ports.read_snapshot(), payload))
                result = ports.apply(payload, sync_accept_monitor)
                audit("port-" + result["action"], f'{result["changed_protocol"]}/{result["changed_port"]}', "Cambio confirmado desde el panel", True)
                emit(result)
            except ports.PortsError as exc:
                raise ControlError(str(exc)) from exc
        entries = load_entries()
        provider_entries = load_provider_entries()
        if args.command in ("status", "list"):
            emit(controller_status(entries, provider_entries))
        if args.command == "sync":
            sync_all(entries, provider_entries)
            forwarding_action("forwarding-sync", {})
            emit({**controller_status(entries, provider_entries), "synced": True})

        payload = request_payload(args)
        previous_entries = list(entries)
        previous_providers = list(provider_entries)
        if args.command == "provider-block":
            item = provider_payload(payload)
            existing = next((row for row in provider_entries if row["asn"] == item["asn"]), None)
            changed = existing is None or existing["prefix_digest"] != item["prefix_digest"]
            if changed:
                provider_entries = [row for row in provider_entries if row["asn"] != item["asn"]]
                provider_entries.append(item)
                provider_entries.sort(key=lambda row: int(row["asn"][2:]))
            apply_change(previous_providers, provider_entries, provider=True)
            audit("provider-block", item["asn"], item["reason"], changed)
            emit({
                **controller_status(entries, provider_entries),
                "action": "provider-block", "changed": changed,
                "asn": item["asn"], "name": item["name"],
            })

        if args.command == "provider-unblock":
            asn = parse_asn(payload.get("asn", ""))
            existing = next((row for row in provider_entries if row["asn"] == asn), None)
            changed = existing is not None
            if changed:
                provider_entries = [row for row in provider_entries if row["asn"] != asn]
            apply_change(previous_providers, provider_entries, provider=True)
            audit("provider-unblock", asn, existing.get("reason", "") if existing else "", changed)
            emit({
                **controller_status(entries, provider_entries),
                "action": "provider-unblock", "changed": changed, "asn": asn,
            })

        address = parse_public_ip(payload.get("ip", ""))
        canonical = str(address)
        if args.command == "block":
            reason = sanitized_reason(payload.get("reason", ""))
            changed = not any(item["ip"] == canonical for item in entries)
            if changed:
                entries.append({
                    "ip": canonical,
                    "family": address.version,
                    "reason": reason,
                    "created_at": utc_now(),
                })
                entries.sort(key=lambda item: (item["family"], item["ip"]))
            apply_change(previous_entries, entries)
            audit("block", address, reason, changed)
            emit({**controller_status(entries, provider_entries), "action": "block", "changed": changed, "ip": canonical})

        existing = next((item for item in entries if item["ip"] == canonical), None)
        changed = existing is not None
        if changed:
            entries = [item for item in entries if item["ip"] != canonical]
        apply_change(previous_entries, entries)
        audit("unblock", address, existing.get("reason", "") if existing else "", changed)
        emit({**controller_status(entries, provider_entries), "action": "unblock", "changed": changed, "ip": canonical})


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        emit({"ok": False, "error": str(exc)}, 1)
