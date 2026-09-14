#!/usr/bin/env python3
"""Controlador mínimo y auditable de Server Security para UFW e ipset."""

import argparse
import datetime as dt
import fcntl
import functools
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


CONFIG_DIR = pathlib.Path("/etc/server-security")
CONFIG_PATH = CONFIG_DIR / "manual-blocks.json"
PROVIDER_CONFIG_PATH = CONFIG_DIR / "provider-blocks.json"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
AUDIT_PATH = pathlib.Path("/var/log/server-security-blocks.jsonl")
LOCK_PATH = pathlib.Path("/run/lock/server-securityctl.lock")
REPORT_LOCK_PATH = pathlib.Path("/run/lock/server-security-ssh-report.lock")
REPORT_MAX_MINUTES = 7 * 24 * 60
REPORT_TIMEOUT = 30 * 60

SETS = {4: "ss_manual4", 6: "ss_manual6"}
PROVIDER_SETS = {4: "ss_provider4", 6: "ss_provider6"}
CHAINS = {4: "ufw-before-input", 6: "ufw6-before-input"}
BINARIES = {4: "iptables", 6: "ip6tables"}
FAMILIES = {4: "inet", 6: "inet6"}
USER_CHAINS = {4: "ufw-user-input", 6: "ufw6-user-input"}
SAVE_BINARIES = {4: "iptables-save", 6: "ip6tables-save"}
ACCEPT_MONITOR_COMMENT = "Server Security accepted LOG"

# Nunca permitir que el panel bloquee la red privada de gestión. Las IP
# propias del servidor, la sesión SSH y las redes definidas por el
# administrador también se protegen dinámicamente más abajo.
BASE_PROTECTED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "100.64.0.0/10",          # Tailscale IPv4
    "fd7a:115c:a1e0::/48",    # Tailscale IPv6
))


class ControlError(RuntimeError):
    pass


def load_settings():
    if not SETTINGS_PATH.is_file():
        return {}
    try:
        payload = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(f"No se pudo leer {SETTINGS_PATH}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ControlError(f"{SETTINGS_PATH} debe contener un objeto JSON")
    return payload


SETTINGS = load_settings()
REPORT_SCRIPT = pathlib.Path(str(SETTINGS.get("report_script", "/opt/server-security/ssh-report.sh")))
REPORT_OUTPUT_DIR = pathlib.Path(str(SETTINGS.get("report_output_dir", "/var/lib/server-security/reports")))
REPORT_TIMEZONE = str(SETTINGS.get("report_timezone", "UTC"))


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


@functools.lru_cache(maxsize=1)
def protected_networks():
    networks = list(BASE_PROTECTED_NETWORKS)

    configured = SETTINGS.get("protected_networks", [])
    if not isinstance(configured, list):
        raise ControlError("protected_networks debe ser una lista en settings.json")
    for value in configured:
        try:
            networks.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError as exc:
            raise ControlError(f"Red protegida no válida: {value}") from exc

    # Protege todas las direcciones asignadas al VPS sin publicar ninguna de
    # ellas en el repositorio.
    try:
        result = run(["ip", "-j", "address", "show"], check=False)
        for interface in json.loads(result.stdout or "[]"):
            for info in interface.get("addr_info", []):
                address = ipaddress.ip_address(str(info.get("local", "")))
                suffix = 32 if address.version == 4 else 128
                networks.append(ipaddress.ip_network(f"{address}/{suffix}"))
    except (OSError, ValueError, json.JSONDecodeError):
        pass

    # SSH_CONNECTION contiene cliente y servidor. Su presencia evita que una
    # operación remota pueda bloquear accidentalmente la sesión administrativa.
    for token in os.environ.get("SSH_CONNECTION", "").split():
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        suffix = 32 if address.version == 4 else 128
        networks.append(ipaddress.ip_network(f"{address}/{suffix}"))

    return tuple(dict.fromkeys(networks))


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


def parse_public_ip(value):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ControlError("La dirección IP no es válida") from exc
    if not address.is_global:
        raise ControlError("Sólo se pueden bloquear direcciones públicas globales")
    if any(address in network for network in protected_networks()):
        raise ControlError("La dirección pertenece a una red protegida y no puede bloquearse")
    return address


def parse_public_network(value):
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=True)
    except ValueError as exc:
        raise ControlError("El prefijo de red no es válido o no está normalizado") from exc
    if not network.is_global:
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
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def report_locked():
    """Impide ejecutar dos generadores pesados al mismo tiempo."""
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


def report_command(minutes):
    return [
        "/usr/bin/bash",
        REPORT_SCRIPT.as_posix(),
        "--since",
        f"{minutes} minutes ago",
        "--all",
        "--output-dir",
        REPORT_OUTPUT_DIR.as_posix(),
    ]


def report_snapshot():
    snapshot = {}
    try:
        for pattern in ("ssh_reporte_*", "ssh_eventos_*"):
            for path in REPORT_OUTPUT_DIR.glob(pattern):
                if not path.is_file() or path.suffix.lower() not in (".txt", ".csv"):
                    continue
                stat = path.stat()
                snapshot[path.name] = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        pass
    return snapshot


def report_result_detail(completed):
    combined = "\n".join(
        part.strip()
        for part in (completed.stdout, completed.stderr)
        if part and part.strip()
    )
    if not combined:
        return "Sin detalle adicional."
    return "\n".join(combined.splitlines()[-8:])[-1200:]


def generate_ssh_report(payload):
    minutes = report_minutes(payload)
    if not REPORT_SCRIPT.is_file():
        raise ControlError(f"No se encontró el generador de reportes en {REPORT_SCRIPT}")
    if not REPORT_OUTPUT_DIR.is_dir():
        raise ControlError(f"No existe el directorio de reportes {REPORT_OUTPUT_DIR}")

    before = report_snapshot()
    environment = os.environ.copy()
    environment["XDG_CACHE_HOME"] = "/tmp/server-security-report-cache"
    environment["REPORT_TIMEZONE"] = REPORT_TIMEZONE
    completed = subprocess.run(
        report_command(minutes),
        cwd=str(REPORT_OUTPUT_DIR),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        umask=0o022,
        timeout=REPORT_TIMEOUT,
        check=False,
    )
    after = report_snapshot()
    generated = sorted(
        name for name, state in after.items()
        if name not in before or before[name] != state
    )
    detail = report_result_detail(completed)
    if completed.returncode != 0 and not generated:
        raise ControlError(
            f"El generador terminó con código {completed.returncode}: {detail}"
        )

    files = []
    for name in generated:
        path = REPORT_OUTPUT_DIR / name
        try:
            path.chmod(path.stat().st_mode | 0o044)
            size = path.stat().st_size
        except OSError as exc:
            raise ControlError(f"No se pudo preparar {name} para la descarga: {exc}") from exc
        files.append({"name": name, "type": path.suffix.lower().lstrip("."), "size": size})

    no_findings = not files and "No se encontraron fallos" in detail
    return {
        "ok": True,
        "minutes": minutes,
        "days": minutes / 1440,
        "files": files,
        "no_findings": no_findings,
        "warning": "" if files or no_findings else "El análisis terminó sin crear archivos nuevos",
        "detail": detail,
    }


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
        except (AttributeError, ControlError):
            continue
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
        except (AttributeError, TypeError, ControlError):
            continue
        if not prefixes or asn in seen:
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
        "-m", "comment", "--comment", f"Server Security manual LOG {family}",
        "-j", "LOG", "--log-prefix", f"SSMANUAL{version}: ", "--log-level", "4",
    ]
    drop = common + [
        "-m", "comment", "--comment", f"Server Security manual DROP {family}",
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
        "-m", "comment", "--comment", f"Server Security provider LOG {family}",
        "-j", "LOG", "--log-prefix", f"SSPROVIDER{version}: ", "--log-level", "4",
    ]
    drop = common + [
        "-m", "comment", "--comment", f"Server Security provider DROP {family}",
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
    # Si quedó una regla parcial, se reconstruye el par en orden LOG -> DROP.
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
    """Quita comentarios descriptivos sin cambiar el criterio de red."""
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
    """Registra sólo conexiones NEW que coinciden con un ACCEPT real de UFW."""
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
            "-j", "LOG", "--log-prefix", f"SSALLOW{version}: ", "--log-level", "4",
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
        run(["ipset", "create", target, "hash:ip", "family", family, "maxelem", "65536", "-exist"])
        run(["ipset", "create", stage, "hash:ip", "family", family, "maxelem", "65536", "-exist"])
        run(["ipset", "flush", stage])
        for item in entries:
            if item["family"] == version:
                run(["ipset", "add", stage, item["ip"], "-exist"])
        run(["ipset", "swap", stage, target])
        run(["ipset", "destroy", stage], check=False)
        ensure_rules(version)
        sync_accept_monitor(version)


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
        result = subprocess.run(
            ["ipset", "restore", "-exist"],
            input="\n".join(commands) + "\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "LC_ALL": "C"},
            check=False,
            timeout=90,
        )
        if result.returncode:
            raise ControlError(f"ipset: {(result.stderr or result.stdout or 'sincronización fallida').strip()}")
        ensure_provider_rules(version)


def sync_all(entries, provider_entries):
    sync_sets(entries)
    sync_provider_sets(provider_entries)


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
            payload = json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            raise ControlError("El cuerpo JSON no es válido") from exc
        if not isinstance(payload, dict):
            raise ControlError("El cuerpo JSON debe ser un objeto")
        return payload
    return {"ip": getattr(args, "ip", ""), "reason": getattr(args, "reason", "")}


def provider_payload(payload):
    asn = parse_asn(payload.get("asn", ""))
    name = sanitized_provider_name(payload.get("name", ""))
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


def main():
    parser = argparse.ArgumentParser(description="Bloqueos manuales Server Security")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("list")
    subparsers.add_parser("sync")
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
    args = parser.parse_args()

    if args.command == "report-ssh":
        with report_locked():
            emit(generate_ssh_report(request_payload(args)))

    with locked():
        entries = load_entries()
        provider_entries = load_provider_entries()
        if args.command in ("status", "list"):
            emit(controller_status(entries, provider_entries))
        if args.command == "sync":
            sync_all(entries, provider_entries)
            emit({**controller_status(entries, provider_entries), "synced": True})

        payload = request_payload(args)
        if args.command == "provider-block":
            item = provider_payload(payload)
            existing = next((row for row in provider_entries if row["asn"] == item["asn"]), None)
            changed = existing is None or existing["prefix_digest"] != item["prefix_digest"]
            if changed:
                provider_entries = [row for row in provider_entries if row["asn"] != item["asn"]]
                provider_entries.append(item)
                provider_entries.sort(key=lambda row: int(row["asn"][2:]))
                save_provider_entries(provider_entries)
            sync_all(entries, provider_entries)
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
                save_provider_entries(provider_entries)
            sync_all(entries, provider_entries)
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
                save_entries(entries)
            sync_all(entries, provider_entries)
            audit("block", address, reason, changed)
            emit({**controller_status(entries, provider_entries), "action": "block", "changed": changed, "ip": canonical})

        existing = next((item for item in entries if item["ip"] == canonical), None)
        changed = existing is not None
        if changed:
            entries = [item for item in entries if item["ip"] != canonical]
            save_entries(entries)
        sync_all(entries, provider_entries)
        audit("unblock", address, existing.get("reason", "") if existing else "", changed)
        emit({**controller_status(entries, provider_entries), "action": "unblock", "changed": changed, "ip": canonical})


if __name__ == "__main__":
    try:
        main()
    except (ControlError, subprocess.TimeoutExpired, OSError) as exc:
        emit({"ok": False, "error": str(exc)}, 1)
