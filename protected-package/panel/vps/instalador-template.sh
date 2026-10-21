#!/usr/bin/env bash
# Autonomous root bootstrap; only fixed packages/actions, no remote shell downloads.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
[[ $EUID -eq 0 ]] || { echo 'ERROR: este instalador sólo puede ejecutarse como root (sudo bash instalar-servidor.sh).' >&2; exit 1; }
PANEL_USER=${SUDO_USER:-root}
CHECK_ONLY=0 MIGRATE_FIREWALL=0 MIGRATION_PENDING=0 UFW_WAS_ACTIVE=0 SSH_RULES_PENDING=0
ADMIN_IPS=() PACKAGES=() FOREIGN_FIREWALLS=()
WORK='' STEP='validación inicial' BACKUP=''
exec 4>&1
[[ ! -L /var/log/server-monitor-installer ]] || { echo 'ERROR: ruta de log insegura.' >&2; exit 1; }
install -d -o root -g root -m 0700 /var/log/server-monitor-installer
LOG=/var/log/server-monitor-installer/instalacion-$(date -u +%Y%m%dT%H%M%SZ)-$$.log
exec 3>>"$LOG"
exec >>"$LOG" 2>&1
say() { printf '%s\n' "$*" >&4; printf '%s\n' "$*" >&3; }
show() { "$@" 2>&1 | tee -a "$LOG" >&4; }
failed() {
  local code=$1 line=$2
  trap - ERR
  if ((SSH_RULES_PENDING)); then
    SSH_RULES_PENDING=0
    say 'No se pudo ordenar el permiso SSH; se restauran las reglas anteriores.'
    for rules_file in user.rules user6.rules; do
      if [[ -f $BACKUP/etc/ufw/$rules_file ]]; then
        cp -a -- "$BACKUP/etc/ufw/$rules_file" "/etc/ufw/$rules_file" || say "AVISO: no se pudo restaurar $rules_file; revisá la consola del proveedor."
      fi
    done
    if ((UFW_WAS_ACTIVE)); then ufw reload || say 'AVISO: no se pudo recargar UFW; revisá la consola del proveedor.'; fi
  fi
  if ((MIGRATION_PENDING)); then
    MIGRATION_PENDING=0
    say 'La activación del firewall falló; se restaura el firewall que estaba activo.'
    if ((!UFW_WAS_ACTIVE)); then ufw --force disable || say 'AVISO: revisá el estado de UFW desde la consola del proveedor.'; fi
    for service in "${FOREIGN_FIREWALLS[@]}"; do
      if [[ ${FOREIGN_ENABLED[$service]:-0} == 1 ]]; then systemctl enable "$service" || say "AVISO: no se pudo habilitar $service al arrancar."; fi
      systemctl start "$service" || say "AVISO: no se pudo restaurar $service; revisá la consola del proveedor."
    done
  fi
  say "ERROR en paso \"$STEP\", línea $line, código $code."
  say "Log completo: $LOG | Respaldo: ${BACKUP:-aún no creado}"
  say 'La instalación quedó incompleta; revisá el log antes de reintentar.'
  exit "$code"
}
cleanup() { if [[ $WORK == /var/tmp/server-monitor.* && -d $WORK && ! -L $WORK ]]; then rm -rf -- "$WORK"; fi; }
trap 'failed $? $LINENO' ERR
trap cleanup EXIT
trap 'failed 130 $LINENO' INT
trap 'failed 143 $LINENO' TERM
progress() { STEP=$2; say "[$1/8 · $(( $1 * 100 / 8 ))%] $STEP"; }
say '========================================================'
say '       Instalador Monitor Security by FacuSecX'
say '              https://github.com/FacuSecX'
say '========================================================'
sleep 3
usage() {
  say 'Uso: sudo bash instalar-servidor.sh [--usuario USUARIO_SSH] [opciones]'
  say 'Distribuciones: Debian, Ubuntu, CentOS Stream 9/10 y Arch Linux; requieren systemd, repositorios activos y Python >= 3.8.'
  say '--ip-admin IP          Proteger una IP administrativa; repetible.'
  say '--migrar-firewall      Respaldar y desactivar firewalld/nftables; aplicar UFW con acceso SSH. No importa reglas ajenas.'
  say '--comprobar            Diagnóstico sin instalar ni cambiar la red (conserva sólo su log).'
  say '--ayuda               Mostrar ayuda.'
  say 'El panel se conecta por SSH directo. La web funciona localmente en Windows; no se abre su puerto en el VPS.'
  say 'Los juegos y servicios opcionales abren sus puertos al instalarlos desde el panel.'
}
while (($#)); do
  case "$1" in
    --usuario|--ip-admin)
      (($# >= 2)) || { say "ERROR: falta valor para $1"; exit 2; }
      if [[ $1 == --usuario ]]; then PANEL_USER=$2; else ADMIN_IPS+=("$2"); fi
      shift 2 ;;
    --migrar-firewall) MIGRATE_FIREWALL=1; shift ;;
    --comprobar) CHECK_ONLY=1; shift ;;
    --ayuda|--help|-h) usage; exit 0 ;;
    *) say "ERROR: opción desconocida: $1"; usage; exit 2 ;;
  esac
done
[[ -r /etc/os-release ]] || { say 'ERROR: no se encontró /etc/os-release.'; exit 1; }
# This is the root-owned OS identity file, never a panel/browser argument.
. /etc/os-release
case ${ID:-} in
  debian|ubuntu)
    FAMILY=apt SSH_SERVICE=ssh.service
    command -v apt-get >/dev/null || { say 'ERROR: no se encontró APT.'; exit 1; }
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz-utils util-linux python3 sudo ufw iptables ipset iproute2 openssh-server ca-certificates curl jq gawk tzdata openssl logrotate kmod gnupg)
    if [[ $ID == debian ]]; then PACKAGES+=(debian-archive-keyring); else PACKAGES+=(ubuntu-keyring); fi ;;
  centos)
    FAMILY=rpm SSH_SERVICE=sshd.service
    MAJOR=${VERSION_ID%%.*}
    [[ $MAJOR =~ ^[0-9]+$ && $MAJOR -ge 9 ]] || { say 'ERROR: CentOS Linux 7/8 y Stream 8 están fuera de soporte. Se necesita CentOS Stream 9 o posterior.'; exit 1; }
    if command -v dnf >/dev/null; then RPM_MANAGER=dnf; elif command -v yum >/dev/null; then RPM_MANAGER=yum; else say 'ERROR: falta DNF/YUM.'; exit 1; fi
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz util-linux python3 sudo ufw iptables ipset iproute openssh-server ca-certificates curl jq gawk tzdata openssl logrotate kmod policycoreutils-python-utils rpm gnupg2) ;;
  arch)
    FAMILY=arch SSH_SERVICE=sshd.service
    command -v pacman >/dev/null || { say 'ERROR: no se encontró Pacman.'; exit 1; }
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz util-linux python sudo ufw iptables ipset iproute2 openssh ca-certificates curl jq gawk tzdata openssl logrotate kmod gnupg archlinux-keyring) ;;
  *) say "ERROR: distribución no compatible: ${ID:-desconocida}."; exit 1 ;;
esac
[[ -d /run/systemd/system ]] || { say 'ERROR: se necesita un servidor iniciado con systemd; un contenedor mínimo sin systemd no es suficiente.'; exit 1; }
[[ $PANEL_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { say 'ERROR: usuario SSH inválido.'; exit 2; }
id "$PANEL_USER" >/dev/null 2>&1 || { say 'ERROR: el usuario SSH indicado no existe.'; exit 2; }
say "Distribución detectada: $PRETTY_NAME | Gestor: $FAMILY | Usuario SSH: $PANEL_USER"
say "Log detallado: $LOG"

package_installed() {
  case "$FAMILY" in
    apt) [[ $(dpkg-query -W '-f=${db:Status-Status}' "$1" 2>/dev/null || true) == installed ]] ;;
    rpm) rpm -q "$1" >/dev/null 2>&1 ;;
    arch) pacman -Q "$1" >/dev/null 2>&1 ;;
  esac
}
install_packages() {
  local package
  local missing=()
  for package in "$@"; do
    if package_installed "$package"; then say "  Disponible: $package"; else missing+=("$package"); say "  Instalando: $package"; fi
  done
  ((${#missing[@]})) || return 0
  case "$FAMILY" in
    apt)
      apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 update
      apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 install -y --no-install-recommends "${missing[@]}" ;;
    rpm) "$RPM_MANAGER" -y install "${missing[@]}" ;;
    arch) pacman -Syu --needed --noconfirm "${missing[@]}" ;;
  esac
}
if ((CHECK_ONLY)); then
  missing_count=0
  for package in "${PACKAGES[@]}"; do
    if package_installed "$package"; then say "[OK] $package"; else say "[FALTA] $package"; missing_count=1; fi
  done
  say 'Comprobación finalizada. No se instalaron paquetes ni se cambió la red.'
  exit "$missing_count"
fi
declare -A FOREIGN_ENABLED=()
for service in firewalld.service nftables.service; do
  if systemctl is-active --quiet "$service"; then
    FOREIGN_FIREWALLS+=("$service")
    FOREIGN_ENABLED[$service]=0
    if systemctl is-enabled --quiet "$service"; then FOREIGN_ENABLED[$service]=1; fi
  fi
done
if ((${#FOREIGN_FIREWALLS[@]})) && (( ! MIGRATE_FIREWALL )); then
  say "ERROR: hay otro firewall activo: ${FOREIGN_FIREWALLS[*]}. No se superpondrá UFW."
  say 'Para un servidor nuevo podés repetir con --migrar-firewall. Guardará un respaldo, pero no traducirá sus reglas.'
  exit 2
fi

progress 1 'Verificar paquete integrado y parámetros'
WORK=$(mktemp -d /var/tmp/server-monitor.XXXXXX)
# PAYLOAD_INSTALLER


if [[ -n ${SSH_CONNECTION:-} ]]; then
  read -r client_address _ _ _ <<< "$SSH_CONNECTION"
  ADMIN_IPS+=("$client_address")
elif [[ -n ${SSH_CLIENT:-} ]]; then
  read -r client_address _ _ <<< "$SSH_CLIENT"
  ADMIN_IPS+=("$client_address")
fi
# No Python is required yet: syntax is checked after apt installs the interpreter.
for address in "${ADMIN_IPS[@]}"; do
  [[ $address =~ ^[0-9a-fA-F:.]+$ && ${#address} -le 45 ]] || { say 'ERROR: IP administrativa inválida.'; exit 2; }
done

progress 2 'Instalar dependencias según la distribución'
if [[ $FAMILY == rpm ]]; then
  install_packages dnf-plugins-core epel-release
  "$RPM_MANAGER" config-manager --set-enabled crb
fi
install_packages "${PACKAGES[@]}"
python3 -c 'import sys;assert sys.version_info >= (3,8), "Se necesita Python 3.8 o posterior desde un repositorio mantenido"'
for tool in python3 sudo visudo ufw iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore ipset ip ss sshd ssh-keygen systemctl systemd-run journalctl openssl curl awk tar gzip xz modprobe logrotate sha256sum; do
  command -v "$tool" >/dev/null || { say "ERROR: falta la herramienta requerida $tool después de instalar dependencias."; exit 1; }
done
python3 -c 'import base64,fcntl,gzip,hashlib,ipaddress,json,ssl,urllib.request;print("Python y biblioteca estándar disponibles.")'

python3 - "$WORK" "${ADMIN_IPS[@]}" <<'PY_VALIDATE'
import ipaddress,json,os,sys
from pathlib import Path
addresses=[str(ipaddress.ip_address(value)) for value in sys.argv[2:]]
server_ips=[];server_ports=[]
def connection(raw,full):
 if not raw:return
 addresses.append(str(ipaddress.ip_address(raw[0])))
 if full and len(raw)==4:server_ips.append(str(ipaddress.ip_address(raw[2])))
 if len(raw)==(4 if full else 3):
  port=int(raw[3 if full else 2])
  if not 1<=port<=65535:raise ValueError('Puerto de la conexión SSH no válido')
  server_ports.append(port)
process=os.getppid()
for _ in range(16):
 try:
  content=Path('/proc/'+str(process)+'/environ').read_bytes().split(b'\0')
  selected={v.split(b'=',1)[0]:v.split(b'=',1)[1] for v in content if v.startswith((b'SSH_CONNECTION=',b'SSH_CLIENT='))}
  raw=selected.get(b'SSH_CONNECTION',selected.get(b'SSH_CLIENT',b'')).decode('ascii').split()
  if raw:
   connection(raw,b'SSH_CONNECTION' in selected)
   break
  process=int(next(line.split()[1] for line in Path('/proc/'+str(process)+'/status').read_text().splitlines() if line.startswith('PPid:')))
  if process<=1:break
 except (OSError,ValueError,StopIteration,UnicodeError):break
# Include the inherited values too (and keep the current SSH server endpoint).
raw=os.environ.get('SSH_CONNECTION','').split()
connection(raw or os.environ.get('SSH_CLIENT','').split(),bool(raw))
(Path(sys.argv[1])/'admin-ips.json').write_text(json.dumps(sorted(set(addresses))))
(Path(sys.argv[1])/'server-ips.json').write_text(json.dumps(sorted(set(server_ips))))
(Path(sys.argv[1])/'ssh-session-ports.json').write_text(json.dumps(sorted(set(server_ports))))
PY_VALIDATE
mapfile -t ADMIN_IPS < <(python3 -c 'import json,sys;sys.stdout.write("".join(value+"\n" for value in json.load(open(sys.argv[1]))))' "$WORK/admin-ips.json")
# PAYLOAD_EXTRACTOR

for file in "$WORK"/*.py; do python3 -c 'import ast,sys;ast.parse(open(sys.argv[1],encoding="utf-8-sig").read())' "$file"; done
/usr/bin/bash -n "$WORK/instalar-control-bloqueos.sh"
/usr/bin/bash -n "$WORK/instalar-forwarding.sh"
/usr/bin/bash -n "$WORK/ssh_security.ssh"

progress 3 'Respaldar configuración y componentes actuales'
BACKUP=/var/backups/server-monitor-installer/$(date -u +%Y%m%dT%H%M%SZ)-$$
install -d -o root -g root -m 0700 "$BACKUP"
# Debian 12/coreutils 9.1 needs explicit ancestors for a fresh backup.
# Other distributions, including Debian 13, retain the original copy operation.
backup_path() {
  local path=$1 parent code
  if [[ $ID != debian || ${VERSION_ID%%.*} != 12 ]]; then
    [[ ! -e $path ]] || cp -a --parents -- "$path" "$BACKUP/"
    return
  fi
  [[ -e $path || -L $path ]] || return 0
  parent=$BACKUP${path%/*}
  install -d -o root -g root -m 0700 -- "$parent"
  if cp -a -- "$path" "$parent/"; then
    return 0
  else
    code=$?
    say "ERROR: no se pudo respaldar $path. Se detiene la instalación."
    return "$code"
  fi
}
for path in /usr/local/lib/storypulse-security/ssh_security.ssh /etc/ufw /etc/firewalld /etc/nftables.conf /etc/storypulse-security /etc/storypulse-alerts/telegram.env /etc/systemd/journald.conf.d/60-server-monitor.conf /etc/logrotate.d/server-monitor-security /etc/sudoers.d/storypulse-securityctl /etc/systemd/system/storypulse-manual-blocks.service /etc/systemd/system/storypulse-forwarding.service /etc/systemd/system/storypulse-cleanup.service /etc/systemd/system/storypulse-cleanup.timer /etc/systemd/system/server-monitor-alerts.service /etc/systemd/system/ufw-vps-providers.service.d/storypulse-manual-blocks.conf; do
  backup_path "$path"
done
for source in "$WORK"/*.py; do
  name=${source##*/}
  case "$name" in collector.py) name=storypulse_collector.py ;; storypulse-securityctl.py) name=storypulse-securityctl ;; esac
  backup_path "/usr/local/sbin/$name"
done
say "Respaldo: $BACKUP"

progress 4 'Comprobar el acceso SSH directo'
# Arch/RPM generate host keys when sshd first starts; validate only after creating missing keys.
ssh-keygen -A
install -d -o root -g root -m 0755 /run/sshd
/usr/sbin/sshd -t
systemctl enable --now "$SSH_SERVICE"
ssh_configuration=$(/usr/sbin/sshd -T)
python3 - "$WORK/ssh-session-ports.json" "$ssh_configuration" > "$WORK/ssh-ports.txt" <<'PY_SSH_PORTS'
import json,sys
ports=set(json.load(open(sys.argv[1])))
for line in sys.argv[2].splitlines():
 fields=line.split()
 if len(fields)==2 and fields[0]=='port':ports.add(int(fields[1]))
if not ports or any(type(port) is not int or not 1<=port<=65535 for port in ports):raise ValueError('Puertos SSH no válidos')
print('\n'.join(map(str,sorted(ports))))
PY_SSH_PORTS
mapfile -t SSH_PORTS < "$WORK/ssh-ports.txt"
((${#SSH_PORTS[@]} > 0)) || { say 'ERROR: no se pudieron identificar los puertos SSH.'; exit 1; }
say "Puertos SSH protegidos: ${SSH_PORTS[*]}"

progress 5 'Preparar UFW y comprobar el soporte del kernel'
if ! modprobe ip_set || ! modprobe xt_set; then
  if [[ $FAMILY == rpm ]]; then
    say '  Instalando módulos adicionales para el kernel actual'
    "$RPM_MANAGER" -y install "kernel-modules-extra-$(uname -r)"
    modprobe ip_set; modprobe xt_set
  else
    say 'ERROR: el kernel no permite ipset/xt_set; el proveedor debe habilitar esos módulos.'
    exit 1
  fi
fi
ufw_state=$(ufw status)
if grep -q '^Status: active$' <<< "$ufw_state"; then UFW_WAS_ACTIVE=1; fi
if ((!UFW_WAS_ACTIVE)) && ! grep -q '^Status: inactive$' <<< "$ufw_state"; then
  say 'ERROR: no se pudo determinar el estado de UFW. No se cambió el firewall.'; exit 1
fi
if ((!UFW_WAS_ACTIVE || ${#FOREIGN_FIREWALLS[@]})); then
  ((${#ADMIN_IPS[@]} > 0)) || { say 'ERROR: no se cambió el firewall. Desde consola, indicá --ip-admin para conservar el acceso.'; exit 2; }
fi
if ((!UFW_WAS_ACTIVE)); then
  ufw default deny incoming
  ufw default allow outgoing
else
  say 'UFW ya está activo: se conservan reglas y políticas; se comprueba el permiso SSH administrativo.'
fi
# Reposition only these exact administrative permits. UFW skips an existing
# equivalent rule instead of moving it ahead of a broad deny. Use prepend:
# insert 1 is invalid on an empty ruleset and can address the wrong IP family.
SSH_RULES_PENDING=1
for port in "${SSH_PORTS[@]}"; do
  for address in "${ADMIN_IPS[@]}"; do
    ufw --force delete allow in proto tcp from "$address" to any port "$port"
    # Test the status explicitly so ERR does not run rollback in a subshell.
    if ssh_rule_result=$(ufw prepend allow in proto tcp from "$address" to any port "$port" comment 'Server Monitor acceso administrativo' 2>&1); then
      say "$ssh_rule_result"
    else
      ssh_rule_code=$?
      say "ERROR: UFW no pudo anteponer el permiso SSH para $address en el puerto $port."
      say "$ssh_rule_result"
      failed "$ssh_rule_code" "$LINENO"
    fi
    if [[ $ssh_rule_result == *'Skipping inserting existing rule'* ]]; then
      say 'ERROR: una regla SSH específica en conflicto impide crear la excepción administrativa. No se activó otro firewall.'
      failed 1 "$LINENO"
    fi
  done
done
SSH_RULES_PENDING=0
if ((${#FOREIGN_FIREWALLS[@]})); then
  MIGRATION_PENDING=1
  for service in "${FOREIGN_FIREWALLS[@]}"; do
    say "  Migrando desde $service: respaldo guardado; se conservará acceso SSH"
    systemctl stop "$service"
  done
fi
if ((!UFW_WAS_ACTIVE)); then
  ufw --force enable
fi
ufw logging low
# Persist UFW on distributions whose package does not enable the unit by default.
systemctl enable ufw.service
iptables -L ufw-before-input -n >/dev/null
ip6tables -L ufw6-before-input -n >/dev/null
ipset list -n >/dev/null
for service in "${FOREIGN_FIREWALLS[@]}"; do systemctl disable "$service"; done
MIGRATION_PENDING=0

progress 6 'Instalar el controlador limitado y las tareas persistentes'
install -d -o root -g root -m 0700 /etc/storypulse-security
python3 - "$WORK" <<'PY_PROTECTION'
import ipaddress,json,os,subprocess,sys,tempfile
from pathlib import Path
path=Path('/etc/storypulse-security/protected-networks.json')
if path.is_symlink():raise SystemExit('ERROR: ruta de redes protegidas insegura.')
values=json.loads(path.read_text()) if path.exists() else []
if not isinstance(values,list):raise SystemExit('ERROR: redes protegidas existentes inválidas.')
values=[str(ipaddress.ip_network(value,strict=True)) for value in values]
for value in json.loads((Path(sys.argv[1])/'admin-ips.json').read_text()):
 values.append(str(ipaddress.ip_network(ipaddress.ip_address(value))))
result=subprocess.run(['/usr/sbin/ip','-j','address','show'],check=True,text=True,capture_output=True,timeout=10)
for interface in json.loads(result.stdout):
 for info in interface.get('addr_info',[]):
  address=ipaddress.ip_address(info['local'])
  if address.is_global:values.append(str(ipaddress.ip_network(address)))
fd,name=tempfile.mkstemp(prefix='.networks-',dir=path.parent)
with os.fdopen(fd,'w') as target:json.dump(sorted(set(values)),target);target.write('\n');target.flush();os.fsync(target.fileno())
os.chmod(name,0o600);os.replace(name,path)
PY_PROTECTION
# Seed the real SSH client plus this server's addresses, preserving existing secrets/settings.
python3 - "$WORK" <<'PY_ALERTS'
import ipaddress,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import storypulse_trusted as trusted
root=Path(sys.argv[1])
values=json.loads((root/'admin-ips.json').read_text())+json.loads((root/'server-ips.json').read_text())
interfaces=json.loads(subprocess.run(['/usr/sbin/ip','-j','address','show'],check=True,capture_output=True,text=True,timeout=10).stdout)
for interface in interfaces:
 for item in interface.get('addr_info',[]):
  ip=ipaddress.ip_address(item['local'])
  if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):values.append(str(ip))
paths=(Path('/etc/storypulse-alerts/telegram.env'),Path('/etc/storypulse-security/alerts.env'))
try:path,text,previous,info=trusted.read_setting(paths)
except trusted.TrustedError:
 if any(p.exists() for p in paths):raise
 path=paths[-1];text='TRUSTED_IPS=""\n';previous=[]
values=sorted(set(previous+[trusted.canonical(ip) for ip in values]))
if len(values)>256:raise SystemExit('Demasiadas IP autorizadas; revisá las interfaces del servidor.')
updated=trusted.SETTING.sub(lambda m:'TRUSTED_IPS="'+','.join(values)+'"',text)
if path==paths[-1]:trusted.atomic(path,updated.encode())
else:print('Se conserva intacta la configuración del sistema de alertas externo existente.')
print('IP autorizadas preparadas:',len(values),'entradas; cliente SSH y direcciones del servidor incluidos.')
PY_ALERTS
# Existing external Telegram services are never restarted by this installer.
say 'Autorización automática preparada; alertas sólo por accesos autenticados.'
STORYPULSE_PANEL_USER="$PANEL_USER" /bin/sh "$WORK/instalar-control-bloqueos.sh" "$WORK/storypulse-securityctl.py"

progress 7 'Configurar retención y rotación de registros'
install -d -o root -g root -m 0755 /etc/systemd/journald.conf.d
cat > "$WORK/journal.conf" <<'JOURNAL'
[Journal]
Storage=persistent
SystemMaxUse=512M
RuntimeMaxUse=128M
MaxRetentionSec=30day
JOURNAL
install -o root -g root -m 0644 "$WORK/journal.conf" /etc/systemd/journald.conf.d/60-server-monitor.conf
install -d -o root -g root -m 0755 /etc/logrotate.d
cat > "$WORK/logrotate.conf" <<'ROTATION'
/var/log/storypulse-security-blocks.jsonl {
 weekly
 rotate 8
 maxsize 16M
 compress
 delaycompress
 missingok
 notifempty
 create 0600 root root
}
ROTATION
install -o root -g root -m 0644 "$WORK/logrotate.conf" /etc/logrotate.d/server-monitor-security
systemctl restart systemd-journald.service
journalctl --flush
if systemctl cat logrotate.timer >/dev/null 2>&1; then
  systemctl enable --now logrotate.timer
else
  # Some RPM installations ship a cron job instead of a systemd timer.
  LOGROTATE_BIN=$(command -v logrotate)
  printf '[Unit]\nDescription=Monitor Security log rotation\n[Service]\nType=oneshot\nExecStart=%s /etc/logrotate.conf\n' "$LOGROTATE_BIN" > /etc/systemd/system/storypulse-logrotate.service
  printf '[Unit]\nDescription=Monitor Security daily log rotation\n[Timer]\nOnCalendar=daily\nPersistent=true\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/storypulse-logrotate.timer
  systemctl daemon-reload
  systemctl enable --now storypulse-logrotate.timer
fi

progress 8 'Comprobar funciones base y mostrar conexión'
visudo -cf /etc/sudoers.d/storypulse-securityctl
# Output remains root-owned in the private installer workspace.
# shellcheck disable=SC2024
sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl system-metrics --json-input <<< '{}' > "$WORK/metrics.json"
python3 - "$WORK/metrics.json" <<'PY_RESULT'
import json,sys
value=json.load(open(sys.argv[1]));assert value.get('ok') is True
print('Hardware leído correctamente. Servidor:',value['hostname'],'IP pública:',value.get('public_ip') or 'sin detectar')
PY_RESULT
sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl services-status --json-input <<< '{}' > "$WORK/ftp-status.json"
sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl mysql-status --json-input <<< '{}' > "$WORK/mysql-status.json"
systemctl is-active storypulse-manual-blocks.service storypulse-cleanup.timer
systemctl is-enabled --quiet ufw.service
# Output remains root-owned in the private installer workspace.
# shellcheck disable=SC2024
collector_until=$(date +%s)
sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl collect --json-input <<< "{\"since\":$((collector_until-60)),\"until\":$collector_until}" > "$WORK/collector.json.gz64"
python3 - "$WORK/collector.json.gz64" <<'PY_COLLECT'
import base64,gzip,json,sys
wire=open(sys.argv[1]).read().strip();assert wire.startswith('SPGZIP1:')
data=json.loads(gzip.decompress(base64.b64decode(wire[8:],validate=True)));assert data.get('ok') is True
assert isinstance(data.get('events'),list) and isinstance(data.get('providers'),list),'Respuesta de historial incompleta'
assert type(data.get('generated_at')) is int and type(data.get('collected_until')) is int,'Límites de historial ausentes'
system=data.get('system',{})
assert system.get('accept_monitor',{}).get('enabled') is True,'No quedó activo el registro de tráfico entrante'
assert system.get('outgoing_monitor',{}).get('enabled') is True,'No quedó activo el registro de tráfico saliente'
assert isinstance(system.get('services'),list),'Inventario de servicios ausente'
print('Lectura SSH, firewall, servicios y tráfico entrante/saliente verificada con el usuario del panel.')
PY_COLLECT
say 'INSTALACIÓN COMPLETADA — Monitor Security by FacuSecX'
say "Distribución: $PRETTY_NAME | Usuario SSH: $PANEL_USER"
say "Log: $LOG | Respaldo: $BACKUP"
say 'Huellas SSH del servidor: comparalas con la que muestre el asistente de conexión.'
for key in /etc/ssh/ssh_host_*_key.pub; do [[ ! -f $key ]] || show ssh-keygen -lf "$key"; done
say "Puertos SSH: ${SSH_PORTS[*]}. El panel utiliza la IP o dominio de este servidor."
say 'Windows: abrir iniciar-panel.exe o iniciar-panel.bat y completar el asistente gráfico.'
say 'Permite contraseña SSH o llave PPK/OpenSSH. La conexión protegida utiliza SSH.NET integrado.'
say 'La web permanece en el equipo Windows, normalmente en http://127.0.0.1:8766; no necesita un puerto web abierto en el VPS.'
say 'Los puertos de SA-MP, FTPS, bases de datos y otros servicios se habilitan al instalar/configurar cada servicio desde el panel.'
say 'https://github.com/FacuSecX'
