#!/usr/bin/env bash
# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
[[ $EUID -eq 0 ]] || { echo 'ERROR: este instalador sólo puede ejecutarse como root (sudo bash instalar-servidor.sh).' >&2; exit 1; }
PANEL_USER=${SUDO_USER:-root}
CHECK_ONLY=0 WITH_TAILSCALE=1 LOGIN_TAILSCALE=0 MIGRATE_FIREWALL=0
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
  say '--sin-tailscale        Usar otro canal SSH seguro.'
  say '--iniciar-tailscale    Mostrar el enlace de autorización al finalizar.'
  say '--migrar-firewall      Respaldar y desactivar firewalld/nftables; aplicar UFW con acceso SSH. No importa reglas ajenas.'
  say '--comprobar            Diagnóstico sin instalar ni cambiar la red (conserva sólo su log).'
  say '--ayuda               Mostrar ayuda.'
  say 'FTP y MySQL/MariaDB se instalan después desde el panel. La web sigue en Windows.'
}
while (($#)); do
  case "$1" in
    --usuario|--ip-admin)
      (($# >= 2)) || { say "ERROR: falta valor para $1"; exit 2; }
      if [[ $1 == --usuario ]]; then PANEL_USER=$2; else ADMIN_IPS+=("$2"); fi
      shift 2 ;;
    --sin-tailscale) WITH_TAILSCALE=0; shift ;;
    --iniciar-tailscale) LOGIN_TAILSCALE=1; shift ;;
    --migrar-firewall) MIGRATE_FIREWALL=1; shift ;;
    --comprobar) CHECK_ONLY=1; shift ;;
    --ayuda|--help|-h) usage; exit 0 ;;
    *) say "ERROR: opción desconocida: $1"; usage; exit 2 ;;
  esac
done
[[ -r /etc/os-release ]] || { say 'ERROR: no se encontró /etc/os-release.'; exit 1; }

. /etc/os-release
case ${ID:-} in
  debian|ubuntu)
    FAMILY=apt SSH_SERVICE=ssh.service
    command -v apt-get >/dev/null || { say 'ERROR: no se encontró APT.'; exit 1; }
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz-utils util-linux python3 sudo ufw iptables ipset iproute2 openssh-server ca-certificates curl jq gawk tzdata openssl logrotate kmod) ;;
  centos)
    FAMILY=rpm SSH_SERVICE=sshd.service
    MAJOR=${VERSION_ID%%.*}
    [[ $MAJOR =~ ^[0-9]+$ && $MAJOR -ge 9 ]] || { say 'ERROR: CentOS Linux 7/8 y Stream 8 están fuera de soporte. Se necesita CentOS Stream 9 o posterior.'; exit 1; }
    if command -v dnf >/dev/null; then RPM_MANAGER=dnf; elif command -v yum >/dev/null; then RPM_MANAGER=yum; else say 'ERROR: falta DNF/YUM.'; exit 1; fi
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz util-linux python3 sudo ufw iptables ipset iproute openssh-server ca-certificates curl jq gawk tzdata openssl logrotate kmod policycoreutils-python-utils) ;;
  arch)
    FAMILY=arch SSH_SERVICE=sshd.service
    command -v pacman >/dev/null || { say 'ERROR: no se encontró Pacman.'; exit 1; }
    PACKAGES=(bash coreutils findutils grep sed tar gzip xz util-linux python sudo ufw iptables ipset iproute2 openssh ca-certificates curl jq gawk tzdata openssl logrotate kmod) ;;
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
for service in firewalld.service nftables.service; do
  if systemctl is-active --quiet "$service"; then FOREIGN_FIREWALLS+=("$service"); fi
done
if ((${#FOREIGN_FIREWALLS[@]})) && (( ! MIGRATE_FIREWALL )); then
  say "ERROR: hay otro firewall activo: ${FOREIGN_FIREWALLS[*]}. No se superpondrá UFW."
  say 'Para un servidor nuevo podés repetir con --migrar-firewall. Guardará un respaldo, pero no traducirá sus reglas.'
  exit 2
fi

progress 1 'Verificar paquete integrado y parámetros'
WORK=$(mktemp -d /var/tmp/server-monitor.XXXXXX)
__SERVER_MONITOR_PAYLOAD_INSTALLER__

if [[ -n ${SSH_CONNECTION:-} ]]; then
  read -r client_address _ _ _ <<< "$SSH_CONNECTION"
  ADMIN_IPS+=("$client_address")
elif [[ -n ${SSH_CLIENT:-} ]]; then
  read -r client_address _ _ <<< "$SSH_CLIENT"
  ADMIN_IPS+=("$client_address")
fi

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
python3 - "$WORK" "${ADMIN_IPS[@]}" <<'PY_VALIDATE'
import ipaddress,json,os,sys
from pathlib import Path
addresses=[str(ipaddress.ip_address(value)) for value in sys.argv[2:]]
server_ips=[]
process=os.getppid()
for _ in range(16):
 try:
  content=Path('/proc/'+str(process)+'/environ').read_bytes().split(b'\0')
  selected={v.split(b'=',1)[0]:v.split(b'=',1)[1] for v in content if v.startswith((b'SSH_CONNECTION=',b'SSH_CLIENT='))}
  raw=selected.get(b'SSH_CONNECTION',selected.get(b'SSH_CLIENT',b'')).decode('ascii').split()
  if raw:
   addresses.append(str(ipaddress.ip_address(raw[0])))
   if b'SSH_CONNECTION' in selected and len(raw)==4:server_ips.append(str(ipaddress.ip_address(raw[2])))
   break
  process=int(next(line.split()[1] for line in Path('/proc/'+str(process)+'/status').read_text().splitlines() if line.startswith('PPid:')))
  if process<=1:break
 except (OSError,ValueError,StopIteration,UnicodeError):break

raw=os.environ.get('SSH_CONNECTION','').split()
if len(raw)==4:server_ips.append(str(ipaddress.ip_address(raw[2])))
(Path(sys.argv[1])/'admin-ips.json').write_text(json.dumps(sorted(set(addresses))))
(Path(sys.argv[1])/'server-ips.json').write_text(json.dumps(sorted(set(server_ips))))
PY_VALIDATE
mapfile -t ADMIN_IPS < <(python3 -c 'import json,sys;print("\n".join(json.load(open(sys.argv[1]))))' "$WORK/admin-ips.json")
__SERVER_MONITOR_PAYLOAD_EXTRACTOR__
for file in "$WORK"/*.py; do python3 -c 'import ast,sys;ast.parse(open(sys.argv[1],encoding="utf-8-sig").read())' "$file"; done
/usr/bin/bash -n "$WORK/instalar-control-bloqueos.sh"
/usr/bin/bash -n "$WORK/instalar-forwarding.sh"
/usr/bin/bash -n "$WORK/ssh_security.ssh"

progress 3 'Respaldar configuración y componentes actuales'
BACKUP=/var/backups/server-monitor-installer/$(date -u +%Y%m%dT%H%M%SZ)-$$
install -d -o root -g root -m 0700 "$BACKUP"
for path in /usr/local/lib/storypulse-security/ssh_security.ssh /etc/ufw /etc/firewalld /etc/nftables.conf /etc/storypulse-security /etc/storypulse-alerts/telegram.env /etc/systemd/journald.conf.d/60-server-monitor.conf /etc/logrotate.d/server-monitor-security /etc/sudoers.d/storypulse-securityctl /etc/systemd/system/storypulse-manual-blocks.service /etc/systemd/system/storypulse-forwarding.service /etc/systemd/system/storypulse-cleanup.service /etc/systemd/system/storypulse-cleanup.timer; do
  if [[ -e $path ]]; then cp -a --parents -- "$path" "$BACKUP/"; fi
done
for name in storypulse_trusted.py storypulse-securityctl storypulse_platform.py storypulse_collector.py storypulse_report.py storypulse_ports.py storypulse_forwarding.py storypulse_services.py storypulse_mysql.py storypulse_cleanup.py storypulse_system.py; do
  [[ ! -e /usr/local/sbin/$name ]] || cp -a --parents -- "/usr/local/sbin/$name" "$BACKUP/"
done
say "Respaldo: $BACKUP"

progress 4 'Preparar acceso privado y Tailscale'
if ((WITH_TAILSCALE)); then
  if ! command -v tailscale >/dev/null; then
    say '  Instalando: tailscale'
    case "$FAMILY" in
      apt)
        [[ ${VERSION_CODENAME:-} =~ ^[a-z][a-z0-9_-]*$ ]] || { say 'ERROR: el sistema no informa un nombre de versión válido para Tailscale.'; exit 1; }
        curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 45 --max-filesize 1048576 \
          "https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.noarmor.gpg" -o "$WORK/tailscale.gpg"
        install -o root -g root -m 0644 "$WORK/tailscale.gpg" /usr/share/keyrings/tailscale-archive-keyring.gpg
        printf '%s\n' "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/$ID $VERSION_CODENAME main" > "$WORK/tailscale.list"
        install -o root -g root -m 0644 "$WORK/tailscale.list" /etc/apt/sources.list.d/tailscale.list
        install_packages tailscale ;;
      rpm)
        curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --max-time 45 --max-filesize 1048576 \
          "https://pkgs.tailscale.com/stable/centos/$MAJOR/tailscale.repo" -o "$WORK/tailscale.repo"
        install -o root -g root -m 0644 "$WORK/tailscale.repo" /etc/yum.repos.d/tailscale.repo
        install_packages tailscale ;;
      arch) install_packages tailscale ;;
    esac
  else say '  Disponible: tailscale'; fi
  systemctl enable --now tailscaled.service
fi
systemctl enable --now "$SSH_SERVICE"
ssh_configuration=$(/usr/sbin/sshd -T)
mapfile -t SSH_PORTS < <(printf '%s\n' "$ssh_configuration" | awk '$1=="port" && $2 ~ /^[0-9]+$/ {print $2}' | sort -nu)
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
for service in "${FOREIGN_FIREWALLS[@]}"; do
  say "  Migrando desde $service: respaldo guardado; se conservará acceso SSH"
  systemctl disable --now "$service"
done
if ! ufw status | grep -q '^Status: active$'; then
  ((${#ADMIN_IPS[@]} > 0)) || { say 'ERROR: no se activó UFW. Desde consola, indicá --ip-admin para conservar el acceso.'; exit 2; }
  ufw default deny incoming
  ufw default allow outgoing
  for port in "${SSH_PORTS[@]}"; do
    for address in "${ADMIN_IPS[@]}"; do
      ufw allow in proto tcp from "$address" to any port "$port" comment 'Server Monitor acceso administrativo'
    done
    if ((WITH_TAILSCALE)); then ufw allow in on tailscale0 proto tcp to any port "$port" comment 'Server Monitor SSH privado'; fi
  done
  ufw --force enable
else
  say 'UFW ya está activo: se conservan reglas, políticas y accesos existentes.'
fi
ufw logging low
iptables -L ufw-before-input -n >/dev/null
ip6tables -L ufw6-before-input -n >/dev/null
ipset list -n >/dev/null

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
  
  LOGROTATE_BIN=$(command -v logrotate)
  printf '[Unit]\nDescription=Monitor Security log rotation\n[Service]\nType=oneshot\nExecStart=%s /etc/logrotate.conf\n' "$LOGROTATE_BIN" > /etc/systemd/system/storypulse-logrotate.service
  printf '[Unit]\nDescription=Monitor Security daily log rotation\n[Timer]\nOnCalendar=daily\nPersistent=true\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/storypulse-logrotate.timer
  systemctl daemon-reload
  systemctl enable --now storypulse-logrotate.timer
fi

progress 8 'Comprobar funciones base y mostrar conexión'
visudo -cf /etc/sudoers.d/storypulse-securityctl


sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl system-metrics --json-input <<< '{}' > "$WORK/metrics.json"
python3 - "$WORK/metrics.json" <<'PY_RESULT'
import json,sys
value=json.load(open(sys.argv[1]));assert value.get('ok') is True
print('Hardware leído correctamente. Servidor:',value['hostname'],'IP pública:',value.get('public_ip') or 'sin detectar')
PY_RESULT
/usr/local/sbin/storypulse-securityctl services-status --json-input <<< '{}' > "$WORK/ftp-status.json"
/usr/local/sbin/storypulse-securityctl mysql-status --json-input <<< '{}' > "$WORK/mysql-status.json"
systemctl is-active storypulse-manual-blocks.service storypulse-cleanup.timer


sudo -u "$PANEL_USER" sudo -n /usr/local/sbin/storypulse-securityctl collect --json-input <<< "{\"since\":$(date +%s),\"until\":$(date +%s)}" > "$WORK/collector.json.gz64"
python3 - "$WORK/collector.json.gz64" <<'PY_COLLECT'
import base64,gzip,json,sys
wire=open(sys.argv[1]).read().strip();assert wire.startswith('SPGZIP1:')
data=json.loads(gzip.decompress(base64.b64decode(wire[8:])));assert data.get('ok') is True
print('Recolección SSH/firewall verificada.')
PY_COLLECT
if ((WITH_TAILSCALE && LOGIN_TAILSCALE)); then
  if ! tailscale ip -4; then
    say 'Autorizá el enlace de Tailscale que se mostrará a continuación.'
    if ! show tailscale up --timeout=120s; then say 'Tailscale instalado, pero falta autorizarlo. Ejecutá sudo tailscale up cuando estés listo.'; fi
  fi
fi
say 'INSTALACIÓN COMPLETADA — Monitor Security by FacuSecX'
say "Distribución: $PRETTY_NAME | Usuario SSH: $PANEL_USER"
say "Log: $LOG | Respaldo: $BACKUP"
say 'Huella de la llave del servidor (config.json en Windows):'
show ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
if ((WITH_TAILSCALE)); then show tailscale ip -4 || say 'Falta autorizar Tailscale: sudo tailscale up'; fi
say 'Windows: Node.js 24 y PuTTY/Pageant; configurar host, usuario, llave y huella en config.json.'
say 'Abrir iniciar-panel.bat. La web sigue en http://127.0.0.1:8766.'
say 'FTP y MySQL/MariaDB se instalan después desde el panel según el sistema detectado.'
say 'https://github.com/FacuSecX'
