#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecuta este instalador con sudo." >&2
  exit 1
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_file="${1:-$script_dir/server-securityctl.py}"
settings_source="${2:-$script_dir/server-security-settings.example.json}"
collector_source="${3:-$script_dir/collector.py}"

if [ ! -f "$source_file" ]; then
  echo "ERROR: no se encontró server-securityctl.py" >&2
  exit 1
fi
if [ ! -f "$settings_source" ]; then
  echo "ERROR: no se encontró server-security-settings.example.json" >&2
  exit 1
fi
if [ ! -f "$collector_source" ]; then
  echo "ERROR: no se encontró collector.py" >&2
  exit 1
fi

install -o root -g root -m 0755 "$source_file" /usr/local/sbin/server-securityctl
install -d -o root -g root -m 0755 /usr/local/lib/server-security
install -o root -g root -m 0755 "$collector_source" /usr/local/lib/server-security/collector.py
install -d -o root -g root -m 0700 /etc/server-security
install -d -o root -g root -m 0750 /var/lib/server-security/reports

if [ ! -f /etc/server-security/settings.json ]; then
  install -o root -g root -m 0600 "$settings_source" /etc/server-security/settings.json
fi
if [ ! -f /etc/server-security/manual-blocks.json ]; then
  printf '[]\n' > /etc/server-security/manual-blocks.json
fi
if [ ! -f /etc/server-security/provider-blocks.json ]; then
  printf '[]\n' > /etc/server-security/provider-blocks.json
fi
chown root:root \
  /etc/server-security/settings.json \
  /etc/server-security/manual-blocks.json \
  /etc/server-security/provider-blocks.json
chmod 0600 \
  /etc/server-security/settings.json \
  /etc/server-security/manual-blocks.json \
  /etc/server-security/provider-blocks.json

panel_user="${SERVER_SECURITY_PANEL_USER:-${SUDO_USER:-}}"
case "$panel_user" in
  ''|root|*[!A-Za-z0-9_-]*)
    echo "ERROR: define SERVER_SECURITY_PANEL_USER con el usuario SSH administrativo no-root." >&2
    exit 1
    ;;
esac

sudoers_tmp="$(mktemp)"
trap 'rm -f "$sudoers_tmp"' EXIT
cat > "$sudoers_tmp" <<EOF
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl status
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl list
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl sync
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl block --json-input
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl unblock --json-input
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl provider-block --json-input
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl provider-unblock --json-input
$panel_user ALL=(root) NOPASSWD: /usr/local/sbin/server-securityctl report-ssh --json-input
$panel_user ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/lib/server-security/collector.py *
EOF
chmod 0440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
install -o root -g root -m 0440 "$sudoers_tmp" /etc/sudoers.d/server-securityctl

cat > /etc/systemd/system/server-security-manual-blocks.service <<'EOF'
[Unit]
Description=Server Security manual IP and approved provider blocks
After=network-online.target ufw.service ufw-vps-providers.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/server-securityctl sync
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

if systemctl cat ufw-vps-providers.service >/dev/null 2>&1; then
  install -d -o root -g root -m 0755 /etc/systemd/system/ufw-vps-providers.service.d
  cat > /etc/systemd/system/ufw-vps-providers.service.d/server-security-manual-blocks.conf <<'EOF'
[Service]
ExecStartPost=/usr/local/sbin/server-securityctl sync
EOF
fi

systemctl daemon-reload
systemctl enable --now server-security-manual-blocks.service
/usr/local/sbin/server-securityctl sync
/usr/local/sbin/server-securityctl status

echo
echo "Control de Server Security instalado correctamente."
echo "Configuración: /etc/server-security/settings.json"
echo "Reportes: /var/lib/server-security/reports"
echo "Sudo quedó limitado a las operaciones explícitas del controlador."
