#!/bin/sh
# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecuta este instalador con sudo." >&2
  exit 1
fi

source_file="${1:-$(dirname "$0")/storypulse-securityctl.py}"
if [ ! -f "$source_file" ]; then
  echo "ERROR: no se encontró storypulse-securityctl.py" >&2
  exit 1
fi

for file in storypulse_trusted.py storypulse_platform.py storypulse-securityctl.py collector.py storypulse_report.py storypulse_ports.py storypulse_forwarding.py storypulse_services.py storypulse_mysql.py storypulse_cleanup.py storypulse_system.py storypulse_panel_alerts.py; do
  [ -f "$(dirname "$source_file")/$file" ] || { echo "ERROR: falta $file" >&2; exit 1; }
  python3 -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8-sig").read())' "$(dirname "$source_file")/$file"
done
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_trusted.py" /usr/local/sbin/storypulse_trusted.py
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_platform.py" /usr/local/sbin/storypulse_platform.py
install -o root -g root -m 0644 "$(dirname "$source_file")/collector.py" /usr/local/sbin/storypulse_collector.py
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_report.py" /usr/local/sbin/storypulse_report.py
[ -f "$(dirname "$source_file")/ssh_security.ssh" ] || { echo "ERROR: falta ssh_security.ssh" >&2; exit 1; }
/usr/bin/bash -n "$(dirname "$source_file")/ssh_security.ssh"

printf '%s  %s\n' 543cf0e2055edda59a2a7c1c9913d35867cd524a872f3aa3f5e12750c215d07a "$(dirname "$source_file")/ssh_security.ssh" | sha256sum -c -
install -d -o root -g root -m 0755 /usr/local/lib/storypulse-security
install -o root -g root -m 0700 "$(dirname "$source_file")/ssh_security.ssh" /usr/local/lib/storypulse-security/ssh_security.ssh
install -d -o root -g root -m 0700 /var/lib/storypulse-security/Informes/SSH/archivos /var/cache/storypulse-security
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_services.py" /usr/local/sbin/storypulse_services.py
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_mysql.py" /usr/local/sbin/storypulse_mysql.py
ports_file="$(dirname "$source_file")/storypulse_ports.py"
if [ ! -f "$ports_file" ]; then
  echo "ERROR: no se encontró storypulse_ports.py" >&2
  exit 1
fi
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_forwarding.py" /usr/local/sbin/storypulse_forwarding.py
/bin/sh "$(dirname "$source_file")/instalar-forwarding.sh"
install -o root -g root -m 0644 "$ports_file" /usr/local/sbin/storypulse_ports.py
install -o root -g root -m 0755 "$source_file" /usr/local/sbin/storypulse-securityctl
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_cleanup.py" /usr/local/sbin/storypulse_cleanup.py
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_system.py" /usr/local/sbin/storypulse_system.py
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse-cleanup.service" /etc/systemd/system/storypulse-cleanup.service
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse-cleanup.timer" /etc/systemd/system/storypulse-cleanup.timer
install -d -o root -g root -m 0755 /var/lib/storypulse-cleanup
install -o root -g root -m 0644 "$(dirname "$source_file")/storypulse_panel_alerts.py" /usr/local/sbin/storypulse_panel_alerts.py
install -o root -g root -m 0644 "$(dirname "$source_file")/server-monitor-alerts.service" /etc/systemd/system/server-monitor-alerts.service
install -d -o root -g root -m 0700 /var/lib/server-monitor-alerts

systemctl daemon-reload
systemctl enable --now storypulse-cleanup.timer
install -d -o root -g root -m 0700 /etc/storypulse-security
if [ ! -f /etc/storypulse-security/manual-blocks.json ]; then
  printf '[]\n' > /etc/storypulse-security/manual-blocks.json
fi
if [ ! -f /etc/storypulse-security/provider-blocks.json ]; then
  printf '[]\n' > /etc/storypulse-security/provider-blocks.json
fi
chown root:root /etc/storypulse-security/manual-blocks.json /etc/storypulse-security/provider-blocks.json
chmod 0600 /etc/storypulse-security/manual-blocks.json /etc/storypulse-security/provider-blocks.json

panel_user="${STORYPULSE_PANEL_USER:-${SUDO_USER:-debian}}"
case "$panel_user" in
  ''|*[!A-Za-z0-9_-]*)
    echo "ERROR: usuario administrativo no válido." >&2
    exit 1
    ;;
esac

sudoers_tmp="$(mktemp)"
trap 'rm -f "$sudoers_tmp"' EXIT
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/storypulse-securityctl *\n' "$panel_user" > "$sudoers_tmp"
chmod 0440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
install -o root -g root -m 0440 "$sudoers_tmp" /etc/sudoers.d/storypulse-securityctl

cat > /etc/systemd/system/storypulse-manual-blocks.service <<'EOF'
[Unit]
Description=StoryPulse manual IP and approved provider blocks
After=network-online.target ufw.service ufw-vps-providers.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/storypulse-securityctl sync
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

if systemctl cat ufw-vps-providers.service >/dev/null 2>&1; then
  install -d -o root -g root -m 0755 /etc/systemd/system/ufw-vps-providers.service.d
  cat > /etc/systemd/system/ufw-vps-providers.service.d/storypulse-manual-blocks.conf <<'EOF'
[Service]
ExecStartPost=/usr/local/sbin/storypulse-securityctl sync
EOF
fi

systemctl daemon-reload
systemctl enable --now storypulse-manual-blocks.service
/usr/local/sbin/storypulse-securityctl sync
/usr/local/sbin/storypulse-securityctl status

echo
echo "Control de bloqueos instalado correctamente."
echo "Los proveedores aprobados usan conjuntos ipset persistentes separados."
echo "El monitoreo de conexiones nuevas aceptadas quedó sincronizado con las reglas ALLOW de UFW."
echo "La generación limitada de reportes SSH quedó disponible para el panel."
echo "El panel sólo puede ejecutar el controlador limitado storypulse-securityctl."


