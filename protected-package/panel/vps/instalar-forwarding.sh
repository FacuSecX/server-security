#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Ejecutar como root" >&2; exit 1; }
install -d -o root -g root -m 0700 /etc/storypulse-security
hook=/etc/ufw/after.init
if [ -e "$hook" ] && ! grep -q '^# StoryPulse forwarding hook v1$' "$hook"; then
  if [ -e /etc/storypulse-security/ufw-after.original ]; then
    echo "Existe un respaldo anterior del hook UFW; revisar antes de reemplazar." >&2
    exit 1
  fi
  cp -p "$hook" /etc/storypulse-security/ufw-after.original
fi
hook_tmp=$(mktemp /etc/ufw/.storypulse-after.XXXXXX)
trap 'rm -f "$hook_tmp"' EXIT
cat > "$hook_tmp" <<'EOF'
#!/bin/sh
# StoryPulse forwarding hook v1
set -eu
if [ -x /etc/storypulse-security/ufw-after.original ]; then
  /bin/sh /etc/storypulse-security/ufw-after.original "$@"
fi
case "${1:-}" in
  start|restart|reload|force-reload|stop|flush-all)
    /usr/local/sbin/storypulse-securityctl forwarding-sync --from-hook
    ;;
esac
EOF
chown root:root "$hook_tmp"
chmod 0755 "$hook_tmp"
mv -f "$hook_tmp" "$hook"
cat > /etc/systemd/system/storypulse-forwarding.service <<'EOF'
[Unit]
Description=StoryPulse managed IPv4 port forwarding
After=network-online.target ufw.service ufw-vps-providers.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/storypulse-securityctl forwarding-sync
RemainAfterExit=yes
TimeoutStartSec=90
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable storypulse-forwarding.service
# Empty installation does not enable routing, change NAT or restart UFW.
