#!/usr/bin/env bash
set -euo pipefail
REMOVE_STATE=0

for arg in "$@"; do
    case "$arg" in
        --remove-state) REMOVE_STATE=1 ;;
        -h|--help)
            cat <<'USAGE'
Usage: sudo ./uninstall-ups-shutdown.sh [--remove-state]

By design this does NOT remove the gpio-poweroff GPIO26 boot overlay. Removing the
kernel power-control overlay changes the hardware power-off contract and should be
done manually only after the relay/power circuit has been made safe.
USAGE
            exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 2; }

systemctl disable --now ups-shutdown.service 2>/dev/null || true
systemctl disable ups-shutdown-clean-marker.service 2>/dev/null || true
rm -f /etc/systemd/system/ups-shutdown.service /etc/systemd/system/ups-shutdown-clean-marker.service
rm -f /usr/local/sbin/ups-shutdown.py /usr/local/sbin/ups-shutdown-status /usr/local/sbin/ups-shutdown-host-setup /usr/local/sbin/ups-shutdown-smoke-test
rm -f /etc/logrotate.d/ups-shutdown
rm -rf /usr/local/share/doc/ups-shutdown
systemctl daemon-reload
systemctl reset-failed ups-shutdown.service 2>/dev/null || true

if (( REMOVE_STATE == 1 )); then
    rm -rf /var/lib/ups-shutdown
else
    echo "Preserved forensic state: /var/lib/ups-shutdown"
fi
# Revision 1 briefly offered an optional UPS-owned journald drop-in. Remove only
# that exact package-owned file if it still exists; leave all other journald policy alone.
if [[ -f /etc/systemd/journald.conf.d/90-ups-shutdown-persistent.conf ]] && \
   grep -Fq 'Installed by ups-shutdown' /etc/systemd/journald.conf.d/90-ups-shutdown-persistent.conf; then
    rm -f /etc/systemd/journald.conf.d/90-ups-shutdown-persistent.conf
    echo "Removed obsolete ups-shutdown journald drop-in; existing /var/log/journal data was left untouched."
fi

echo "Removed native UPS monitor."
echo "IMPORTANT: GPIO26 gpio-poweroff boot configuration was intentionally left untouched."
