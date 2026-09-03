#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo." >&2
    exit 2
fi

OLD_SERVICE=gpoi_shutdown.service
OLD_UNIT=/etc/systemd/system/gpoi_shutdown.service
OLD_SCRIPT=/usr/local/sbin/gpoi_shutdown.py
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/ups-shutdown-legacy/$STAMP"
mkdir -p "$BACKUP_DIR"

echo "This migration removes ONLY the old GPIO12 Python monitor."
echo "It deliberately leaves the GPIO26 gpio-poweroff boot overlay untouched."
echo

# Never disable the only active UPS monitor while mains-loss is asserted. The
# known legacy installation uses raw GPIO12 LOW=mains healthy, HIGH=mains lost.
if systemctl is-active --quiet "$OLD_SERVICE" 2>/dev/null; then
    RAW=""
    if command -v pinctrl >/dev/null 2>&1; then
        RAW=$(pinctrl get 12 2>/dev/null || true)
    elif command -v raspi-gpio >/dev/null 2>&1; then
        RAW=$(raspi-gpio get 12 2>/dev/null || true)
    else
        echo "ERROR: cannot non-invasively verify GPIO12 before stopping the active legacy UPS monitor." >&2
        echo "Install/use pinctrl or raspi-gpio, or restore/verify mains manually before migration." >&2
        exit 3
    fi
    if grep -Eqi '(^|[|[:space:]])hi([[:space:]]|$)' <<<"$RAW"; then
        echo "ERROR: GPIO12 is HIGH (legacy mains-loss state)." >&2
        echo "Refusing to disable the active UPS monitor during a possible outage." >&2
        echo "Restore mains and verify GPIO12 LOW before rerunning migration." >&2
        exit 3
    fi
    if ! grep -Eqi '(^|[|[:space:]])lo([[:space:]]|$)' <<<"$RAW"; then
        echo "ERROR: could not determine raw GPIO12 state: $RAW" >&2
        echo "Refusing to disable the active UPS monitor without a known healthy input." >&2
        exit 3
    fi
    echo "Safety check: GPIO12 is LOW (mains healthy); legacy monitor may be stopped."
fi

if systemctl cat "$OLD_SERVICE" >/dev/null 2>&1; then
    systemctl cat "$OLD_SERVICE" > "$BACKUP_DIR/gpoi_shutdown.service.rendered.txt" || true
fi
[[ -f "$OLD_UNIT" ]] && cp -a "$OLD_UNIT" "$BACKUP_DIR/"
[[ -f "$OLD_SCRIPT" ]] && cp -a "$OLD_SCRIPT" "$BACKUP_DIR/"

echo "Stopping old service..."
systemctl stop "$OLD_SERVICE" 2>/dev/null || true
systemctl disable "$OLD_SERVICE" 2>/dev/null || true
systemctl reset-failed "$OLD_SERVICE" 2>/dev/null || true
sleep 1

if command -v gpioinfo >/dev/null 2>&1; then
    LINES=$(gpioinfo 2>/dev/null | grep '"GPIO12"' || true)
    if grep -Fq "[used" <<<"$LINES"; then
        echo "ERROR: GPIO12 is still claimed after stopping the old service:" >&2
        echo "$LINES" >&2
        echo "Do not continue until the remaining owner is identified." >&2
        if command -v lsof >/dev/null 2>&1; then
            echo >&2
            lsof /dev/gpiochip* 2>/dev/null || true
        fi
        exit 4
    fi
fi

rm -f "$OLD_UNIT"
rm -f "$OLD_SCRIPT"
systemctl daemon-reload
systemctl reset-failed "$OLD_SERVICE" 2>/dev/null || true

echo "Legacy files backed up to: $BACKUP_DIR"
echo "Old service removed. GPIO12 is free for transfer to ups-shutdown.service."
echo "GPIO26/gpio-poweroff was not modified."
