#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PAYLOAD="$ROOT/payload"
REPLACE_OVERLAY=0
SKIP_DESKTOP=0

for arg in "$@"; do
    case "$arg" in
        --replace-existing-overlay) REPLACE_OVERLAY=1 ;;
        --skip-desktop) SKIP_DESKTOP=1 ;;
        -h|--help)
            cat <<'USAGE'
Usage: sudo ./install-ups-shutdown.sh [options]

Options:
  --replace-existing-overlay   Replace a different gpio-poweroff boot line (review first)
  --skip-desktop               Do not create the invoking user's Desktop reference folder

The installer refuses to proceed while legacy gpoi_shutdown.service is still installed.
Run ./remove-legacy-gpoi-service.sh first for migration.
USAGE
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo." >&2
    exit 2
fi

if [[ ! -r /proc/device-tree/model ]] || ! tr -d '\0' </proc/device-tree/model | grep -qi 'raspberry pi'; then
    echo "This installer is intended for Raspberry Pi OS on Raspberry Pi hardware." >&2
    exit 2
fi

for f in ups-shutdown.py ups-shutdown.service ups-shutdown-clean-marker.service ups-shutdown.default ups-shutdown-status ups-shutdown-host-setup ups-shutdown-smoke-test ups-shutdown.logrotate; do
    [[ -f "$PAYLOAD/$f" ]] || { echo "Package is incomplete: missing payload/$f" >&2; exit 2; }
done

if systemctl cat gpoi_shutdown.service >/dev/null 2>&1 || [[ -e /etc/systemd/system/gpoi_shutdown.service ]] || [[ -e /usr/local/sbin/gpoi_shutdown.py ]]; then
    cat >&2 <<'MSG'
Legacy gpoi_shutdown installation detected.

Refusing to run both GPIO12 monitors at once. First run:
  sudo ./remove-legacy-gpoi-service.sh

That helper backs up and removes only the old Python/service files. It deliberately
leaves the working GPIO26 gpio-poweroff overlay untouched.
MSG
    exit 4
fi

# Do not update/restart an existing monitor while its input already signals power fail.
EXISTING_GPIO_INPUT=12
EXISTING_POWER_FAIL_LEVEL=HIGH
if [[ -r /etc/default/ups-shutdown ]]; then
    # shellcheck disable=SC1091
    source /etc/default/ups-shutdown
    EXISTING_GPIO_INPUT=${GPIO_INPUT:-12}
    EXISTING_POWER_FAIL_LEVEL=${POWER_FAIL_LEVEL:-HIGH}
fi
if systemctl is-active --quiet ups-shutdown.service 2>/dev/null; then
    RAW=""
    if command -v pinctrl >/dev/null 2>&1; then
        RAW=$(pinctrl get "$EXISTING_GPIO_INPUT" 2>/dev/null || true)
    elif command -v raspi-gpio >/dev/null 2>&1; then
        RAW=$(raspi-gpio get "$EXISTING_GPIO_INPUT" 2>/dev/null || true)
    else
        echo "Cannot non-invasively verify the active UPS input before stopping the service." >&2
        echo "Refusing to update an armed power-protection service without a known healthy input." >&2
        exit 5
    fi
    RAW_LEVEL=UNKNOWN
    grep -Eqi '(^|[|[:space:]])hi([[:space:]]|$)' <<<"$RAW" && RAW_LEVEL=HIGH
    grep -Eqi '(^|[|[:space:]])lo([[:space:]]|$)' <<<"$RAW" && RAW_LEVEL=LOW
    if [[ "$RAW_LEVEL" == UNKNOWN ]]; then
        echo "Could not determine raw GPIO$EXISTING_GPIO_INPUT state: $RAW" >&2
        echo "Refusing to stop/update the active UPS monitor." >&2
        exit 5
    fi
    if [[ "$RAW_LEVEL" == "${EXISTING_POWER_FAIL_LEVEL^^}" ]]; then
        echo "GPIO$EXISTING_GPIO_INPUT currently reads $RAW_LEVEL (configured failure state)." >&2
        echo "Refusing to stop/update the active UPS monitor during a possible outage." >&2
        exit 5
    fi
fi

install_deps=()
python3 -c 'import gpiozero' >/dev/null 2>&1 || install_deps+=(python3-gpiozero)
command -v gpioinfo >/dev/null 2>&1 || install_deps+=(gpiod)
command -v logrotate >/dev/null 2>&1 || install_deps+=(logrotate)
if ((${#install_deps[@]})); then
    echo "Installing required OS packages: ${install_deps[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${install_deps[@]}"
fi

# Stop our own previous version cleanly before replacing files.
systemctl stop ups-shutdown.service 2>/dev/null || true

install -d -m 0755 /var/lib/ups-shutdown
install -d -m 0755 /usr/local/share/doc/ups-shutdown
install -m 0755 "$PAYLOAD/ups-shutdown.py" /usr/local/sbin/ups-shutdown.py
install -m 0755 "$PAYLOAD/ups-shutdown-status" /usr/local/sbin/ups-shutdown-status
install -m 0755 "$PAYLOAD/ups-shutdown-host-setup" /usr/local/sbin/ups-shutdown-host-setup
install -m 0755 "$PAYLOAD/ups-shutdown-smoke-test" /usr/local/sbin/ups-shutdown-smoke-test
install -m 0644 "$PAYLOAD/ups-shutdown.service" /etc/systemd/system/ups-shutdown.service
install -m 0644 "$PAYLOAD/ups-shutdown-clean-marker.service" /etc/systemd/system/ups-shutdown-clean-marker.service
install -m 0644 "$PAYLOAD/ups-shutdown.logrotate" /etc/logrotate.d/ups-shutdown

if [[ ! -e /etc/default/ups-shutdown ]]; then
    install -m 0644 "$PAYLOAD/ups-shutdown.default" /etc/default/ups-shutdown
    echo "Installed default configuration: /etc/default/ups-shutdown"
else
    echo "Preserving existing configuration: /etc/default/ups-shutdown"
fi

if [[ -f "$ROOT/README.md" ]]; then
    install -m 0644 "$ROOT/README.md" /usr/local/share/doc/ups-shutdown/README.md
fi

python3 -m py_compile /usr/local/sbin/ups-shutdown.py
/usr/local/sbin/ups-shutdown.py --self-test

# The configured input must be free before the new service is allowed to claim it.
# shellcheck disable=SC1091
source /etc/default/ups-shutdown
GPIO_INPUT=${GPIO_INPUT:-12}
if command -v gpioinfo >/dev/null 2>&1; then
    INPUT_LINES=$(gpioinfo 2>/dev/null | grep "\"GPIO${GPIO_INPUT}\"" || true)
    if grep -Fq "[used" <<<"$INPUT_LINES"; then
        echo "ERROR: GPIO$GPIO_INPUT is already owned before ups-shutdown is started:" >&2
        echo "$INPUT_LINES" >&2
        echo "Identify/remove that owner before continuing." >&2
        exit 6
    fi
fi

set +e
if (( REPLACE_OVERLAY == 1 )); then
    /usr/local/sbin/ups-shutdown-host-setup --replace-existing
else
    /usr/local/sbin/ups-shutdown-host-setup --apply
fi
OVERLAY_RC=$?
set -e
if [[ $OVERLAY_RC -ne 0 && $OVERLAY_RC -ne 10 ]]; then
    echo "Host gpio-poweroff setup failed (rc=$OVERLAY_RC)." >&2
    exit "$OVERLAY_RC"
fi

echo "Dedicated UPS history retention installed: /etc/logrotate.d/ups-shutdown"

systemctl daemon-reload
systemctl enable ups-shutdown.service
systemctl enable ups-shutdown-clean-marker.service

if (( OVERLAY_RC == 10 )); then
    echo
    echo "GPIO26 boot configuration was installed/changed, but is not live yet."
    echo "ups-shutdown.service has been ENABLED but will not be started until after reboot."
    echo "Reboot, then run: sudo ups-shutdown-smoke-test --preflight"
else
    systemctl start ups-shutdown.service
    sleep 2
    if ! systemctl is-active --quiet ups-shutdown.service; then
        echo "ups-shutdown.service failed to start:" >&2
        systemctl --no-pager --full status ups-shutdown.service >&2 || true
        journalctl -u ups-shutdown.service -n 50 --no-pager >&2 || true
        exit 7
    fi

    INPUT_LINES=$(gpioinfo 2>/dev/null | grep "\"GPIO${GPIO_INPUT}\"" || true)
    if ! grep -Fq "[used" <<<"$INPUT_LINES"; then
        echo "ERROR: service is running but GPIO$GPIO_INPUT does not appear claimed:" >&2
        echo "$INPUT_LINES" >&2
        exit 8
    fi
    echo "GPIO$GPIO_INPUT ownership transferred to the new monitor:"
    echo "$INPUT_LINES"
fi

if (( SKIP_DESKTOP == 0 )); then
    TARGET_USER=${SUDO_USER:-}
    if [[ -n "$TARGET_USER" && "$TARGET_USER" != root ]]; then
        USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
        if [[ -n "$USER_HOME" ]]; then
            DESKTOP="$USER_HOME/Desktop"
            if [[ -d "$DESKTOP" ]]; then
                REF="$DESKTOP/UPS Shutdown"
                mkdir -p "$REF"
                cat > "$REF/README.txt" <<'DESK'
UPS Shutdown
============

Status:
  sudo ups-shutdown-status

Configuration:
  /etc/default/ups-shutdown

Logs:
  sudo journalctl -u ups-shutdown.service
  /var/lib/ups-shutdown/history.log

Pre-production check:
  sudo ups-shutdown-smoke-test --preflight

Host GPIO26 setup/check:
  sudo ups-shutdown-host-setup --check
DESK
                ln -sfn /etc/default/ups-shutdown "$REF/config"
                ln -sfn /var/lib/ups-shutdown "$REF/state-and-history"
                ln -sfn /etc/systemd/system/ups-shutdown.service "$REF/systemd-service"
                GROUP=$(id -gn "$TARGET_USER")
                chown "$TARGET_USER:$GROUP" "$REF" "$REF/README.txt" || true
                chown -h "$TARGET_USER:$GROUP" "$REF/config" "$REF/state-and-history" "$REF/systemd-service" || true
                echo "Desktop reference created: $REF"
            fi
        fi
    fi
fi

echo
echo "Installation complete."
if (( OVERLAY_RC != 10 )); then
    /usr/local/sbin/ups-shutdown-status || true
    echo
    echo "Next: sudo ups-shutdown-smoke-test --preflight"
fi
