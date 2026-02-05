#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sudo ./scripts/install_pi.sh [options]

Modes:
  --install                 Install (default)
  --update                  Update install in place
  --uninstall               Remove systemd units (preserve data)
  --purge                   With --uninstall, also remove /opt and /etc files

Pinmap selection (one of):
  --board-name NAME         Export pinmap for board
  --board-address ADDR      Export pinmap for board by address
  --child-name NAME         Export pinmap for bridge child
  --child-address ADDR      Export pinmap for bridge child by downstream address
  --bridge-name NAME        Disambiguate bridge child selection
  --bridge-address ADDR     Disambiguate bridge child selection
  --pinmap-src PATH         Copy an existing pinmap JSON instead of generating

Config overrides:
  --serial PATH             Modbus serial device (default: /dev/ttyUSB0)
  --baud BAUD               Modbus baud (default: 250000)
  --parity N|E|O            Modbus parity (default: N)
  --data-bits N             Serial data bits (default: 8)
  --stop-bits N             Serial stop bits (default: 1)
  --slave-address ADDR      Override Modbus slave address
  --socket-path PATH        IPC socket path (default: /run/ogm_pi.sock)
  --custom-types-dir PATH   Custom pin handler dir (default: <target-dir>/custom_types)
  --gpio-chip PATH          GPIO chip path (default: /dev/gpiochip0)
  --no-modbus               Disable Modbus backend
  --no-gpio                 Disable GPIO access
  --pin-poll-ms MS          Pin poll interval (default: 20)
  --stats-interval SEC      Board stats interval (default: 5.0)
  --log-level LEVEL         Logging level (default: INFO)

Install behavior:
  --target-dir PATH         Install path (default: /opt/OGM_slave_pi)
  --config-dir PATH         Config dir (default: /etc/ogm_pi)
  --no-delete               Do not delete extra files during rsync (default)
  --delete                  Enable rsync --delete
  --offline                 Skip apt and pip installs
  --skip-apt                Skip apt installs
  --skip-pip                Skip pip installs
  --skip-systemd            Do not enable/start systemd units
  --write-config            Force overwrite of ogm_pi.yaml (backs up existing)
  --write-pinmap            Force overwrite of pinmap.json (backs up existing)

USAGE
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install_pi.sh must be run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="/opt/OGM_slave_pi"
CONFIG_DIR="/etc/ogm_pi"
CONFIG_FILE="${CONFIG_DIR}/ogm_pi.yaml"
PINMAP_FILE="${CONFIG_DIR}/pinmap.json"
MODE="install"

BOARD_NAME=""
BOARD_ADDRESS=""
CHILD_NAME=""
CHILD_ADDRESS=""
BRIDGE_NAME=""
BRIDGE_ADDRESS=""
PINMAP_SRC=""

SERIAL="/dev/ttyUSB0"
BAUD="250000"
PARITY="N"
DATA_BITS="8"
STOP_BITS="1"
SLAVE_ADDRESS=""
SOCKET_PATH="/run/ogm_pi.sock"
GPIO_CHIP="/dev/gpiochip0"
CUSTOM_TYPES_DIR=""
NO_MODBUS="false"
NO_GPIO="false"
PIN_POLL_MS="20"
STATS_INTERVAL="5.0"
LOG_LEVEL="INFO"

SKIP_APT="false"
SKIP_PIP="false"
SKIP_SYSTEMD="false"
RSYNC_DELETE="false"
WRITE_CONFIG="false"
WRITE_PINMAP="false"
PURGE="false"

CONFIG_OVERRIDES="false"
PINMAP_REQUESTED="false"
CUSTOM_TYPES_OVERRIDE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) MODE="install"; shift ;;
    --update) MODE="update"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --purge) PURGE="true"; shift ;;

    --board-name) BOARD_NAME="$2"; PINMAP_REQUESTED="true"; shift 2 ;;
    --board-address) BOARD_ADDRESS="$2"; PINMAP_REQUESTED="true"; shift 2 ;;
    --child-name) CHILD_NAME="$2"; PINMAP_REQUESTED="true"; shift 2 ;;
    --child-address) CHILD_ADDRESS="$2"; PINMAP_REQUESTED="true"; shift 2 ;;
    --bridge-name) BRIDGE_NAME="$2"; shift 2 ;;
    --bridge-address) BRIDGE_ADDRESS="$2"; shift 2 ;;
    --pinmap-src) PINMAP_SRC="$2"; PINMAP_REQUESTED="true"; shift 2 ;;

    --serial) SERIAL="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --baud) BAUD="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --parity) PARITY="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --data-bits) DATA_BITS="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --stop-bits) STOP_BITS="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --slave-address) SLAVE_ADDRESS="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --socket-path) SOCKET_PATH="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --custom-types-dir) CUSTOM_TYPES_DIR="$2"; CUSTOM_TYPES_OVERRIDE="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --gpio-chip) GPIO_CHIP="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --no-modbus) NO_MODBUS="true"; CONFIG_OVERRIDES="true"; shift ;;
    --no-gpio) NO_GPIO="true"; CONFIG_OVERRIDES="true"; shift ;;
    --pin-poll-ms) PIN_POLL_MS="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --stats-interval) STATS_INTERVAL="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --log-level) LOG_LEVEL="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;

    --target-dir) TARGET_DIR="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; CONFIG_FILE="${CONFIG_DIR}/ogm_pi.yaml"; PINMAP_FILE="${CONFIG_DIR}/pinmap.json"; shift 2 ;;
    --no-delete) RSYNC_DELETE="false"; shift ;;
    --delete) RSYNC_DELETE="true"; shift ;;
    --offline) SKIP_APT="true"; SKIP_PIP="true"; shift ;;
    --skip-apt) SKIP_APT="true"; shift ;;
    --skip-pip) SKIP_PIP="true"; shift ;;
    --skip-systemd) SKIP_SYSTEMD="true"; shift ;;
    --write-config) WRITE_CONFIG="true"; shift ;;
    --write-pinmap) WRITE_PINMAP="true"; shift ;;

    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
 done

if [[ "$PURGE" == "true" && "$MODE" != "uninstall" ]]; then
  echo "--purge must be used with --uninstall" >&2
  exit 1
fi

pinmap_modes=0
if [[ -n "$PINMAP_SRC" ]]; then
  pinmap_modes=$((pinmap_modes + 1))
fi
if [[ -n "$BOARD_NAME" || -n "$BOARD_ADDRESS" ]]; then
  pinmap_modes=$((pinmap_modes + 1))
fi
if [[ -n "$CHILD_NAME" || -n "$CHILD_ADDRESS" ]]; then
  pinmap_modes=$((pinmap_modes + 1))
fi
if [[ "$pinmap_modes" -gt 1 ]]; then
  echo "Select only one pinmap source (board, child, or --pinmap-src)" >&2
  exit 1
fi

CONFIG_FILE="${CONFIG_DIR}/ogm_pi.yaml"
PINMAP_FILE="${CONFIG_DIR}/pinmap.json"
if [[ "$CUSTOM_TYPES_OVERRIDE" != "true" ]]; then
  CUSTOM_TYPES_DIR="${TARGET_DIR}/custom_types"
fi

ensure_group_user() {
  getent group ogm >/dev/null || groupadd ogm
  if ! id -u ogm_pi >/dev/null 2>&1; then
    useradd -r -g ogm -d /nonexistent -s /usr/sbin/nologin ogm_pi
  fi
  usermod -a -G gpio,dialout ogm_pi
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    cp "$path" "${path}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

escape_sed() {
  printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'
}

install_units() {
  local target_esc
  local config_esc
  local socket_esc

  target_esc="$(escape_sed "$TARGET_DIR")"
  config_esc="$(escape_sed "$CONFIG_FILE")"
  socket_esc="$(escape_sed "$SOCKET_PATH")"

  if [[ "$SOCKET_PATH" == /* ]]; then
    mkdir -p "$(dirname "$SOCKET_PATH")"
  fi

  sed \
    -e "s|/opt/OGM_slave_pi|${target_esc}|g" \
    -e "s|/etc/ogm_pi/ogm_pi.yaml|${config_esc}|g" \
    "$TARGET_DIR/systemd/ogm_pi.service" > /etc/systemd/system/ogm_pi.service

  sed \
    -e "s|/run/ogm_pi.sock|${socket_esc}|g" \
    "$TARGET_DIR/systemd/ogm_pi.socket" > /etc/systemd/system/ogm_pi.socket
}

write_config() {
  local slave_line=""
  if [[ -n "$SLAVE_ADDRESS" ]]; then
    slave_line="$SLAVE_ADDRESS"
  else
    slave_line="null"
  fi
  cat > "$CONFIG_FILE" <<EOF
# Auto-generated by install_pi.sh
pinmap: ${PINMAP_FILE}
serial: ${SERIAL}
baud: ${BAUD}
parity: ${PARITY}
data_bits: ${DATA_BITS}
stop_bits: ${STOP_BITS}
slave_address: ${slave_line}
socket_path: ${SOCKET_PATH}
custom_types_dir: ${CUSTOM_TYPES_DIR}
no_modbus: ${NO_MODBUS}
no_gpio: ${NO_GPIO}
gpio_chip: ${GPIO_CHIP}
pin_poll_ms: ${PIN_POLL_MS}
stats_interval: ${STATS_INTERVAL}
log_level: ${LOG_LEVEL}
EOF
}

validate_devices() {
  if [[ "$NO_MODBUS" != "true" ]]; then
    if [[ ! -e "$SERIAL" ]]; then
      echo "Warning: serial device $SERIAL does not exist" >&2
    fi
  fi
  if [[ "$NO_GPIO" != "true" ]]; then
    if [[ ! -e "$GPIO_CHIP" ]]; then
      echo "Warning: gpio chip $GPIO_CHIP does not exist" >&2
    fi
  fi
}

generate_pinmap() {
  if [[ -n "$PINMAP_SRC" ]]; then
    backup_file "$PINMAP_FILE"
    cp "$PINMAP_SRC" "$PINMAP_FILE"
    return
  fi

  if [[ "$PINMAP_REQUESTED" != "true" ]]; then
    if [[ ! -f "$PINMAP_FILE" ]]; then
      echo "Pinmap missing; pass --board-name/--board-address or --child-name/--child-address or --pinmap-src" >&2
      exit 1
    fi
    return
  fi

  local python_bin="${TARGET_DIR}/.venv/bin/python"
  if [[ ! -x "$python_bin" ]]; then
    python_bin="/usr/bin/python3"
  fi

  backup_file "$PINMAP_FILE"

  local cmd=("$python_bin" "${TARGET_DIR}/scripts/export_pinmap.py" --output "$PINMAP_FILE")
  if [[ -n "$BOARD_NAME" ]]; then cmd+=(--name "$BOARD_NAME"); fi
  if [[ -n "$BOARD_ADDRESS" ]]; then cmd+=(--address "$BOARD_ADDRESS"); fi
  if [[ -n "$CHILD_NAME" ]]; then cmd+=(--child-name "$CHILD_NAME"); fi
  if [[ -n "$CHILD_ADDRESS" ]]; then cmd+=(--child-address "$CHILD_ADDRESS"); fi
  if [[ -n "$BRIDGE_NAME" ]]; then cmd+=(--bridge-name "$BRIDGE_NAME"); fi
  if [[ -n "$BRIDGE_ADDRESS" ]]; then cmd+=(--bridge-address "$BRIDGE_ADDRESS"); fi

  "${cmd[@]}"
}

setup_systemd_override() {
  if [[ "$SKIP_SYSTEMD" == "true" ]]; then
    return
  fi
  local override_dir="/etc/systemd/system/ogm_pi.service.d"
  mkdir -p "$override_dir"
  cat > "${override_dir}/override.conf" <<EOF
[Service]
DevicePolicy=closed
EOF
  if [[ "$NO_MODBUS" != "true" ]]; then
    echo "DeviceAllow=${SERIAL} rwm" >> "${override_dir}/override.conf"
  fi
  if [[ "$NO_GPIO" != "true" ]]; then
    echo "DeviceAllow=${GPIO_CHIP} rwm" >> "${override_dir}/override.conf"
  fi
}

systemd_reload_restart() {
  if [[ "$SKIP_SYSTEMD" == "true" ]]; then
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; skipping systemd configuration" >&2
    return
  fi

  systemctl daemon-reload
  systemctl enable --now ogm_pi.socket
  systemctl restart ogm_pi.socket
  systemctl restart ogm_pi.service
}

stop_service_if_active() {
  if [[ "$SKIP_SYSTEMD" == "true" ]]; then
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi
  if systemctl is-active --quiet ogm_pi.service; then
    systemctl stop ogm_pi.service
  fi
  if systemctl is-active --quiet ogm_pi.socket; then
    systemctl stop ogm_pi.socket
  fi
}

uninstall_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; skipping service removal" >&2
    return
  fi
  systemctl disable --now ogm_pi.service ogm_pi.socket || true
  rm -f /etc/systemd/system/ogm_pi.service
  rm -f /etc/systemd/system/ogm_pi.socket
  rm -rf /etc/systemd/system/ogm_pi.service.d
  systemctl daemon-reload
}

if [[ "$MODE" == "uninstall" ]]; then
  uninstall_service
  if [[ "$PURGE" == "true" ]]; then
    rm -rf "$TARGET_DIR" "$CONFIG_DIR"
  fi
  echo "Uninstalled ogm_pi systemd units."
  exit 0
fi

if [[ "$SKIP_APT" != "true" ]]; then
  apt-get update
  apt-get install -y \
    libmodbus \
    libmodbus-dev \
    python3 \
    python3-venv \
    python3-libgpiod
fi

ensure_group_user

stop_service_if_active

mkdir -p "$TARGET_DIR"
if command -v rsync >/dev/null 2>&1; then
  if [[ "$RSYNC_DELETE" == "true" ]]; then
    rsync -a --delete --exclude '.git' "$ROOT_DIR/" "$TARGET_DIR/"
  else
    rsync -a --exclude '.git' "$ROOT_DIR/" "$TARGET_DIR/"
  fi
else
  if [[ "$RSYNC_DELETE" == "true" ]]; then
    echo "Warning: rsync not found; --delete ignored" >&2
  fi
  cp -a "$ROOT_DIR/." "$TARGET_DIR/"
fi
mkdir -p "$CUSTOM_TYPES_DIR"

if [[ "$SKIP_PIP" != "true" ]]; then
  if [[ ! -d "${TARGET_DIR}/.venv" ]]; then
    python3 -m venv "${TARGET_DIR}/.venv"
  fi
  "${TARGET_DIR}/.venv/bin/pip" install --upgrade pip
  "${TARGET_DIR}/.venv/bin/pip" install -r "${TARGET_DIR}/requirements.txt"
fi

mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

if [[ "$WRITE_CONFIG" == "true" || ! -f "$CONFIG_FILE" || "$CONFIG_OVERRIDES" == "true" ]]; then
  backup_file "$CONFIG_FILE"
  write_config
fi

if [[ "$WRITE_PINMAP" == "true" || "$PINMAP_REQUESTED" == "true" ]]; then
  generate_pinmap
fi

chown -R ogm_pi:ogm "$TARGET_DIR"
if [[ -d "$CUSTOM_TYPES_DIR" ]]; then
  chown -R ogm_pi:ogm "$CUSTOM_TYPES_DIR"
fi
if [[ -f "$CONFIG_FILE" ]]; then
  chown ogm_pi:ogm "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
fi
if [[ -f "$PINMAP_FILE" ]]; then
  chown ogm_pi:ogm "$PINMAP_FILE"
  chmod 0640 "$PINMAP_FILE"
fi

if [[ "$SKIP_SYSTEMD" != "true" ]]; then
  install_units
  setup_systemd_override
fi

validate_devices
systemd_reload_restart

echo "Installed OGM_slave_pi to ${TARGET_DIR}"
echo "Config: ${CONFIG_FILE}"
echo "Pinmap: ${PINMAP_FILE}"
echo "Next: edit config/pinmap as needed, then run 'systemctl status ogm_pi.service'"
