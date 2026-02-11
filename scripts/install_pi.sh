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
  --serial PATH             Modbus serial device (base default: /dev/ttyUSB0; default profile uses /dev/serial0)
  --baud BAUD               Modbus baud (default: 250000)
  --parity N|E|O            Modbus parity (default: N)
  --data-bits N             Serial data bits (default: 8)
  --stop-bits N             Serial stop bits (default: 1)
  --slave-address ADDR      Override Modbus slave address
  --socket-path PATH        IPC socket path (default: /run/ogm_pi.sock)
  --custom-types-dir PATH   Custom pin handler dir (default: <target-dir>/custom_types)
  --apps-dir PATH           Child app payload dir (default: <target-dir>/apps)
  --gpio-chip PATH          GPIO chip path (default: /dev/gpiochip0)
  --default-install-config  Use default GPIO14/15 RS485 config (serial0 + uart-fix)
  --no-default-install-config
                            Skip default GPIO14/15 RS485 config prompt
  --uart-fix                Apply UART compatibility fixes/checks (default)
  --no-uart-fix             Only report UART status, do not modify boot/console UART settings
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
  --write-apps              Force overwrite/sync of existing apps dir content
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
SHUTDOWN_HELPER_PATH="/usr/local/sbin/ogm_pi_shutdown"
SUDOERS_SHUTDOWN_FILE="/etc/sudoers.d/ogm_pi_shutdown"
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
APPS_DIR=""
NO_MODBUS="false"
NO_GPIO="false"
PIN_POLL_MS="20"
STATS_INTERVAL="5.0"
LOG_LEVEL="INFO"
DEFAULT_INSTALL_CONFIG="auto"
UART_FIX="true"

SKIP_APT="false"
SKIP_PIP="false"
SKIP_SYSTEMD="false"
RSYNC_DELETE="false"
WRITE_CONFIG="false"
WRITE_APPS="false"
WRITE_PINMAP="false"
PURGE="false"

CONFIG_OVERRIDES="false"
PINMAP_REQUESTED="false"
CUSTOM_TYPES_OVERRIDE="false"
APPS_DIR_OVERRIDE="false"
SERIAL_SET="false"
BAUD_SET="false"
PARITY_SET="false"
DATA_BITS_SET="false"
STOP_BITS_SET="false"
UART_REBOOT_REQUIRED="false"
UART_FIX_APPLIED="false"
CONFIG_ACCESS_USER=""

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

    --serial) SERIAL="$2"; SERIAL_SET="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --baud) BAUD="$2"; BAUD_SET="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --parity) PARITY="$2"; PARITY_SET="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --data-bits) DATA_BITS="$2"; DATA_BITS_SET="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --stop-bits) STOP_BITS="$2"; STOP_BITS_SET="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --slave-address) SLAVE_ADDRESS="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --socket-path) SOCKET_PATH="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --custom-types-dir) CUSTOM_TYPES_DIR="$2"; CUSTOM_TYPES_OVERRIDE="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --apps-dir) APPS_DIR="$2"; APPS_DIR_OVERRIDE="true"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --gpio-chip) GPIO_CHIP="$2"; CONFIG_OVERRIDES="true"; shift 2 ;;
    --default-install-config) DEFAULT_INSTALL_CONFIG="yes"; shift ;;
    --no-default-install-config) DEFAULT_INSTALL_CONFIG="no"; shift ;;
    --uart-fix) UART_FIX="true"; shift ;;
    --no-uart-fix) UART_FIX="false"; shift ;;
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
    --write-apps) WRITE_APPS="true"; shift ;;
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
if [[ "$APPS_DIR_OVERRIDE" != "true" ]]; then
  APPS_DIR="${TARGET_DIR}/apps"
fi
if [[ -n "${OGM_CONFIG_USER:-}" ]]; then
  CONFIG_ACCESS_USER="${OGM_CONFIG_USER}"
elif [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  CONFIG_ACCESS_USER="${SUDO_USER}"
fi
if [[ -n "$CONFIG_ACCESS_USER" ]]; then
  if ! id -u "$CONFIG_ACCESS_USER" >/dev/null 2>&1; then
    echo "Warning: requested config access user '$CONFIG_ACCESS_USER' does not exist; skipping user ACL grants." >&2
    CONFIG_ACCESS_USER=""
  fi
fi

is_soc_uart_path() {
  local dev="$1"
  case "$dev" in
    /dev/serial[0-9]*|/dev/ttyAMA*|/dev/ttyS*) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_boot_config_path() {
  if [[ -f /boot/firmware/config.txt ]]; then
    echo "/boot/firmware/config.txt"
    return
  fi
  if [[ -f /boot/config.txt ]]; then
    echo "/boot/config.txt"
    return
  fi
  echo ""
}

resolve_cmdline_path() {
  if [[ -f /boot/firmware/cmdline.txt ]]; then
    echo "/boot/firmware/cmdline.txt"
    return
  fi
  if [[ -f /boot/cmdline.txt ]]; then
    echo "/boot/cmdline.txt"
    return
  fi
  echo ""
}

ensure_boot_key_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  [[ -f "$file" ]] || return
  local key_re="${key//./\\.}"
  if grep -Eq "^[[:space:]]*${key_re}[[:space:]]*=" "$file"; then
    if ! grep -Eq "^[[:space:]]*${key_re}[[:space:]]*=[[:space:]]*${value}[[:space:]]*$" "$file"; then
      backup_file "$file"
      sed -i -E "s|^[[:space:]]*${key_re}[[:space:]]*=.*$|${key}=${value}|" "$file"
      UART_REBOOT_REQUIRED="true"
      UART_FIX_APPLIED="true"
      echo "Updated ${key}=${value} in ${file}"
    fi
  else
    backup_file "$file"
    printf "\n%s=%s\n" "$key" "$value" >> "$file"
    UART_REBOOT_REQUIRED="true"
    UART_FIX_APPLIED="true"
    echo "Added ${key}=${value} to ${file}"
  fi
}

ensure_disable_bt_overlay() {
  local file="$1"
  [[ -f "$file" ]] || return
  if grep -Eq "^[[:space:]]*dtoverlay[[:space:]]*=[[:space:]]*disable-bt[[:space:]]*$" "$file"; then
    return
  fi
  backup_file "$file"
  if grep -Eq "^[[:space:]]*dtoverlay[[:space:]]*=[[:space:]]*miniuart-bt[[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*dtoverlay[[:space:]]*=[[:space:]]*miniuart-bt[[:space:]]*$|dtoverlay=disable-bt|" "$file"
    echo "Replaced dtoverlay=miniuart-bt with dtoverlay=disable-bt in ${file}"
  else
    printf "\ndtoverlay=disable-bt\n" >> "$file"
    echo "Added dtoverlay=disable-bt to ${file}"
  fi
  UART_REBOOT_REQUIRED="true"
  UART_FIX_APPLIED="true"
}

remove_serial_console_tokens() {
  local file="$1"
  [[ -f "$file" ]] || return
  local before after
  before="$(cat "$file")"
  after="$(printf '%s\n' "$before" \
    | sed -E 's/(^| )console=(serial0|ttyAMA[0-9]+|ttyS[0-9]+)(,[^ ]*)?//g; s/[[:space:]]+/ /g; s/^ //; s/ $//')"
  if [[ "$after" != "$before" ]]; then
    backup_file "$file"
    printf '%s\n' "$after" > "$file"
    UART_REBOOT_REQUIRED="true"
    UART_FIX_APPLIED="true"
    echo "Removed serial console entries from ${file}"
  fi
}

disable_service_if_enabled() {
  local svc="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi
  if systemctl is-enabled --quiet "$svc" 2>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    UART_FIX_APPLIED="true"
    echo "Disabled ${svc}"
  fi
}

choose_default_install_config() {
  if [[ "$DEFAULT_INSTALL_CONFIG" == "auto" ]]; then
    if [[ -t 0 ]]; then
      local reply
      read -r -p "Use default install config for GPIO14/15 RS485 (recommended) [Y/n]: " reply
      case "${reply,,}" in
        ""|y|yes) DEFAULT_INSTALL_CONFIG="yes" ;;
        n|no) DEFAULT_INSTALL_CONFIG="no" ;;
        *) echo "Invalid response '${reply}', using default: yes"; DEFAULT_INSTALL_CONFIG="yes" ;;
      esac
    else
      DEFAULT_INSTALL_CONFIG="yes"
    fi
  fi

  if [[ "$DEFAULT_INSTALL_CONFIG" == "yes" ]]; then
    echo "Applying default install config for GPIO14/15 RS485."
    if [[ "$SERIAL_SET" != "true" ]]; then SERIAL="/dev/serial0"; fi
    if [[ "$BAUD_SET" != "true" ]]; then BAUD="250000"; fi
    if [[ "$PARITY_SET" != "true" ]]; then PARITY="N"; fi
    if [[ "$DATA_BITS_SET" != "true" ]]; then DATA_BITS="8"; fi
    if [[ "$STOP_BITS_SET" != "true" ]]; then STOP_BITS="1"; fi
  else
    echo "Skipping default install config."
  fi
}

uart_preflight() {
  if [[ "$NO_MODBUS" == "true" ]]; then
    echo "UART preflight skipped (Modbus disabled)."
    return
  fi

  if ! is_soc_uart_path "$SERIAL"; then
    echo "UART preflight skipped for non-SoC serial path: ${SERIAL}"
    return
  fi

  local serial_target serial0_target boot_cfg cmdline_cfg getty_active cmdline_console parity_upper dedicate_serial0
  serial_target="$(readlink -f "$SERIAL" 2>/dev/null || true)"
  if [[ -z "$serial_target" ]]; then
    serial_target="$SERIAL"
  fi
  serial0_target="$(readlink -f /dev/serial0 2>/dev/null || true)"
  boot_cfg="$(resolve_boot_config_path)"
  cmdline_cfg="$(resolve_cmdline_path)"
  parity_upper="${PARITY^^}"
  getty_active="no"
  cmdline_console="no"
  dedicate_serial0="yes"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled --quiet serial-getty@serial0.service 2>/dev/null \
      || systemctl is-active --quiet serial-getty@serial0.service 2>/dev/null; then
      getty_active="yes"
    fi
  fi

  if [[ -n "$cmdline_cfg" ]] && grep -Eq '(^| )console=(serial0|ttyAMA[0-9]+|ttyS[0-9]+)' "$cmdline_cfg"; then
    cmdline_console="yes"
  fi

  echo "UART preflight report:"
  echo "  serial config: ${SERIAL} (resolved: ${serial_target})"
  if [[ -n "$serial0_target" ]]; then
    echo "  /dev/serial0 -> ${serial0_target}"
  fi
  if [[ -n "$boot_cfg" ]]; then
    echo "  boot config: ${boot_cfg}"
  else
    echo "  boot config: not found"
  fi
  if [[ -n "$cmdline_cfg" ]]; then
    echo "  cmdline: ${cmdline_cfg} (serial console present: ${cmdline_console})"
  else
    echo "  cmdline: not found"
  fi
  echo "  serial-getty@serial0 active/enabled: ${getty_active}"

  if [[ "$UART_FIX" == "true" ]]; then
    if [[ -t 0 ]]; then
      local reply
      read -r -p "Disable Bluetooth and dedicate serial0 to GPIO14/15 (recommended) [Y/n]: " reply
      case "${reply,,}" in
        ""|y|yes) dedicate_serial0="yes" ;;
        n|no) dedicate_serial0="no" ;;
        *) echo "Invalid response '${reply}', using default: yes"; dedicate_serial0="yes" ;;
      esac
    fi

    echo "Applying UART compatibility fixes (--uart-fix enabled)..."
    if command -v raspi-config >/dev/null 2>&1; then
      raspi-config nonint do_serial_cons 1 || true
      raspi-config nonint do_serial_hw 0 || true
    else
      echo "Warning: raspi-config not found; applying file/service based fixes only."
    fi

    if [[ -n "$boot_cfg" ]]; then
      ensure_boot_key_value "$boot_cfg" "enable_uart" "1"
      if [[ "$dedicate_serial0" == "yes" ]]; then
        ensure_disable_bt_overlay "$boot_cfg"
      else
        echo "Leaving Bluetooth UART overlay unchanged in ${boot_cfg}."
      fi
    fi
    if [[ -n "$cmdline_cfg" ]]; then
      remove_serial_console_tokens "$cmdline_cfg"
    fi
    disable_service_if_enabled "serial-getty@serial0.service"
    disable_service_if_enabled "serial-getty@ttyAMA0.service"
    disable_service_if_enabled "serial-getty@ttyS0.service"
    if [[ "$dedicate_serial0" == "yes" ]]; then
      disable_service_if_enabled "hciuart.service"
    fi

    serial_target="$(readlink -f "$SERIAL" 2>/dev/null || true)"
    if [[ -z "$serial_target" ]]; then
      serial_target="$SERIAL"
    fi
  fi

  if [[ "$serial_target" =~ ^/dev/ttyS[0-9]+$ ]]; then
    echo "Warning: ${SERIAL} currently resolves to mini UART (${serial_target})."
    if [[ "$UART_FIX" == "true" && "$dedicate_serial0" == "yes" ]]; then
      echo "Note: this can persist until reboot after applying GPIO14/15 serial0 routing changes."
    fi
    if [[ "$UART_FIX" == "true" && "$dedicate_serial0" == "no" ]]; then
      echo "Note: Bluetooth UART was kept enabled by choice; serial0 may continue using mini UART."
    fi
    if [[ "$parity_upper" != "N" ]]; then
      echo "ERROR: parity '${PARITY}' requested but mini UART does not support parity. Use PL011 (ttyAMA) or parity N." >&2
      exit 1
    fi
  fi

  if [[ "$serial0_target" == "/dev/ttyAMA10" ]]; then
    echo "Warning: /dev/serial0 points at ttyAMA10 (debug UART). Confirm your Pi model UART routing before proceeding."
  fi

  if [[ "$UART_FIX_APPLIED" == "true" ]]; then
    UART_REBOOT_REQUIRED="true"
    echo "UART fix changes were applied; reboot is required."
  fi
}

ensure_group_user() {
  getent group ogm >/dev/null || groupadd ogm
  if ! id -u ogm_pi >/dev/null 2>&1; then
    useradd -r -g ogm -d /nonexistent -s /usr/sbin/nologin ogm_pi
  fi
  local groups="gpio,dialout"
  if getent group video >/dev/null 2>&1; then
    groups="${groups},video"
  fi
  if getent group render >/dev/null 2>&1; then
    groups="${groups},render"
  fi
  usermod -a -G "$groups" ogm_pi
  if [[ -n "$CONFIG_ACCESS_USER" ]]; then
    usermod -a -G ogm "$CONFIG_ACCESS_USER" >/dev/null 2>&1 || true
  fi
}

install_shutdown_privileges() {
  local shutdown_cmd=""
  if command -v shutdown >/dev/null 2>&1; then
    shutdown_cmd="$(command -v shutdown)"
  elif [[ -x /usr/sbin/shutdown ]]; then
    shutdown_cmd="/usr/sbin/shutdown"
  elif [[ -x /sbin/shutdown ]]; then
    shutdown_cmd="/sbin/shutdown"
  fi

  if [[ -z "$shutdown_cmd" ]]; then
    echo "ERROR: shutdown command not found on this system." >&2
    exit 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo not found. Install sudo or rerun without --skip-apt." >&2
    exit 1
  fi
  if ! command -v visudo >/dev/null 2>&1; then
    echo "ERROR: visudo not found. Ensure sudo is installed correctly." >&2
    exit 1
  fi

  cat > "$SHUTDOWN_HELPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec ${shutdown_cmd} now
EOF
  chown root:root "$SHUTDOWN_HELPER_PATH"
  chmod 0755 "$SHUTDOWN_HELPER_PATH"

  cat > "$SUDOERS_SHUTDOWN_FILE" <<EOF
# Managed by OGM_slave_pi install_pi.sh
ogm_pi ALL=(root) NOPASSWD: ${SHUTDOWN_HELPER_PATH}
EOF
  chown root:root "$SUDOERS_SHUTDOWN_FILE"
  chmod 0440 "$SUDOERS_SHUTDOWN_FILE"
  visudo -cf "$SUDOERS_SHUTDOWN_FILE" >/dev/null
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    cp "$path" "${path}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

prompt_yes_no() {
  local question="$1"
  local default="$2"
  local suffix reply
  case "$default" in
    yes) suffix="[Y/n]" ;;
    no) suffix="[y/N]" ;;
    *)
      echo "prompt_yes_no default must be 'yes' or 'no'" >&2
      return 1
      ;;
  esac

  while true; do
    read -r -p "${question} ${suffix}: " reply
    case "${reply,,}" in
      "")
        [[ "$default" == "yes" ]]
        return
        ;;
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

dir_has_contents() {
  local path="$1"
  [[ -d "$path" ]] || return 1
  find "$path" -mindepth 1 -maxdepth 1 -print -quit | grep -q .
}

should_write_config() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if [[ "$WRITE_CONFIG" == "true" ]]; then
    return 0
  fi
  if [[ "$CONFIG_OVERRIDES" != "true" ]]; then
    echo "Config exists at ${file}; preserving existing file."
    return 1
  fi
  if [[ -t 0 ]]; then
    if prompt_yes_no "Config exists at ${file}. Generate a new version from installer values?" "no"; then
      return 0
    fi
    echo "Keeping existing config at ${file}; override flags were not applied."
    return 1
  fi
  echo "Config exists at ${file}; preserving existing file (non-interactive). Use --write-config to overwrite."
  return 1
}

should_preserve_existing_apps_dir() {
  local dir="$1"
  if [[ "$WRITE_APPS" == "true" ]]; then
    return 1
  fi
  if ! dir_has_contents "$dir"; then
    return 1
  fi
  if [[ -t 0 ]]; then
    if prompt_yes_no "Apps dir ${dir} contains files. Preserve existing app payloads?" "yes"; then
      return 0
    fi
    return 1
  fi
  echo "Apps dir ${dir} contains files; preserving existing payloads (non-interactive). Use --write-apps to overwrite."
  return 0
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
apps_dir: ${APPS_DIR}
no_modbus: ${NO_MODBUS}
no_gpio: ${NO_GPIO}
gpio_chip: ${GPIO_CHIP}
pin_poll_ms: ${PIN_POLL_MS}
stats_interval: ${STATS_INTERVAL}
log_level: ${LOG_LEVEL}
failure_log: ${TARGET_DIR}/runtime_failures.log
crash_dump_dir: ${TARGET_DIR}/crash_dumps
modbus_log_every_failure: false
modbus_show_all_frames: false
app:
  enabled: false
  name: default
  command: ""
  cwd: ${APPS_DIR}/default
  restart_policy: always
  restart_backoff_ms: 2000
  startup_timeout_ms: 10000
  shutdown_timeout_ms: 5000
  pin_bindings: []
  gpio_bindings: []
  env: {}
EOF
}

grant_user_path_access() {
  local user="$1"
  local path="$2"
  local perms="$3"
  [[ -n "$user" ]] || return
  [[ -e "$path" ]] || return
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -m "u:${user}:${perms}" "$path" >/dev/null 2>&1 || true
  else
    case "$path" in
      /home/*) chown "$user:ogm" "$path" >/dev/null 2>&1 || true ;;
      *) ;;
    esac
  fi
}

grant_config_access_for_user() {
  local user="$1"
  [[ -n "$user" ]] || return
  grant_user_path_access "$user" "$CONFIG_DIR" "rwx"
  grant_user_path_access "$user" "$CONFIG_FILE" "rw"
  grant_user_path_access "$user" "$PINMAP_FILE" "rw"
}

apply_shared_runtime_permissions() {
  local path="$1"
  local user="$2"
  [[ -d "$path" ]] || return

  chgrp -R ogm "$path" >/dev/null 2>&1 || true
  chmod -R g+rwX "$path" >/dev/null 2>&1 || true
  find "$path" -type d -exec chmod g+s {} + >/dev/null 2>&1 || true

  if command -v setfacl >/dev/null 2>&1; then
    setfacl -R -m u:ogm_pi:rwX "$path" >/dev/null 2>&1 || true
    find "$path" -type d -exec setfacl -m d:u:ogm_pi:rwX {} + >/dev/null 2>&1 || true
    if [[ -n "$user" ]]; then
      setfacl -R -m "u:${user}:rwX" "$path" >/dev/null 2>&1 || true
      find "$path" -type d -exec setfacl -m "d:u:${user}:rwX" {} + >/dev/null 2>&1 || true
    fi
  elif [[ -n "$user" ]]; then
    usermod -a -G ogm "$user" >/dev/null 2>&1 || true
  fi
}

grant_dir_traverse() {
  local d="$1"
  [[ -d "$d" ]] || return
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:ogm_pi:rx "$d" >/dev/null 2>&1 || chmod o+rx "$d"
  else
    chmod o+rx "$d"
  fi
}

ensure_service_path_access() {
  local p
  for p in "$TARGET_DIR" "$CONFIG_DIR"; do
    case "$p" in
      /home/*) ;;
      *) continue ;;
    esac
    while [[ "$p" != "/" ]]; do
      grant_dir_traverse "$p"
      p="$(dirname "$p")"
    done
    grant_dir_traverse "/home"
  done
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

apt_has_package() {
  local pkg="$1"
  local candidate
  candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/{print $2; exit}')"
  [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

pick_first_available_pkg() {
  local pkg
  for pkg in "$@"; do
    if apt_has_package "$pkg"; then
      echo "$pkg"
      return 0
    fi
  done
  return 1
}

has_libmodbus_runtime() {
  if command -v ldconfig >/dev/null 2>&1; then
    if ldconfig -p 2>/dev/null | grep -q 'libmodbus\\.so'; then
      return 0
    fi
  fi

  local candidate
  for candidate in \
    /usr/lib/*/libmodbus.so \
    /usr/lib/*/libmodbus.so.* \
    /lib/*/libmodbus.so \
    /lib/*/libmodbus.so.*
  do
    if [[ -e "$candidate" ]]; then
      return 0
    fi
  done
  return 1
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
  local supp_groups="gpio dialout"
  if getent group video >/dev/null 2>&1; then
    supp_groups="${supp_groups} video"
  fi
  if getent group render >/dev/null 2>&1; then
    supp_groups="${supp_groups} render"
  fi
  local override_dir="/etc/systemd/system/ogm_pi.service.d"
  mkdir -p "$override_dir"
  cat > "${override_dir}/override.conf" <<EOF
[Service]
DevicePolicy=closed
SupplementaryGroups=${supp_groups}
EOF
  if [[ "$NO_MODBUS" != "true" ]]; then
    echo "DeviceAllow=${SERIAL} rwm" >> "${override_dir}/override.conf"
  fi
  if [[ "$NO_GPIO" != "true" ]]; then
    echo "DeviceAllow=${GPIO_CHIP} rwm" >> "${override_dir}/override.conf"
  fi
  if [[ -e /dev/dri/card0 ]]; then
    echo "DeviceAllow=/dev/dri/card0 rwm" >> "${override_dir}/override.conf"
  fi
  if [[ -e /dev/dri/renderD128 ]]; then
    echo "DeviceAllow=/dev/dri/renderD128 rwm" >> "${override_dir}/override.conf"
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
  if [[ "$UART_REBOOT_REQUIRED" == "true" ]]; then
    systemctl enable ogm_pi.socket ogm_pi.service
    echo "Skipping ogm_pi start/restart until reboot (UART settings changed)."
    return
  fi
  systemctl enable --now ogm_pi.socket ogm_pi.service
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
  else
    systemctl disable --now ogm_pi.service ogm_pi.socket || true
    rm -f /etc/systemd/system/ogm_pi.service
    rm -f /etc/systemd/system/ogm_pi.socket
    rm -rf /etc/systemd/system/ogm_pi.service.d
    systemctl daemon-reload
  fi
  rm -f "$SUDOERS_SHUTDOWN_FILE"
  rm -f "$SHUTDOWN_HELPER_PATH"
}

if [[ "$MODE" == "uninstall" ]]; then
  uninstall_service
  if [[ "$PURGE" == "true" ]]; then
    rm -rf "$TARGET_DIR" "$CONFIG_DIR"
  fi
  echo "Uninstalled ogm_pi systemd units and shutdown privilege helper."
  exit 0
fi

choose_default_install_config
uart_preflight

if [[ "$SKIP_APT" != "true" ]]; then
  apt-get update
  MODBUS_RUNTIME_PKG="$(pick_first_available_pkg libmodbus5 libmodbus || true)"
  if [[ -z "$MODBUS_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find a libmodbus runtime package (tried: libmodbus5, libmodbus)." >&2
    exit 1
  fi
  GPIO_PY_PKG="$(pick_first_available_pkg python3-libgpiod python3-gpiod || true)"
  if [[ -z "$GPIO_PY_PKG" ]]; then
    echo "ERROR: Could not find a Python gpiod package (tried: python3-libgpiod, python3-gpiod)." >&2
    exit 1
  fi
  SDL_RUNTIME_PKG="$(pick_first_available_pkg libsdl2-2.0-0 libsdl2-2.0-0t64 || true)"
  if [[ -z "$SDL_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find an SDL2 runtime package (tried: libsdl2-2.0-0, libsdl2-2.0-0t64)." >&2
    exit 1
  fi
  EGL_RUNTIME_PKG="$(pick_first_available_pkg libegl1 || true)"
  if [[ -z "$EGL_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find EGL runtime package libegl1." >&2
    exit 1
  fi
  GLES_RUNTIME_PKG="$(pick_first_available_pkg libgles2 || true)"
  if [[ -z "$GLES_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find GLES runtime package libgles2." >&2
    exit 1
  fi
  GBM_RUNTIME_PKG="$(pick_first_available_pkg libgbm1 || true)"
  if [[ -z "$GBM_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find GBM runtime package libgbm1." >&2
    exit 1
  fi
  DRM_RUNTIME_PKG="$(pick_first_available_pkg libdrm2 || true)"
  if [[ -z "$DRM_RUNTIME_PKG" ]]; then
    echo "ERROR: Could not find DRM runtime package libdrm2." >&2
    exit 1
  fi
  apt-get install -y \
    acl \
    "$MODBUS_RUNTIME_PKG" \
    "$SDL_RUNTIME_PKG" \
    "$EGL_RUNTIME_PKG" \
    "$GLES_RUNTIME_PKG" \
    "$GBM_RUNTIME_PKG" \
    "$DRM_RUNTIME_PKG" \
    sudo \
    python3 \
    python3-venv \
    "$GPIO_PY_PKG"
fi

if [[ "$NO_MODBUS" != "true" ]]; then
  if ! has_libmodbus_runtime; then
    echo "ERROR: libmodbus runtime library not found on this system." >&2
    echo "Install mode without --skip-apt, or install libmodbus manually and retry." >&2
    exit 1
  fi
fi

ensure_group_user
install_shutdown_privileges

stop_service_if_active

mkdir -p "$TARGET_DIR"

APPS_REL_UNDER_TARGET=""
if [[ "$APPS_DIR" == "$TARGET_DIR"/* ]]; then
  APPS_REL_UNDER_TARGET="${APPS_DIR#"$TARGET_DIR"/}"
fi
PRESERVE_EXISTING_APPS="false"
if [[ -n "$APPS_REL_UNDER_TARGET" && -d "$APPS_DIR" ]]; then
  if should_preserve_existing_apps_dir "$APPS_DIR"; then
    PRESERVE_EXISTING_APPS="true"
  fi
fi

if command -v rsync >/dev/null 2>&1; then
  rsync_args=(rsync -a --exclude '.git')
  if [[ "$PRESERVE_EXISTING_APPS" == "true" ]]; then
    rsync_args+=(--exclude "${APPS_REL_UNDER_TARGET}/")
  fi
  if [[ "$RSYNC_DELETE" == "true" ]]; then
    rsync_args+=(--delete)
  fi
  rsync_args+=("$ROOT_DIR/" "$TARGET_DIR/")
  "${rsync_args[@]}"
else
  if [[ "$RSYNC_DELETE" == "true" ]]; then
    echo "Warning: rsync not found; --delete ignored" >&2
  fi
  if [[ "$PRESERVE_EXISTING_APPS" == "true" ]]; then
    tar -C "$ROOT_DIR" --exclude '.git' --exclude "$APPS_REL_UNDER_TARGET" -cf - . | tar -C "$TARGET_DIR" -xf -
  else
    cp -a "$ROOT_DIR/." "$TARGET_DIR/"
  fi
fi
mkdir -p "$CUSTOM_TYPES_DIR"
mkdir -p "$APPS_DIR"

if [[ "$SKIP_PIP" != "true" ]]; then
  if [[ ! -d "${TARGET_DIR}/.venv" ]]; then
    python3 -m venv "${TARGET_DIR}/.venv"
  fi
  "${TARGET_DIR}/.venv/bin/pip" install --upgrade pip
  "${TARGET_DIR}/.venv/bin/pip" install -r "${TARGET_DIR}/requirements.txt"
fi

mkdir -p "$CONFIG_DIR"
chown root:ogm "$CONFIG_DIR"
chmod 0770 "$CONFIG_DIR"

CONFIG_REGENERATED="false"
if should_write_config "$CONFIG_FILE"; then
  backup_file "$CONFIG_FILE"
  write_config
  CONFIG_REGENERATED="true"
fi

if [[ "$WRITE_PINMAP" == "true" || "$PINMAP_REQUESTED" == "true" ]]; then
  generate_pinmap
fi

chown -R ogm_pi:ogm "$TARGET_DIR"
mkdir -p "${TARGET_DIR}/crash_dumps"
chown ogm_pi:ogm "${TARGET_DIR}/crash_dumps"
chmod 0755 "${TARGET_DIR}/crash_dumps"
touch "${TARGET_DIR}/runtime_failures.log"
chown ogm_pi:ogm "${TARGET_DIR}/runtime_failures.log"
chmod 0644 "${TARGET_DIR}/runtime_failures.log"
if [[ -d "$CUSTOM_TYPES_DIR" ]]; then
  chown -R ogm_pi:ogm "$CUSTOM_TYPES_DIR"
fi
if [[ -d "$APPS_DIR" ]]; then
  chown -R ogm_pi:ogm "$APPS_DIR"
fi
apply_shared_runtime_permissions "$TARGET_DIR" "$CONFIG_ACCESS_USER"
if [[ "$CUSTOM_TYPES_DIR" != "$TARGET_DIR" && -d "$CUSTOM_TYPES_DIR" ]]; then
  apply_shared_runtime_permissions "$CUSTOM_TYPES_DIR" "$CONFIG_ACCESS_USER"
fi
if [[ "$APPS_DIR" != "$TARGET_DIR" && -d "$APPS_DIR" ]]; then
  apply_shared_runtime_permissions "$APPS_DIR" "$CONFIG_ACCESS_USER"
fi
if [[ -f "$CONFIG_FILE" ]]; then
  chown ogm_pi:ogm "$CONFIG_FILE"
  chmod 0660 "$CONFIG_FILE"
fi
if [[ -f "$PINMAP_FILE" ]]; then
  chown ogm_pi:ogm "$PINMAP_FILE"
  chmod 0660 "$PINMAP_FILE"
fi
grant_config_access_for_user "$CONFIG_ACCESS_USER"

if [[ "$SKIP_SYSTEMD" != "true" ]]; then
  install_units
  setup_systemd_override
  ensure_service_path_access
fi

validate_devices
systemd_reload_restart

echo "Installed OGM_slave_pi to ${TARGET_DIR}"
echo "Config: ${CONFIG_FILE}"
echo "Pinmap: ${PINMAP_FILE}"
if [[ "$CONFIG_REGENERATED" == "true" ]]; then
  echo "Config action: regenerated"
else
  echo "Config action: preserved existing"
fi
if [[ "$PRESERVE_EXISTING_APPS" == "true" ]]; then
  echo "Apps action: preserved existing content in ${APPS_DIR}"
else
  echo "Apps action: synced bundled content into ${APPS_DIR}"
fi
if [[ "$UART_REBOOT_REQUIRED" == "true" ]]; then
  echo "UART updates were applied. Reboot before using Modbus on ${SERIAL}."
  echo "After reboot: sudo systemctl restart ogm_pi.socket ogm_pi.service"
fi
echo "Next: edit config/pinmap as needed, then run 'systemctl status ogm_pi.service'"
