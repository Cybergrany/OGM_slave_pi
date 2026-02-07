#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sudo ./scripts/uninstall.sh [options]

Removes OGM Pi service/socket units and cleans deploy artifacts for the
Desktop deploy layout used by deploy_slave_pi.py.

Options:
  --root PATH         Deploy root to clean.
                      Default: /home/<sudo-user>/Desktop/OGM_slave_pi
  --socket-path PATH  IPC socket path to remove (default: /run/ogm_pi.sock)
  --delete-logs       Also delete deploy/runtime failure logs under --root
  --dry-run           Print commands without executing
  -h, --help          Show this help

Examples:
  sudo ./scripts/uninstall.sh
  sudo ./scripts/uninstall.sh --delete-logs
  sudo ./scripts/uninstall.sh --root /home/dave/Desktop/OGM_slave_pi
USAGE
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "uninstall.sh must be run as root" >&2
  exit 1
fi

detect_default_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf '%s\n' "${SUDO_USER}"
    return
  fi

  local login_user
  login_user="$(logname 2>/dev/null || true)"
  if [[ -n "$login_user" && "$login_user" != "root" ]]; then
    printf '%s\n' "$login_user"
    return
  fi

  printf '%s\n' "dave"
}

DEFAULT_USER="$(detect_default_user)"
ROOT_DIR="/home/${DEFAULT_USER}/Desktop/OGM_slave_pi"
SOCKET_PATH="/run/ogm_pi.sock"
SHUTDOWN_HELPER_PATH="/usr/local/sbin/ogm_pi_shutdown"
SUDOERS_SHUTDOWN_FILE="/etc/sudoers.d/ogm_pi_shutdown"
DELETE_LOGS="false"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_DIR="$2"
      shift 2
      ;;
    --socket-path)
      SOCKET_PATH="$2"
      shift 2
      ;;
    --delete-logs)
      DELETE_LOGS="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ROOT_DIR" || "$ROOT_DIR" == "/" ]]; then
  echo "Refusing to clean invalid root path: '$ROOT_DIR'" >&2
  exit 1
fi

RUNTIME_DIR="${ROOT_DIR}/runtime"
CONFIG_DIR="${ROOT_DIR}/config"
INCOMING_DIR="${ROOT_DIR}/incoming"
STAGING_DIR="${ROOT_DIR}/staging"
DEPLOY_LOG="${ROOT_DIR}/deploy_failures.log"
RUNTIME_LOG="${ROOT_DIR}/runtime_failures.log"

print_cmd() {
  local first="true"
  for arg in "$@"; do
    if [[ "$first" == "true" ]]; then
      printf '+ %q' "$arg"
      first="false"
    else
      printf ' %q' "$arg"
    fi
  done
  printf '\n'
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    print_cmd "$@"
    return 0
  fi
  "$@"
}

run_cmd_allow_fail() {
  if [[ "$DRY_RUN" == "true" ]]; then
    print_cmd "$@"
    printf '  (allowed to fail)\n'
    return 0
  fi
  "$@" || true
}

run_cmd_allow_fail_quiet() {
  if [[ "$DRY_RUN" == "true" ]]; then
    print_cmd "$@"
    printf '  (allowed to fail, quiet)\n'
    return 0
  fi
  "$@" >/dev/null 2>&1 || true
}

echo "Cleaning OGM_slave_pi deploy artifacts"
echo "  root: ${ROOT_DIR}"
echo "  socket: ${SOCKET_PATH}"
echo "  delete logs: ${DELETE_LOGS}"
echo "  dry-run: ${DRY_RUN}"

if command -v systemctl >/dev/null 2>&1; then
  run_cmd_allow_fail systemctl stop ogm_pi.service ogm_pi.socket
  run_cmd_allow_fail systemctl disable ogm_pi.service ogm_pi.socket
  run_cmd rm -f /etc/systemd/system/ogm_pi.service /etc/systemd/system/ogm_pi.socket
  run_cmd rm -rf /etc/systemd/system/ogm_pi.service.d
  run_cmd systemctl daemon-reload
  run_cmd_allow_fail_quiet systemctl reset-failed ogm_pi.service ogm_pi.socket
else
  echo "Warning: systemctl not found, skipping systemd cleanup." >&2
fi

run_cmd rm -f "$SUDOERS_SHUTDOWN_FILE" "$SHUTDOWN_HELPER_PATH"

run_cmd rm -rf "$RUNTIME_DIR" "$CONFIG_DIR" "$INCOMING_DIR" "$STAGING_DIR"
run_cmd rm -f "$SOCKET_PATH"

if [[ "$DELETE_LOGS" == "true" ]]; then
  run_cmd rm -f "$DEPLOY_LOG" "$RUNTIME_LOG"
fi

echo "Cleanup complete."
