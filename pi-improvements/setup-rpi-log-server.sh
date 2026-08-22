#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Lightweight central TCP syslog collector for a small Raspberry Pi fleet.
#
# - Raspberry Pi OS / Debian-family host with systemd + apt
# - rsyslog TCP ingress only (no database/indexer)
# - per-host/per-day files under a user-visible symlink
# - bounded in-memory action queue and modest file buffering
# - optional sender CIDR/IP restriction
# - daily retention pruning
# - syntax, service, listener and end-to-end local ingress validation
#
# Usage:
#   sudo bash setup-rpi-log-server.sh
#   sudo bash setup-rpi-log-server.sh --verify

CONFIG_FILE="/etc/rpi-fleet-log-server.conf"
RSYSLOG_CFG="/etc/rsyslog.d/20-rpi-fleet-collector.conf"
PRUNE_SERVICE="/etc/systemd/system/rpi-fleet-log-prune.service"
PRUNE_TIMER="/etc/systemd/system/rpi-fleet-log-prune.timer"

say()  { printf '%s\n' "$*"; }
info() { printf 'INFO:  %s\n' "$*"; }
ok()   { printf 'OK:    %s\n' "$*"; }
warn() { printf 'WARN:  %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root, e.g. sudo bash $0"
}

read_default() {
  local prompt="$1" def="$2" value
  read -r -p "${prompt} [default: ${def}] " value || true
  [[ -n "${value:-}" ]] && printf '%s\n' "$value" || printf '%s\n' "$def"
}

read_optional() {
  local prompt="$1" def="$2" value
  if [[ -n "$def" ]]; then
    read -r -p "${prompt} [default: ${def}; '-' = none] " value || true
    if [[ -z "${value:-}" ]]; then printf '%s\n' "$def"; return; fi
    if [[ "$value" == "-" ]]; then printf '\n'; return; fi
    printf '%s\n' "$value"
  else
    read -r -p "${prompt} [blank = none] " value || true
    printf '%s\n' "${value:-}"
  fi
}

read_yesno() {
  local prompt="$1" def="$2" value
  while true; do
    value="$(read_default "$prompt (yes/no)" "$def")"
    case "$value" in
      yes|y|Y) printf 'yes\n'; return ;;
      no|n|N)  printf 'no\n'; return ;;
      *) warn "Please enter yes or no." ;;
    esac
  done
}

numeric_range() {
  local value="$1" name="$2" min="$3" max="$4"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a whole number (got '$value')."
  (( value >= min && value <= max )) || die "$name must be between $min and $max (got '$value')."
}

require_supported_host() {
  command -v apt-get >/dev/null 2>&1 || die "This setup currently supports apt-based Raspberry Pi OS/Debian-family hosts only."
  command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl is required."
  command -v ip >/dev/null 2>&1 || die "The 'ip' command (iproute2) is required."
  [[ -r /etc/os-release ]] || die "/etc/os-release is missing."
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    raspbian|debian) ;;
    *)
      if [[ " ${ID_LIKE:-} " != *" debian "* ]]; then
        die "Detected OS '${PRETTY_NAME:-${ID:-unknown}}'. This script currently supports Raspberry Pi OS/Debian-family collectors only."
      fi
      ;;
  esac
}

install_rsyslog_if_needed() {
  if ! dpkg-query -W -f='${Status}' rsyslog 2>/dev/null | grep -q 'install ok installed'; then
    info "Installing rsyslog..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y rsyslog
  else
    ok "rsyslog already installed"
  fi
  command -v rsyslogd >/dev/null 2>&1 || die "rsyslog package is installed but rsyslogd is unavailable."
  command -v logger >/dev/null 2>&1 || die "The util-linux 'logger' utility is required for validation."
  command -v runuser >/dev/null 2>&1 || die "The util-linux 'runuser' utility is required for validation."
  getent passwd syslog >/dev/null || die "rsyslog installed, but the expected 'syslog' user does not exist."
}

primary_interface() {
  ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}'
}

primary_ipv4() {
  local iface
  iface="$(primary_interface)"
  if [[ -n "$iface" ]]; then
    ip -4 addr show dev "$iface" scope global 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}'
  fi
}

primary_cidr() {
  local iface ipaddr
  iface="$(primary_interface)"
  ipaddr="$(primary_ipv4)"
  [[ -n "$iface" && -n "$ipaddr" ]] || return 0
  ip -4 route show dev "$iface" proto kernel scope link 2>/dev/null |
    awk -v src="$ipaddr" '$1 ~ /^[0-9]+\./ && $1 ~ /\// && $0 ~ ("src " src) {print $1; exit}'
}

all_ipv4s() {
  hostname -I 2>/dev/null | tr ' ' '\n' | awk 'NF && $0 !~ /^127\./' | paste -sd' ' -
}

safe_simple_path() {
  local p="$1" name="$2"
  [[ "$p" == /* ]] || die "$name must be an absolute path."
  [[ "$p" != *$'\n'* && "$p" != *$'\t'* && "$p" != *' '* ]] || die "$name may not contain whitespace."
  [[ "$p" != "/" ]] || die "$name may not be '/'."
}

validate_allowed_sender() {
  local v="$1"
  [[ -z "$v" ]] && return 0
  # Let rsyslog perform final semantic validation, but reject characters that
  # could break the generated RainerScript string.
  [[ "$v" =~ ^[A-Za-z0-9_.:/-]+$ ]] || die "Allowed sender must be a single IP, CIDR or simple hostname (got '$v')."
}

listener_lines() {
  local port="$1"
  ss -H -ltnp "sport = :${port}" 2>/dev/null || true
}

port_in_use_by_unmanaged_listener() {
  local port="$1" lines
  lines="$(listener_lines "$port")"
  [[ -z "$lines" ]] && return 1

  if [[ -f "$RSYSLOG_CFG" ]] && grep -q "Managed by setup-rpi-log-server.sh" "$RSYSLOG_CFG" && grep -q 'rsyslogd' <<<"$lines"; then
    return 1
  fi

  printf '%s\n' "$lines" >&2
  return 0
}

backup_file() {
  local src="$1" backup_dir="$2"
  [[ -e "$src" ]] || return 0
  mkdir -p "$backup_dir"
  cp -a "$src" "$backup_dir/$(basename "$src")"
}

write_atomic() {
  local dest="$1" mode="$2" tmp
  tmp="$(mktemp "${dest}.tmp.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown root:root "$tmp"
  mv -f "$tmp" "$dest"
}

write_state() {
  local log_root="$1" view_user="$2" view_group="$3" view_link="$4" port="$5" allowed="$6" retention="$7"
  local tmp
  tmp="$(mktemp "${CONFIG_FILE}.tmp.XXXXXX")"
  {
    printf 'LOG_ROOT=%q\n' "$log_root"
    printf 'VIEW_USER=%q\n' "$view_user"
    printf 'VIEW_GROUP=%q\n' "$view_group"
    printf 'VIEW_LINK=%q\n' "$view_link"
    printf 'PORT=%q\n' "$port"
    printf 'ALLOWED_SENDER=%q\n' "$allowed"
    printf 'RETENTION_DAYS=%q\n' "$retention"
  } >"$tmp"
  chmod 0644 "$tmp"
  chown root:root "$tmp"
  mv -f "$tmp" "$CONFIG_FILE"
}

write_rsyslog_config() {
  local log_root="$1" view_group="$2" port="$3" allowed="$4"
  local allowed_param=""

  if [[ -n "$allowed" ]]; then
    allowed_param="AllowedSender=[\"127.0.0.1\",\"${allowed}\"]"
  fi

  mkdir -p /etc/rsyslog.d
  write_atomic "$RSYSLOG_CFG" 0644 <<EOF
# Managed by setup-rpi-log-server.sh
# Lightweight Raspberry Pi fleet TCP syslog collector.
#
# Remote messages are bound to FleetRemote and therefore do not fall through
# into the collector's normal local /var/log rules.

module(load="imtcp" MaxSessions="64" ${allowed_param})

# Use collector receive time for the directory tree. This avoids a client with
# a bad clock creating misleading date directories. Client-reported time is
# still preserved in each log line.
template(name="FleetLogPath" type="string"
         string="${log_root}/%hostname:::secpath-replace%/%timegenerated:::date-year%/%timegenerated:::date-month%/%timegenerated:::date-day%.log")

template(name="FleetLogLine" type="string"
         string="%timereported:::date-rfc3339% | recv=%timegenerated:::date-rfc3339% | [%syslogseverity-text%] %app-name%[%procid%]: %msg:::drop-last-lf%\\n")

ruleset(name="FleetRemote") {
    action(
        type="omfile"
        dynaFile="FleetLogPath"
        template="FleetLogLine"
        createDirs="on"
        dirOwner="syslog"
        dirGroup="${view_group}"
        dirCreateMode="0750"
        fileOwner="syslog"
        fileGroup="${view_group}"
        fileCreateMode="0640"
        dynaFileCacheSize="32"

        # Small, bounded write buffering: low disk churn without allowing
        # ingress to consume unbounded RAM or worker threads.
        ioBufferSize="64k"
        asyncWriting="on"
        flushOnTXEnd="off"
        flushInterval="1"
        queue.type="LinkedList"
        queue.size="5000"
        queue.timeoutEnqueue="1000"
    )
}

input(
    type="imtcp"
    address="*"
    port="${port}"
    ruleset="FleetRemote"
)
EOF
}

write_retention_units() {
  local log_root="$1" days="$2"

  write_atomic "$PRUNE_SERVICE" 0644 <<EOF
[Unit]
Description=Prune old Raspberry Pi fleet logs

[Service]
Type=oneshot
ExecStart=/usr/bin/find ${log_root} -type f -name *.log -mtime +${days} -delete
ExecStart=/usr/bin/find ${log_root} -mindepth 1 -type d -empty -delete
EOF

  write_atomic "$PRUNE_TIMER" 0644 <<'EOF'
[Unit]
Description=Daily Raspberry Pi fleet log retention

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF
}

setup_view_link() {
  local link="$1" target="$2" user="$3"
  local parent
  parent="$(dirname "$link")"
  [[ -d "$parent" ]] || die "Parent directory for user-facing link does not exist: $parent"

  if [[ -L "$link" ]]; then
    if [[ "$(readlink -f "$link")" == "$(readlink -f "$target")" ]]; then
      ok "User-facing link already points to $target"
      return 0
    fi
    local replace
    replace="$(read_yesno "${link} is an existing symlink to another target. Replace it?" "no")"
    [[ "$replace" == "yes" ]] || die "Refusing to replace existing symlink $link"
    rm -f "$link"
  elif [[ -e "$link" ]]; then
    die "$link already exists and is not a symlink. Move/remove it manually and rerun."
  fi

  ln -s "$target" "$link"
  chown -h "$user:$(id -gn "$user")" "$link" 2>/dev/null || true
  ok "Created user-facing link: $link -> $target"
}

configure_ufw_if_active() {
  local port="$1" allowed="$2"
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q '^Status: active' || return 0

  warn "UFW is active; TCP ${port} may be blocked until a rule is added."
  local answer
  answer="$(read_yesno "Add an inbound UFW rule for this collector?" "yes")"
  [[ "$answer" == "yes" ]] || return 0

  if [[ -n "$allowed" ]]; then
    ufw allow from "$allowed" to any port "$port" proto tcp
  else
    ufw allow "$port/tcp"
  fi
  ok "UFW rule added"
}

run_local_ingress_test() {
  local port="$1" log_root="$2"
  local token="FLEET_SYSLOG_SETUP_TEST_$(date +%s)_$$" found="" i

  info "Sending an end-to-end TCP syslog test through 127.0.0.1:${port}..."
  if logger --help 2>&1 | grep -q -- '--rfc5424'; then
    logger --tcp --server 127.0.0.1 --port "$port" --rfc5424 -t fleet-log-test "$token"
  else
    logger --tcp --server 127.0.0.1 --port "$port" -t fleet-log-test "$token"
  fi

  for i in 1 2 3 4 5; do
    found="$(grep -R -l -F -- "$token" "$log_root" 2>/dev/null | head -n1 || true)"
    [[ -n "$found" ]] && break
    sleep 1
  done

  [[ -n "$found" ]] || return 1
  ok "End-to-end ingress test written to: $found"
  return 0
}

print_endpoint() {
  local port="$1" log_root="$2" view_link="$3" allowed="$4"
  local primary all
  primary="$(primary_ipv4)"
  all="$(all_ipv4s)"

  say
  say "================ COLLECTOR READY ================"
  if [[ -n "$primary" ]]; then
    say "Collector endpoint:  tcp://${primary}:${port}"
    say "Client host/IP:      ${primary}"
  else
    say "Collector endpoint:  tcp://<THIS-PI-IP>:${port}"
    say "Client host/IP:      <THIS-PI-IP>"
  fi
  say "Client TCP port:     ${port}"
  say "Log directory:       ${view_link}"
  say "Backing directory:   ${log_root}"
  if [[ -n "$allowed" ]]; then
    say "Allowed senders:     ${allowed} (+ local loopback for validation)"
  else
    say "Allowed senders:     ANY (LAN/firewall restriction recommended)"
  fi
  [[ -n "$all" ]] && say "Detected IPv4s:      ${all}"
  say "==================================================="
  say
}

load_state() {
  [[ -r "$CONFIG_FILE" ]] || die "No saved collector state at $CONFIG_FILE. Run setup first."
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
  : "${LOG_ROOT:?}" "${VIEW_USER:?}" "${VIEW_GROUP:?}" "${VIEW_LINK:?}" "${PORT:?}" "${RETENTION_DAYS:?}"
  ALLOWED_SENDER="${ALLOWED_SENDER:-}"
}

verify_setup() {
  load_state
  local failures=0 lines

  say "=== Raspberry Pi fleet log collector verification ==="

  if rsyslogd -N1 >/dev/null; then
    ok "rsyslog configuration syntax"
  else
    warn "rsyslog configuration validation failed"
    rsyslogd -N1 || true
    failures=$((failures+1))
  fi

  if systemctl is-active --quiet rsyslog.service; then
    ok "rsyslog service active"
  else
    warn "rsyslog service is not active"
    systemctl status rsyslog.service --no-pager -l || true
    failures=$((failures+1))
  fi

  lines="$(listener_lines "$PORT")"
  if [[ -n "$lines" ]]; then
    ok "TCP ${PORT} listener active"
    printf '%s\n' "$lines"
  else
    warn "No TCP listener found on port ${PORT}"
    failures=$((failures+1))
  fi

  if [[ -d "$LOG_ROOT" ]] && runuser -u syslog -- test -w "$LOG_ROOT"; then
    ok "rsyslog can write to $LOG_ROOT"
  else
    warn "syslog user cannot write to $LOG_ROOT"
    failures=$((failures+1))
  fi

  if runuser -u "$VIEW_USER" -- test -x "$LOG_ROOT"; then
    ok "${VIEW_USER} can traverse the log root"
  else
    warn "${VIEW_USER} cannot traverse $LOG_ROOT"
    failures=$((failures+1))
  fi

  if [[ -L "$VIEW_LINK" && "$(readlink -f "$VIEW_LINK")" == "$(readlink -f "$LOG_ROOT")" ]]; then
    ok "user-facing link: $VIEW_LINK"
  else
    warn "user-facing link is missing or points elsewhere: $VIEW_LINK"
    failures=$((failures+1))
  fi

  if systemctl is-enabled --quiet rpi-fleet-log-prune.timer && systemctl is-active --quiet rpi-fleet-log-prune.timer; then
    ok "retention timer enabled+active (${RETENTION_DAYS} days)"
  else
    warn "retention timer is not enabled and active"
    failures=$((failures+1))
  fi

  if run_local_ingress_test "$PORT" "$LOG_ROOT"; then
    :
  else
    warn "End-to-end local TCP ingress test failed"
    failures=$((failures+1))
  fi

  say
  say "rsyslog process footprint:"
  ps -C rsyslogd -o pid=,%cpu=,%mem=,rss=,etime=,cmd= 2>/dev/null || true

  print_endpoint "$PORT" "$LOG_ROOT" "$VIEW_LINK" "$ALLOWED_SENDER"

  if (( failures == 0 )); then
    ok "Verification PASS"
    return 0
  fi
  warn "Verification FAIL (${failures} check(s))"
  return 1
}

apply_setup() {
  [[ -t 0 ]] || die "Interactive setup requires a terminal. Use --verify for noninteractive validation."

  local sudo_user default_user view_user view_group home log_root view_link port retention default_cidr allowed
  local backup_dir confirm had_cfg="no" primary

  sudo_user="${SUDO_USER:-}"
  if [[ -n "$sudo_user" && "$sudo_user" != "root" ]] && id "$sudo_user" >/dev/null 2>&1; then
    default_user="$sudo_user"
  else
    default_user="$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1; exit}' /etc/passwd)"
    [[ -n "$default_user" ]] || default_user="root"
  fi

  primary="$(primary_ipv4)"
  default_cidr="$(primary_cidr)"

  say "Raspberry Pi fleet log collector setup"
  say "-------------------------------------"
  [[ -n "$primary" ]] && info "Detected primary LAN IPv4: $primary"
  [[ -n "$default_cidr" ]] && info "Detected local IPv4 subnet: $default_cidr"
  say

  view_user="$(read_default "User who should have convenient read access to logs" "$default_user")"
  id "$view_user" >/dev/null 2>&1 || die "User does not exist: $view_user"
  view_group="$(id -gn "$view_user")"
  home="$(getent passwd "$view_user" | cut -d: -f6)"
  [[ -d "$home" ]] || die "Home directory for $view_user does not exist: $home"

  log_root="$(read_default "Backing log directory" "/srv/rpi-logs")"
  safe_simple_path "$log_root" "Log directory"

  view_link="$(read_default "User-facing log path (created as a symlink)" "$home/rpi-logs")"
  safe_simple_path "$view_link" "User-facing log path"

  port="$(read_default "TCP syslog port" "514")"
  numeric_range "$port" "TCP port" 1 65535

  retention="$(read_default "Retention in days" "180")"
  numeric_range "$retention" "Retention days" 1 3650

  allowed="$(read_optional "Allowed sender CIDR/IP" "$default_cidr")"
  validate_allowed_sender "$allowed"

  say
  info "Planned configuration:"
  say "  TCP endpoint:      tcp://${primary:-<this-pi-ip>}:${port}"
  say "  Allowed senders:   ${allowed:-ANY}"
  say "  Logs:              ${log_root}/<hostname>/<YYYY>/<MM>/<DD>.log"
  say "  User-facing path:  ${view_link}"
  say "  Reader user/group: ${view_user}:${view_group}"
  say "  Retention:         ${retention} days"
  say "  Ingress:           rsyslog imtcp; max 64 TCP sessions"
  say "  Output buffering:  64 KiB async buffer; 1 s flush"
  say "  Queue:             bounded 5,000-message in-memory action queue"
  say "  Database/indexer:  none"
  say

  confirm="$(read_yesno "Proceed?" "yes")"
  [[ "$confirm" == "yes" ]] || die "Aborted by user."

  install_rsyslog_if_needed

  if port_in_use_by_unmanaged_listener "$port"; then
    die "TCP port $port is already in use by an unmanaged listener. Choose another port or remove the conflicting listener."
  fi

  backup_dir="/var/backups/rpi-fleet-log-server/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  backup_file "$RSYSLOG_CFG" "$backup_dir"
  backup_file "$PRUNE_SERVICE" "$backup_dir"
  backup_file "$PRUNE_TIMER" "$backup_dir"
  backup_file "$CONFIG_FILE" "$backup_dir"
  [[ -e "$RSYSLOG_CFG" ]] && had_cfg="yes"

  mkdir -p "$log_root"
  chown syslog:"$view_group" "$log_root"
  chmod 0750 "$log_root"

  write_rsyslog_config "$log_root" "$view_group" "$port" "$allowed"

  if ! rsyslogd -N1; then
    warn "New rsyslog configuration failed validation; rolling it back."
    if [[ "$had_cfg" == "yes" && -f "$backup_dir/$(basename "$RSYSLOG_CFG")" ]]; then
      cp -a "$backup_dir/$(basename "$RSYSLOG_CFG")" "$RSYSLOG_CFG"
    else
      rm -f "$RSYSLOG_CFG"
    fi
    die "rsyslog syntax validation failed. Previous collector config restored."
  fi
  ok "rsyslog configuration syntax validated"

  write_retention_units "$log_root" "$retention"
  systemctl daemon-reload
  systemctl enable --now rpi-fleet-log-prune.timer >/dev/null

  systemctl enable rsyslog.service >/dev/null 2>&1 || true
  if ! systemctl restart rsyslog.service; then
    warn "rsyslog failed to restart; rolling collector config back."
    if [[ "$had_cfg" == "yes" && -f "$backup_dir/$(basename "$RSYSLOG_CFG")" ]]; then
      cp -a "$backup_dir/$(basename "$RSYSLOG_CFG")" "$RSYSLOG_CFG"
    else
      rm -f "$RSYSLOG_CFG"
    fi
    systemctl restart rsyslog.service >/dev/null 2>&1 || true
    die "rsyslog restart failed. Review: systemctl status rsyslog --no-pager -l"
  fi

  setup_view_link "$view_link" "$log_root" "$view_user"
  write_state "$log_root" "$view_user" "$view_group" "$view_link" "$port" "$allowed" "$retention"
  configure_ufw_if_active "$port" "$allowed"

  say
  info "Running validation..."
  verify_setup
  say
  info "Backups from this setup run: $backup_dir"
}

need_root
require_supported_host

case "${1:-}" in
  "") apply_setup ;;
  --verify)
    command -v rsyslogd >/dev/null 2>&1 || die "rsyslogd is not installed; run setup first."
    command -v runuser >/dev/null 2>&1 || die "runuser is unavailable."
    verify_setup
    ;;
  *) die "Unknown option '$1'. Supported: --verify" ;;
esac
