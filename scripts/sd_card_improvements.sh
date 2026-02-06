#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# sdcard_longevity_tune_prod.sh
#
# Goals:
# - SD longevity improvements with low runtime risk
# - Keep /var/log on disk
# - journald persistent + capped
# - tmpfs for /tmp and /var/tmp (optional)
# - Prefer Raspberry Pi OS's native rpi-swap/systemd-zram-generator if present (no conflicts)
# - Clear, non-silent output on failures + a run log
#
# Usage:
#   sudo bash sdcard_longevity_tune_prod.sh
#   sudo bash sdcard_longevity_tune_prod.sh --verify

# -------------------- helpers --------------------

die()  { echo "ERROR: $*"; exit 1; }
warn() { echo "WARN:  $*"; }
ok()   { echo "OK:    $*"; }
info() { echo "INFO:  $*"; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (use sudo)."; }

ts() { date +"%Y%m%d-%H%M%S"; }

read_default() {
  local prompt="$1" def="$2" var
  read -r -p "${prompt} [default: ${def}] " var || true
  [[ -z "${var:-}" ]] && echo "$def" || echo "$var"
}

numeric_or_die() {
  local v="$1" name="$2"
  [[ "$v" =~ ^[0-9]+$ ]] || die "${name} must be a whole number (got: ${v})"
}

apt_install_if_missing() {
  local pkg="$1"
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    info "Installing package: $pkg"
    apt-get update -y
    apt-get install -y "$pkg"
  fi
}

backup_file() {
  local f="$1"
  mkdir -p "$BACKUP_DIR"
  # Avoid triggering ERR trap on non-existent files.
  if [[ -e "$f" ]]; then
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").bak"
  fi
}


mount_best_effort() {
  local mnt="$1"
  mkdir -p "$mnt"
  if mountpoint -q "$mnt"; then
    mount -o remount "$mnt" >/dev/null 2>&1 || true
  else
    mount "$mnt" >/dev/null 2>&1 || true
  fi
}

# Manage only lines that end with "# sdcard_tune"
fstab_upsert_managed_line() {
  local mountpoint="$1"
  local newline="$2"   # full line including marker
  local fstab="/etc/fstab"
  local tmp="${fstab}.sdcard_tune.tmp"

  backup_file "$fstab"

  awk -v mnt="$mountpoint" -v nl="$newline" '
    BEGIN { replaced=0 }
    {
      if ($0 ~ /# sdcard_tune[[:space:]]*$/ && $0 ~ ("^tmpfs[[:space:]]+" mnt "[[:space:]]+tmpfs[[:space:]]")) {
        if (nl != "") { print nl; replaced=1; }
        next
      }
      print
    }
    END {
      if (!replaced && nl != "") print nl
    }
  ' "$fstab" > "$tmp"

  [[ -s "$tmp" ]] || die "Refusing to write empty /etc/fstab (tmp generation failed)."
  mv -f "$tmp" "$fstab"
}

fstab_remove_managed_line() {
  local mountpoint="$1"
  fstab_upsert_managed_line "$mountpoint" ""
}

# -------------------- swap backend detection --------------------

detect_rpi_swap_backend() {
  # rpi-swap installs /etc/rpi/swap.conf and uses a systemd generator for zram
  [[ -f /etc/rpi/swap.conf ]] && return 0

  # Units seen on newer Raspberry Pi OS builds
  systemctl list-units --all --no-legend 2>/dev/null | grep -qiE 'systemd-zram-setup|systemd\\x2dzram\\x2dsetup\.slice|rpi-zram-writeback\.timer' && return 0
  systemctl list-unit-files --no-legend 2>/dev/null | grep -qiE '^rpi-zram-writeback\.timer|^systemd-zram-setup@' && return 0

  # Package presence (best-effort)
  dpkg -s rpi-swap >/dev/null 2>&1 && return 0
  dpkg -s systemd-zram-generator >/dev/null 2>&1 && return 0

  return 1
}

zram_swap_active() {
  swapon --show --noheadings --raw 2>/dev/null | awk '{print $1}' | grep -qE '(^/dev/zram|zram)'
}

disable_conflicting_zramswap() {
  # If zram-tools is installed on a system already using rpi-swap, disable/mask zramswap
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^zramswap\.service'; then
    info "Disabling/masking zramswap.service to avoid conflicts with rpi-swap/systemd-zram-generator"
    systemctl disable --now zramswap.service >/dev/null 2>&1 || true
    systemctl mask zramswap.service >/dev/null 2>&1 || true
  fi
}

# -------------------- rpi-swap configuration --------------------

write_rpi_swap_dropin() {
  local zram_mib="$1"
  local dir="/etc/rpi/swap.conf.d"
  local file="${dir}/99-sdcard-tune.conf"

  mkdir -p "$dir"
  backup_file "$file"

  cat > "$file" <<EOF
# Managed by sdcard_longevity_tune_prod.sh
[Zram]
MaxSizeMiB=${zram_mib}
FixedSizeMiB=${zram_mib}
EOF

  ok "Wrote rpi-swap drop-in: ${file} (takes effect after reboot)"
}

# -------------------- zram-tools backend (only when no rpi-swap) --------------------

configure_zram_tools() {
  local percent="$1" algo="$2" prio="$3"
  local cfg="/etc/default/zramswap"
  backup_file "$cfg"
  touch "$cfg"

  if grep -qE '^\s*PERCENT=' "$cfg"; then
    sed -i -E "s/^\s*PERCENT=.*/PERCENT=${percent}/" "$cfg"
  else
    echo "PERCENT=${percent}" >> "$cfg"
  fi

  # Avoid forcing ALGO unless requested; "auto" means remove ALGO
  if [[ "$algo" == "auto" ]]; then
    sed -i -E '/^\s*ALGO=/d' "$cfg"
  else
    if grep -qE '^\s*ALGO=' "$cfg"; then
      sed -i -E "s/^\s*ALGO=.*/ALGO=${algo}/" "$cfg"
    else
      echo "ALGO=${algo}" >> "$cfg"
    fi
  fi

  if grep -qE '^\s*PRIORITY=' "$cfg"; then
    sed -i -E "s/^\s*PRIORITY=.*/PRIORITY=${prio}/" "$cfg"
  else
    echo "PRIORITY=${prio}" >> "$cfg"
  fi
}

start_and_verify_zramswap() {
  systemctl enable --now zramswap.service

  if ! zram_swap_active; then
    systemctl status zramswap.service --no-pager -l || true
    die "zramswap.service started but no zram swap is active (swapon shows no /dev/zram*)."
  fi

  ok "zram swap active via zram-tools (zramswap.service)"
}

# -------------------- disk swap disable (dphys-swapfile only) --------------------

disable_dphys_swapfile_only() {
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^dphys-swapfile\.service'; then
    local swapfile="/var/swap"

    if [[ -f /etc/dphys-swapfile ]]; then
      backup_file "/etc/dphys-swapfile"
      local conf
      conf="$(awk -F= '/^\s*CONF_SWAPFILE=/ {gsub(/\"/,"",$2); print $2}' /etc/dphys-swapfile | tail -n1 || true)"
      [[ -n "${conf:-}" ]] && swapfile="$conf"

      if grep -qE '^\s*CONF_SWAPSIZE=' /etc/dphys-swapfile; then
        sed -i -E 's/^\s*CONF_SWAPSIZE=.*/CONF_SWAPSIZE=0/' /etc/dphys-swapfile
      else
        echo "CONF_SWAPSIZE=0" >> /etc/dphys-swapfile
      fi
    fi

    systemctl disable --now dphys-swapfile.service >/dev/null 2>&1 || true

    if swapon --show --noheadings --raw | awk '{print $1}' | grep -qx "$swapfile"; then
      swapoff "$swapfile" || true
    fi

    ok "dphys-swapfile disabled (disk swapfile: ${swapfile})"
  else
    ok "dphys-swapfile.service not present"
  fi
}

# -------------------- journald persistent + capped --------------------

write_journald_dropin_persistent_capped() {
  local cap_mb="$1"
  local dropdir="/etc/systemd/journald.conf.d"
  local dropfile="${dropdir}/99-sdcard-tune.conf"

  mkdir -p "$dropdir"
  backup_file "$dropfile"

  cat > "$dropfile" <<EOF
# Managed by sdcard_longevity_tune_prod.sh
[Journal]
Storage=persistent
SystemMaxUse=${cap_mb}M
RuntimeMaxUse=${cap_mb}M
EOF

  ok "Wrote journald drop-in: ${dropfile}"
}

ensure_persistent_journal_dir() {
  mkdir -p /var/log/journal
  systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
}

restart_and_verify_journald() {
  systemctl restart systemd-journald
  if ! systemctl is-active --quiet systemd-journald; then
    systemctl status systemd-journald --no-pager -l || true
    die "systemd-journald failed to restart after configuration changes"
  fi
  ok "systemd-journald restarted successfully"
}

# -------------------- logrotate --------------------

ensure_logrotate_active() {
  apt_install_if_missing "logrotate"

  # Prefer systemd timer if present
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^logrotate\.timer'; then
    systemctl enable --now logrotate.timer
    ok "logrotate.timer enabled"
    return 0
  fi

  # Otherwise rely on cron.daily
  if [[ -f /etc/cron.daily/logrotate ]]; then
    chmod +x /etc/cron.daily/logrotate || true
    ok "logrotate scheduled via /etc/cron.daily/logrotate"
  else
    warn "No logrotate.timer and /etc/cron.daily/logrotate missing; logrotate may not run automatically."
  fi

  # Ensure cron service is enabled/running (best-effort)
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^cron\.service'; then
    systemctl enable --now cron.service >/dev/null 2>&1 || true
  fi
}

# -------------------- readiness checks --------------------

kernel_error_scan() {
  # High-signal patterns only; avoids flagging normal boot lines.
  dmesg -T 2>/dev/null | egrep -i \
    'mmc[^\n]*(timeout|timed out|crc|fail|error)|I/O error|Buffer I/O error|EXT4-fs[^\n]*(error|warning)|blk_update_request: I/O error' \
    | tail -n 40 || true
}

run_readiness_checks() {
  local failures=0
  local must_reboot="no"

  echo
  echo "=== Pre-production readiness checks ==="

  echo
  echo "[1] fstab sanity: mount -a"
  if mount -a; then ok "mount -a succeeded"; else warn "mount -a failed"; failures=$((failures+1)); fi

  echo
  echo "[2] Managed fstab entries (# sdcard_tune)"
  grep -n "sdcard_tune" /etc/fstab || true

  echo
  echo "[3] Swap configuration"
  swapon --show || true
  if zram_swap_active; then ok "zram swap present"; else warn "zram swap not present"; failures=$((failures+1)); fi
  if detect_rpi_swap_backend; then ok "Detected rpi-swap/systemd-zram-generator backend"; fi

  echo
  echo "[4] tmpfs mounts"
  local fstype
  fstype="$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)"
  if [[ "$fstype" == "tmpfs" ]]; then ok "/tmp is tmpfs"; else warn "/tmp is not tmpfs (fstype=${fstype}); reboot may be required"; must_reboot="yes"; fi

  local fstype2
  fstype2="$(findmnt -n -o FSTYPE /var/tmp 2>/dev/null || true)"
  if [[ -n "$fstype2" ]]; then
    if [[ "$fstype2" == "tmpfs" ]]; then ok "/var/tmp is tmpfs"; else warn "/var/tmp is not tmpfs (fstype=${fstype2}); reboot may be required"; must_reboot="yes"; fi
  fi

  echo
  echo "[5] journald: persistent + capped"
  if [[ -f /etc/systemd/journald.conf.d/99-sdcard-tune.conf ]]; then
    ok "journald drop-in present"
  else
    warn "journald drop-in not found"
    failures=$((failures+1))
  fi
  journalctl --disk-usage || true

  echo
  echo "[6] logrotate scheduling"
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^logrotate\.timer'; then
    if systemctl is-enabled --quiet logrotate.timer && systemctl is-active --quiet logrotate.timer; then
      ok "logrotate.timer enabled+active"
    else
      warn "logrotate.timer exists but not enabled/active"
      failures=$((failures+1))
    fi
  else
    if [[ -x /etc/cron.daily/logrotate ]]; then ok "/etc/cron.daily/logrotate present+executable"; else warn "logrotate not scheduled"; failures=$((failures+1)); fi
  fi

  echo
  echo "[7] Kernel log scan (high-signal I/O/ext4/mmc errors only)"
  local k
  k="$(kernel_error_scan)"
  if [[ -n "$k" ]]; then
    warn "Kernel log contains I/O/ext4/mmc error patterns (review):"
    echo "$k"
  else
    ok "No high-signal I/O/ext4/mmc error patterns detected"
  fi

  echo
  if [[ "$failures" -eq 0 ]]; then ok "Readiness checks: PASS"; else warn "Readiness checks: FAIL (${failures})"; fi
  if [[ "$must_reboot" == "yes" ]]; then warn "A reboot is recommended to validate boot-time behavior."; fi

  return "$failures"
}

# -------------------- main --------------------

need_root

MODE="apply"
if [[ "${1:-}" == "--verify" ]]; then
  MODE="verify"
fi

RAM_KB="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
RAM_MB="$((RAM_KB / 1024))"

# Defaults tuned for Pi-class devices including Zero 2 W (512MB)
if (( RAM_MB <= 768 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=64
  DEF_VARTMP_MB=32
  DEF_JOURNAL_CAP_MB=50
elif (( RAM_MB <= 1024 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=128
  DEF_VARTMP_MB=64
  DEF_JOURNAL_CAP_MB=100
elif (( RAM_MB <= 4096 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=256
  DEF_VARTMP_MB=128
  DEF_JOURNAL_CAP_MB=200
else
  DEF_ZRAM_PCT=25
  DEF_TMP_MB=512
  DEF_VARTMP_MB=256
  DEF_JOURNAL_CAP_MB=300
fi

STAMP="$(ts)"
BACKUP_DIR="/var/backups/sdcard_longevity_tune/${STAMP}"
mkdir -p "$BACKUP_DIR"
LOGFILE="${BACKUP_DIR}/run.log"

# Make output non-silent: tee everything to a logfile.
exec > >(tee -a "$LOGFILE") 2>&1

# Fail loudly with context
trap 'rc=$?; echo; echo "ERROR: command failed (exit=${rc}) at line ${LINENO}: ${BASH_COMMAND}"; echo "Log: ${LOGFILE}"; exit $rc' ERR

info "Detected RAM: ${RAM_MB} MB"
info "Backups: ${BACKUP_DIR}"
info "Log: ${LOGFILE}"

echo

if [[ "$MODE" == "verify" ]]; then
  run_readiness_checks
  exit $?
fi

ZRAM_PCT="$(read_default "ZRAM size as % of RAM" "${DEF_ZRAM_PCT}")"
ZRAM_ALGO="$(read_default "ZRAM compression algo for zram-tools only (auto/lz4/zstd/lzo-rle)" "auto")"
TMP_MB="$(read_default "tmpfs size for /tmp in MB (0 to skip)" "${DEF_TMP_MB}")"
VARTMP_MB="$(read_default "tmpfs size for /var/tmp in MB (0 to skip)" "${DEF_VARTMP_MB}")"
JOURNAL_CAP_MB="$(read_default "journald persistent cap in MB (SystemMaxUse)" "${DEF_JOURNAL_CAP_MB}")"

numeric_or_die "$ZRAM_PCT" "ZRAM %"
numeric_or_die "$TMP_MB" "tmpfs /tmp MB"
numeric_or_die "$VARTMP_MB" "tmpfs /var/tmp MB"
numeric_or_die "$JOURNAL_CAP_MB" "journald cap MB"

# Sizing warnings (not fatal)
if (( TMP_MB > (RAM_MB * 60 / 100) )) && (( TMP_MB != 0 )); then warn "/tmp tmpfs >60% of RAM; consider lowering to avoid memory pressure."; fi
if (( VARTMP_MB > (RAM_MB * 60 / 100) )) && (( VARTMP_MB != 0 )); then warn "/var/tmp tmpfs >60% of RAM; consider lowering to avoid memory pressure."; fi

echo
info "Planned changes:"
info "  - Swap: if rpi-swap/systemd-zram-generator present, configure it via /etc/rpi/swap.conf.d (reboot required)."
info "          otherwise install/config zram-tools (zramswap.service)."
info "  - Disable dphys-swapfile disk swap (if present)"
info "  - /tmp tmpfs: ${TMP_MB}M (0 means unchanged)"
info "  - /var/tmp tmpfs: ${VARTMP_MB}M (0 means unchanged)"
info "  - Keep /var/log on disk"
info "  - journald: Storage=persistent, caps: ${JOURNAL_CAP_MB}M"
info "  - Ensure logrotate installed + scheduled"

echo
CONFIRM="$(read_default "Proceed? (yes/no)" "no")"
[[ "$CONFIRM" == "yes" ]] || die "Aborted by user."

echo

# ---- Swap configuration (avoid conflicts) ----
NEED_REBOOT="no"

if detect_rpi_swap_backend; then
  ok "rpi-swap/systemd-zram-generator detected; will not use zram-tools to avoid conflicts."

  disable_conflicting_zramswap

  # Configure desired zram size via rpi-swap drop-in; applies on reboot.
  ZRAM_MIB="$(( (RAM_MB * ZRAM_PCT) / 100 ))"
  (( ZRAM_MIB < 64 )) && ZRAM_MIB=64
  write_rpi_swap_dropin "$ZRAM_MIB"
  NEED_REBOOT="yes"

else
  # No rpi-swap backend detected.
  if zram_swap_active; then
    warn "zram swap is already active, but rpi-swap not detected; leaving existing zram config unchanged to avoid disruption."
  else
    apt_install_if_missing "zram-tools"
    configure_zram_tools "$ZRAM_PCT" "$ZRAM_ALGO" "100"
    start_and_verify_zramswap
  fi
fi

# ---- Disable disk swap (dphys-swapfile only) ----
disable_dphys_swapfile_only

# ---- tmpfs mounts (/tmp, /var/tmp) ----
if (( TMP_MB == 0 )); then
  fstab_remove_managed_line "/tmp"
else
  fstab_upsert_managed_line "/tmp" "tmpfs /tmp tmpfs nosuid,nodev,noatime,mode=1777,size=${TMP_MB}M 0 0  # sdcard_tune"
fi

if (( VARTMP_MB == 0 )); then
  fstab_remove_managed_line "/var/tmp"
else
  fstab_upsert_managed_line "/var/tmp" "tmpfs /var/tmp tmpfs nosuid,nodev,noatime,mode=1777,size=${VARTMP_MB}M 0 0  # sdcard_tune"
fi

# Best-effort mount now (still reboot recommended if changing swap backend)
mount_best_effort "/tmp"
mount_best_effort "/var/tmp"

# If configured in fstab but not active, recommend reboot
if grep -qE '^tmpfs[[:space:]]+/tmp[[:space:]]+tmpfs.*# sdcard_tune' /etc/fstab; then
  [[ "$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)" == "tmpfs" ]] || NEED_REBOOT="yes"
fi
if grep -qE '^tmpfs[[:space:]]+/var/tmp[[:space:]]+tmpfs.*# sdcard_tune' /etc/fstab; then
  [[ "$(findmnt -n -o FSTYPE /var/tmp 2>/dev/null || true)" == "tmpfs" ]] || NEED_REBOOT="yes"
fi

# ---- journald persistent + capped ----
write_journald_dropin_persistent_capped "$JOURNAL_CAP_MB"
ensure_persistent_journal_dir
restart_and_verify_journald

# ---- logrotate ----
ensure_logrotate_active

ok "Apply complete."

# ---- readiness checks ----
run_readiness_checks || true

echo
if [[ "$NEED_REBOOT" == "yes" ]]; then
  warn "Reboot recommended (swap generator config and/or boot-time validation)."
  REB="$(read_default "Reboot now? (yes/no)" "no")"
  if [[ "$REB" == "yes" ]]; then
    info "Rebooting now. After reboot, run:"
    info "  sudo bash $0 --verify"
    reboot
  else
    info "After reboot, run:"
    info "  sudo bash $0 --verify"
  fi
else
  info "If you want to validate boot-time behavior anyway, reboot and run:"
  info "  sudo bash $0 --verify"
fi
