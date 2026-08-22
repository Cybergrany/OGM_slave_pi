#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# sd_card_improvements.sh
#
# Goals:
# - SD longevity improvements with low runtime risk
# - Optional Raspberry Pi OS read-only root OverlayFS + read-only boot
# - Preserve useful logs without allowing an OverlayFS RAM upper to fill with journals
# - Persistent + capped journald when /var/log is genuinely writable/persistent
# - Volatile + tightly capped journald when /var/log lives inside a RAM overlay
# - Optional bounded-memory remote syslog forwarding for cross-boot forensics
# - tmpfs for /tmp and /var/tmp (optional)
# - Prefer Raspberry Pi OS's native rpi-swap when present; fail loudly on unsupported generic zram-generator setups
# - Explicit maintenance modes for temporarily disabling/restarting OverlayFS across multiple reboots
# - Detect extra persistent mounts and require deliberate OverlayFS opt-in
# - Clear, non-silent output on failures + a run log
#
# Overlay policy:
# - This script intentionally supports Raspberry Pi OS only. Other Linux flavours
#   fail before configuration changes rather than receiving guessed settings.
# - Automatic OverlayFS enablement requires Raspberry Pi OS + raspi-config.
# - If OverlayFS is enabled and /var/log is not on a separate writable filesystem,
#   journald is switched to Storage=volatile and RuntimeMaxUse is capped.
# - Optional remote syslog forwarding keeps cross-boot forensic history without
#   persistent writes to the SD root filesystem.
#
# Usage:
#   sudo bash sd_card_improvements.sh
#   sudo bash sd_card_improvements.sh --verify
#   sudo bash sd_card_improvements.sh --disable-overlayfs-next-boot
#   sudo bash sd_card_improvements.sh --restart-overlayfs

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

yesno_or_die() {
  local v="$1" name="$2"
  [[ "$v" == "yes" || "$v" == "no" ]] || die "${name} must be yes or no (got: ${v})"
}

numeric_or_die() {
  local v="$1" name="$2"
  [[ "$v" =~ ^[0-9]+$ ]] || die "${name} must be a whole number (got: ${v})"
}

validate_host_or_die() {
  local v="$1"
  [[ -z "$v" || "$v" =~ ^[A-Za-z0-9._:-]+$ ]] || \
    die "Remote syslog host contains unsupported characters: ${v}"
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
  if [[ -e "$f" || -L "$f" ]]; then
    # Avoid basename collisions for the handful of managed files by prefixing
    # a path-safe form of the parent directory.
    local parent base safe_parent
    parent="$(dirname "$f")"
    base="$(basename "$f")"
    safe_parent="$(printf '%s' "$parent" | sed 's#^/##; s#/#_#g')"
    cp -a "$f" "$BACKUP_DIR/${safe_parent}_${base}.bak"
  fi
}

atomic_write_from_stdin() {
  local dest="$1" mode="${2:-0644}"
  local dir tmp
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.$(basename "$dest").XXXXXX")"
  cat > "$tmp"
  chmod "$mode" "$tmp"
  chown root:root "$tmp"
  mv -f "$tmp" "$dest"
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

# -------------------- platform / OverlayFS detection --------------------

is_raspberry_pi_os() {
  [[ -f /etc/rpi-issue ]] && return 0

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == "raspbian" ]] && return 0
    [[ "${ID_LIKE:-}" == *raspbian* ]] && return 0
  fi

  return 1
}

overlay_apply_supported() {
  is_raspberry_pi_os && command -v raspi-config >/dev/null 2>&1
}

overlay_active() {
  local rootfs
  rootfs="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"
  [[ "$rootfs" == "overlay" || "$rootfs" == "overlayfs" ]] && return 0
  grep -qw 'boot=overlay' /proc/cmdline 2>/dev/null && return 0
  grep -Eq '(^|[[:space:]])overlayroot=' /proc/cmdline 2>/dev/null && return 0
  return 1
}

overlay_configured() {
  local cmd=""
  for f in /boot/firmware/cmdline.txt /boot/cmdline.txt; do
    if [[ -r "$f" ]]; then
      cmd+=" $(cat "$f" 2>/dev/null || true)"
    fi
  done
  [[ "$cmd" == *"boot=overlay"* || "$cmd" == *"overlayroot="* ]] && return 0
  [[ -f /etc/initramfs-tools/scripts/overlay ]] && return 0
  return 1
}

boot_mountpoint() {
  if mountpoint -q /boot/firmware 2>/dev/null; then
    echo /boot/firmware
  elif mountpoint -q /boot 2>/dev/null; then
    echo /boot
  else
    echo ""
  fi
}

boot_is_readonly() {
  local b opts
  b="$(boot_mountpoint)"
  [[ -n "$b" ]] || return 1
  opts="$(findmnt -n -o OPTIONS "$b" 2>/dev/null || true)"
  [[ ",${opts}," == *,ro,* ]]
}

varlog_is_separate_persistent_fs() {
  local source fstype opts root_mm varlog_mm
  source="$(findmnt -n -T /var/log -o SOURCE 2>/dev/null || true)"
  fstype="$(findmnt -n -T /var/log -o FSTYPE 2>/dev/null || true)"
  opts="$(findmnt -n -T /var/log -o OPTIONS 2>/dev/null || true)"
  root_mm="$(findmnt -n -T / -o MAJ:MIN 2>/dev/null || true)"
  varlog_mm="$(findmnt -n -T /var/log -o MAJ:MIN 2>/dev/null || true)"

  # A separate /var or /var/log filesystem also qualifies. Comparing MAJ:MIN
  # avoids treating a bind mount from the root filesystem as independent storage.
  [[ -n "$source" && -n "$varlog_mm" && "$varlog_mm" != "$root_mm" ]] || return 1
  [[ "$fstype" != "tmpfs" && "$fstype" != "overlay" && "$fstype" != "overlayfs" ]] || return 1
  [[ ",${opts}," == *,rw,* ]] || return 1
  return 0
}

ensure_overlay_module_hint() {
  # Defensive for Raspberry Pi OS kernels/initramfs versions which have had
  # regressions where overlay.ko existed but was not included in the initramfs.
  # Current raspi-config also adds this itself, so this is idempotent.
  mkdir -p /etc/initramfs-tools
  touch /etc/initramfs-tools/modules
  if ! grep -qxF overlay /etc/initramfs-tools/modules; then
    backup_file /etc/initramfs-tools/modules
    echo overlay >> /etc/initramfs-tools/modules
    ok "Added overlay module to /etc/initramfs-tools/modules"
  fi
}


refresh_overlay_initramfs() {
  command -v update-initramfs >/dev/null 2>&1 || {
    warn "update-initramfs not found; relying on raspi-config/package hooks for OverlayFS initramfs handling."
    return 0
  }

  local was_ro="no"
  boot_is_readonly && was_ro="yes"
  boot_remount_rw
  info "Refreshing initramfs so the overlay kernel module is available after kernel/package changes..."
  update-initramfs -u -k all
  sync
  [[ "$was_ro" == "yes" ]] && boot_remount_ro_best_effort
  ok "initramfs refreshed"
}

enable_rpi_overlayfs() {
  overlay_apply_supported || die "Automatic OverlayFS enablement requires Raspberry Pi OS + raspi-config."

  ensure_overlay_module_hint

  info "Enabling Raspberry Pi OS root OverlayFS and boot write-protection via raspi-config..."
  raspi-config nonint do_overlayfs 0
  refresh_overlay_initramfs

  if overlay_configured; then
    ok "OverlayFS configured; reboot required to activate it"
  else
    warn "raspi-config returned success but OverlayFS configuration was not detected. Verify carefully after reboot."
  fi
}


maintenance_marker_path() {
  local b
  b="$(boot_mountpoint)"
  [[ -n "$b" ]] || return 1
  printf '%s\n' "${b}/.sdcard-tune-maintenance"
}

maintenance_marker_present() {
  local f
  f="$(maintenance_marker_path 2>/dev/null || true)"
  [[ -n "$f" && -e "$f" ]]
}

boot_remount_rw() {
  local b
  b="$(boot_mountpoint)"
  [[ -n "$b" ]] || die "Boot partition is not mounted; cannot enter maintenance mode."
  if boot_is_readonly; then
    mount -o remount,rw "$b" || die "Unable to remount ${b} read-write."
  fi
}

boot_remount_ro_best_effort() {
  local b
  b="$(boot_mountpoint)"
  [[ -n "$b" ]] || return 0
  mount -o remount,ro "$b" >/dev/null 2>&1 || true
}

set_maintenance_marker() {
  local marker was_ro="no"
  marker="$(maintenance_marker_path)" || die "Cannot determine maintenance marker path."
  boot_is_readonly && was_ro="yes"
  boot_remount_rw
  : > "$marker"
  # The boot filesystem is normally FAT; do not rely on POSIX chmod semantics here.
  sync
  [[ "$was_ro" == "yes" ]] && boot_remount_ro_best_effort
  ok "Maintenance marker installed: ${marker}"
}

clear_maintenance_marker() {
  local marker was_ro="no"
  marker="$(maintenance_marker_path 2>/dev/null || true)"
  [[ -n "$marker" ]] || return 0
  [[ -e "$marker" ]] || return 0
  boot_is_readonly && was_ro="yes"
  boot_remount_rw
  rm -f "$marker"
  sync
  [[ "$was_ro" == "yes" ]] && boot_remount_ro_best_effort
  ok "Maintenance marker removed"
}

install_maintenance_boot_helper() {
  local helper="/usr/local/sbin/sdcard-tune-maintenance-boot"
  local unit="/etc/systemd/system/sdcard-tune-maintenance-boot.service"

  backup_file "$helper"
  backup_file "$unit"

  atomic_write_from_stdin "$helper" 0755 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

rootfs="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"
if [[ "$rootfs" == "overlay" || "$rootfs" == "overlayfs" ]]; then
  exit 0
fi

for boot in /boot/firmware /boot; do
  marker="${boot}/.sdcard-tune-maintenance"
  if [[ -e "$marker" ]] && mountpoint -q "$boot" 2>/dev/null; then
    mount -o remount,rw "$boot"
    logger -t sdcard-tune "MAINTENANCE MODE: root is writable and ${boot} was remounted read-write; OverlayFS remains disabled until explicitly restarted."
    exit 0
  fi
done

exit 0
EOF

  atomic_write_from_stdin "$unit" 0644 <<'EOF'
[Unit]
Description=SD-card hardening maintenance-mode boot helper
After=local-fs.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sdcard-tune-maintenance-boot

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sdcard-tune-maintenance-boot.service >/dev/null
  ok "Installed persistent OverlayFS maintenance helper"
}

maintenance_helper_installed() {
  [[ -x /usr/local/sbin/sdcard-tune-maintenance-boot ]] &&
    [[ -f /etc/systemd/system/sdcard-tune-maintenance-boot.service ]] &&
    systemctl is-enabled --quiet sdcard-tune-maintenance-boot.service 2>/dev/null
}

list_extra_persistent_mounts() {
  findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | awk '
    function pseudo(fs) {
      return fs ~ /^(proc|sysfs|devtmpfs|devpts|tmpfs|cgroup2?|pstore|debugfs|tracefs|configfs|securityfs|fusectl|mqueue|hugetlbfs|rpc_pipefs|binfmt_misc|overlay|overlayfs|autofs)$/
    }
    {
      target=$1; source=$2; fs=$3
      if (target=="/" || target=="/boot" || target=="/boot/firmware") next
      if (target=="/tmp" || target=="/var/tmp" || target=="/run" || target ~ "^/run/") next
      if (target ~ "^/proc(/|$)" || target ~ "^/sys(/|$)" || target ~ "^/dev(/|$)") next
      if (pseudo(fs)) next
      print
    }
  '
}

have_extra_persistent_mounts() {
  [[ -n "$(list_extra_persistent_mounts)" ]]
}

show_extra_mount_warning() {
  local extra
  extra="$(list_extra_persistent_mounts)"
  [[ -n "$extra" ]] || return 0
  warn "Additional persistent mounts were detected. Raspberry Pi OS OverlayFS has had regressions with unusual/additional mount layouts."
  printf '%s\n' "$extra"
}

enter_overlay_maintenance() {
  overlay_apply_supported || die "Maintenance-mode OverlayFS control requires Raspberry Pi OS + raspi-config."

  if overlay_active && ! maintenance_helper_installed; then
    die "The persistent maintenance helper is not installed. Because root is already overlaid, installing it now would be temporary. Disable OverlayFS manually once, reboot to writable root, rerun this updated script in normal apply mode, then use this command thereafter."
  fi

  if ! overlay_active && ! overlay_configured; then
    # Already on a normal writable root. Make this an explicit maintenance period.
    maintenance_helper_installed || install_maintenance_boot_helper
    set_maintenance_marker
    boot_remount_rw
    ok "OverlayFS is already disabled. System is now in writable maintenance mode."
    info "OverlayFS will stay disabled across reboots until:"
    info "  sudo bash $0 --restart-overlayfs"
    return 0
  fi

  info "Scheduling OverlayFS to be disabled starting with the next boot..."
  raspi-config nonint do_overlayfs 1
  overlay_configured && die "raspi-config returned success but OverlayFS still appears configured."

  set_maintenance_marker

  echo
  ok "Writable maintenance mode is scheduled."
  info "Reboot once. From that boot onward, root will remain writable across further reboots."
  info "The installed helper will remount the boot partition read-write on each maintenance boot."
  info "When maintenance is complete, run:"
  info "  sudo bash $0 --restart-overlayfs"
}

restart_overlay_protection() {
  overlay_apply_supported || die "OverlayFS control requires Raspberry Pi OS + raspi-config."

  if overlay_active; then
    if maintenance_marker_present; then
      clear_maintenance_marker
    fi
    ok "OverlayFS is already active."
    boot_is_readonly && ok "Boot partition is read-only." || warn "Boot partition is not currently read-only."
    return 0
  fi

  local extra=""
  extra="$(list_extra_persistent_mounts)"
  if [[ -n "$extra" ]]; then
    echo
    warn "Extra persistent mounts are present:"
    printf '%s\n' "$extra"
    warn "Re-enabling OverlayFS on unusual mount layouts can have side effects."
    local ans
    ans="$(read_default "Continue and re-enable OverlayFS anyway? (yes/no)" "no")"
    yesno_or_die "$ans" "OverlayFS restart choice"
    [[ "$ans" == "yes" ]] || die "OverlayFS restart aborted."
  fi

  maintenance_helper_installed || install_maintenance_boot_helper
  ensure_overlay_module_hint

  info "Re-enabling Raspberry Pi OS root OverlayFS + boot write-protection for the next boot..."
  raspi-config nonint do_overlayfs 0
  refresh_overlay_initramfs

  overlay_configured || die "raspi-config returned success but OverlayFS configuration was not detected."

  # Keep the maintenance marker until all protection setup succeeds. This way a
  # failed restart attempt remains visibly recoverable instead of silently
  # dropping maintenance mode halfway through.
  clear_maintenance_marker
  sync

  echo
  ok "OverlayFS protection is configured for the next boot."
  info "You may finish any remaining work in this current writable boot."
  info "Then reboot and validate with:"
  info "  sudo bash $0 --verify"
}

# -------------------- fstab helpers --------------------

# Manage only lines that end with "# sdcard_tune"
fstab_upsert_managed_line() {
  local mountpoint="$1"
  local newline="$2"
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
  [[ -f /etc/rpi/swap.conf ]] && return 0
  dpkg -s rpi-swap >/dev/null 2>&1 && return 0
  return 1
}

generic_zram_generator_present() {
  detect_rpi_swap_backend && return 1
  dpkg -s systemd-zram-generator >/dev/null 2>&1 && return 0
  [[ -f /etc/systemd/zram-generator.conf ]] && return 0
  compgen -G '/etc/systemd/zram-generator.conf.d/*.conf' >/dev/null 2>&1 && return 0
  return 1
}

zram_swap_active() {
  swapon --show --noheadings --raw 2>/dev/null | awk '{print $1}' | grep -qE '(^/dev/zram|zram)'
}

disable_conflicting_zramswap() {
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^zramswap\.service'; then
    info "Disabling/masking zramswap.service to avoid conflicts with rpi-swap"
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

  atomic_write_from_stdin "$file" 0644 <<EOF
# Managed by sd_card_improvements.sh
# Force pure zram. rpi-swap's current auto mode uses zram+file, whose file-backed
# writeback is undesirable for SD longevity and unsafe to place inside RAM OverlayFS.
[Main]
Mechanism=zram

[Zram]
MaxSizeMiB=${zram_mib}
FixedSizeMiB=${zram_mib}
EOF

  ok "Wrote rpi-swap drop-in: pure zram, ${zram_mib} MiB virtual capacity (takes effect after reboot)"
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

# -------------------- disk swap disable --------------------

disable_dphys_swapfile_only() {
  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^dphys-swapfile\.service'; then
    local swapfile="/var/swap"

    if [[ -f /etc/dphys-swapfile ]]; then
      backup_file /etc/dphys-swapfile
      local conf
      conf="$(awk -F= '/^\s*CONF_SWAPFILE=/ {gsub(/\"/,"",$2); print $2}' /etc/dphys-swapfile | tail -n1 || true)"
      [[ -n "${conf:-}" ]] && swapfile="$conf"

      if grep -qE '^\s*CONF_SWAPSIZE=' /etc/dphys-swapfile; then
        sed -i -E 's/^\s*CONF_SWAPSIZE=.*/CONF_SWAPSIZE=0/' /etc/dphys-swapfile
      else
        echo 'CONF_SWAPSIZE=0' >> /etc/dphys-swapfile
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

# -------------------- journald --------------------

journal_file_cap_mb() {
  local cap="$1" v
  v=$(( cap / 8 ))
  (( v < 2 )) && v=2
  echo "$v"
}

write_journald_dropin() {
  local mode="$1" system_cap_mb="$2" runtime_cap_mb="$3" forward_to_syslog="$4"
  local dropdir="/etc/systemd/journald.conf.d"
  local dropfile="${dropdir}/99-sdcard-tune.conf"
  local runtime_file_mb system_file_mb

  runtime_file_mb="$(journal_file_cap_mb "$runtime_cap_mb")"
  system_file_mb="$(journal_file_cap_mb "$system_cap_mb")"

  mkdir -p "$dropdir"
  backup_file "$dropfile"

  if [[ "$mode" == "persistent" ]]; then
    atomic_write_from_stdin "$dropfile" 0644 <<EOF
# Managed by sd_card_improvements.sh
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=${system_cap_mb}M
SystemMaxFileSize=${system_file_mb}M
SystemMaxFiles=8
RuntimeMaxUse=${runtime_cap_mb}M
RuntimeMaxFileSize=${runtime_file_mb}M
RuntimeMaxFiles=8
MaxFileSec=1day
ForwardToSyslog=${forward_to_syslog}
EOF
    ok "Configured journald: persistent, SystemMaxUse=${system_cap_mb}M, early/runtime cap=${runtime_cap_mb}M"
  elif [[ "$mode" == "volatile" ]]; then
    atomic_write_from_stdin "$dropfile" 0644 <<EOF
# Managed by sd_card_improvements.sh
[Journal]
Storage=volatile
Compress=yes
RuntimeMaxUse=${runtime_cap_mb}M
RuntimeMaxFileSize=${runtime_file_mb}M
RuntimeMaxFiles=8
MaxFileSec=6h
ForwardToSyslog=${forward_to_syslog}
EOF
    ok "Configured journald: volatile RAM journal, RuntimeMaxUse=${runtime_cap_mb}M"
  else
    die "Unknown journald mode: $mode"
  fi
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

# -------------------- optional remote syslog --------------------

remote_syslog_managed_file() {
  echo /etc/rsyslog.d/00-sdcard-tune-remote.conf
}

configure_remote_syslog() {
  local host="$1" port="$2" queue_size="$3"
  local file
  file="$(remote_syslog_managed_file)"

  apt_install_if_missing rsyslog
  backup_file "$file"

  # Debian/Raspberry Pi OS's rsyslog package normally loads imuxsock in
  # /etc/rsyslog.conf. Do not count our previous managed file when checking,
  # otherwise a re-run could remove the only module(load="imuxsock") line.
  local imux="" have_imux="no" f
  if grep -qsE '(^|[[:space:]])(module\([^)]*load="?imuxsock"?|\$ModLoad[[:space:]]+imuxsock)' /etc/rsyslog.conf 2>/dev/null; then
    have_imux="yes"
  fi
  if [[ "$have_imux" == "no" ]]; then
    for f in /etc/rsyslog.d/*.conf; do
      [[ -e "$f" ]] || continue
      [[ "$f" == "$file" ]] && continue
      if grep -qsE '(^|[[:space:]])(module\([^)]*load="?imuxsock"?|\$ModLoad[[:space:]]+imuxsock)' "$f"; then
        have_imux="yes"
        break
      fi
    done
  fi
  [[ "$have_imux" == "yes" ]] || imux='module(load="imuxsock")'

  atomic_write_from_stdin "$file" 0644 <<EOF
# Managed by sd_card_improvements.sh
#
# Forward the journal/syslog stream to a central collector without using a
# disk queue. The action queue is intentionally small and memory-only: if the
# collector is unavailable for long enough, new forwarded copies are dropped
# instead of allowing a headless Pi to block or exhaust RAM. The local
# journald ring remains available for the current boot.
${imux}
action(
    type="omfwd"
    target="${host}"
    port="${port}"
    protocol="tcp"
    template="RSYSLOG_SyslogProtocol23Format"
    queue.type="LinkedList"
    queue.size="${queue_size}"
    queue.timeoutEnqueue="1"
    action.resumeRetryCount="-1"
    KeepAlive="on"
    KeepAlive.Time="60"
    KeepAlive.Interval="15"
    KeepAlive.Probes="3"
)

# Prevent later default rsyslog rules (for example 50-default.conf) from
# duplicating the same stream into RAM-backed /var/log files under OverlayFS.
stop
EOF

  if ! rsyslogd -N1; then
    die "rsyslog configuration validation failed; see output above."
  fi

  configure_rsyslog_restart_policy
  systemctl enable rsyslog.service >/dev/null 2>&1 || true
  systemctl restart rsyslog.service
  systemctl is-active --quiet rsyslog.service || die "rsyslog failed to start after remote forwarding configuration"

  ok "Remote syslog forwarding configured: tcp://${host}:${port} (memory queue ${queue_size} messages)"
}

remove_managed_remote_syslog() {
  local file
  file="$(remote_syslog_managed_file)"
  if [[ -e "$file" ]]; then
    backup_file "$file"
    rm -f "$file"
    if command -v rsyslogd >/dev/null 2>&1 && systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^rsyslog\.service'; then
      rsyslogd -N1 || die "rsyslog validation failed after removing managed remote config"
      systemctl try-restart rsyslog.service >/dev/null 2>&1 || true
    fi
    ok "Removed previously managed remote-syslog configuration"
  fi
}

rsyslog_service_present() {
  systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^rsyslog\.service'
}


configure_rsyslog_restart_policy() {
  local dir="/etc/systemd/system/rsyslog.service.d"
  local file="${dir}/99-sdcard-tune-restart.conf"
  mkdir -p "$dir"
  backup_file "$file"
  atomic_write_from_stdin "$file" 0644 <<'EOF'
[Service]
Restart=on-failure
RestartSec=5s
EOF
  systemctl daemon-reload
  ok "Configured rsyslog restart-on-failure policy"
}

verify_rsyslog_restart_policy() {
  local rp rs
  rp="$(systemctl show rsyslog.service -p Restart --value 2>/dev/null || true)"
  rs="$(systemctl show rsyslog.service -p RestartUSec --value 2>/dev/null || true)"
  [[ "$rp" == "on-failure" ]] || return 1
  [[ -n "$rs" ]] || return 1
  return 0
}

disable_local_rsyslog() {
  if rsyslog_service_present; then
    systemctl disable --now rsyslog.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet rsyslog.service 2>/dev/null; then
      warn "rsyslog.service is still active after disable request"
      return 1
    fi
    ok "Disabled local rsyslog service; journald remains the bounded current-boot log store"
  else
    ok "rsyslog.service not installed; no traditional local syslog duplication to disable"
  fi
}

# -------------------- logrotate --------------------

ensure_logrotate_active() {
  apt_install_if_missing logrotate

  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^logrotate\.timer'; then
    systemctl enable --now logrotate.timer
    ok "logrotate.timer enabled"
    return 0
  fi

  if [[ -f /etc/cron.daily/logrotate ]]; then
    chmod +x /etc/cron.daily/logrotate || true
    ok "logrotate scheduled via /etc/cron.daily/logrotate"
  else
    warn "No logrotate.timer and /etc/cron.daily/logrotate missing; logrotate may not run automatically."
  fi

  if systemctl list-unit-files --no-legend 2>/dev/null | grep -qE '^cron\.service'; then
    systemctl enable --now cron.service >/dev/null 2>&1 || true
  fi
}

# -------------------- managed state --------------------

write_state_file() {
  local overlay="$1" journal_mode="$2" runtime_cap="$3" system_cap="$4" remote_host="$5" remote_port="$6" local_rsyslog_disabled="$7"
  local dir=/etc/sdcard-tune file=/etc/sdcard-tune/state.conf
  mkdir -p "$dir"
  backup_file "$file"
  atomic_write_from_stdin "$file" 0644 <<EOF
# Managed by sd_card_improvements.sh
OVERLAY_REQUESTED=${overlay}
JOURNAL_MODE=${journal_mode}
RUNTIME_JOURNAL_CAP_MB=${runtime_cap}
SYSTEM_JOURNAL_CAP_MB=${system_cap}
REMOTE_SYSLOG_HOST=${remote_host}
REMOTE_SYSLOG_PORT=${remote_port}
LOCAL_RSYSLOG_DISABLED=${local_rsyslog_disabled}
EOF
}

state_value() {
  local key="$1" file=/etc/sdcard-tune/state.conf
  [[ -r "$file" ]] || return 0
  awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/, ""); print; exit}' "$file"
}

# -------------------- readiness checks --------------------

kernel_error_scan() {
  dmesg -T 2>/dev/null | egrep -i \
    'mmc[^\n]*(timeout|timed out|crc|fail|error)|I/O error|Buffer I/O error|EXT4-fs[^\n]*(error|warning)|blk_update_request: I/O error' \
    | tail -n 40 || true
}

show_overlay_ram_mounts() {
  echo "Overlay/root mounts:"
  findmnt -n -o TARGET,SOURCE,FSTYPE,OPTIONS / 2>/dev/null || true

  echo "Relevant tmpfs mounts:"
  findmnt -t tmpfs -o TARGET,SOURCE,SIZE,USED,AVAIL,USE% 2>/dev/null | \
    grep -E 'TARGET|/upper|root-rw|/run($|/)|/tmp($|/)|/var/tmp($|/)' || true
}

run_readiness_checks() {
  local phase="${1:-postboot}"
  local failures=0
  local must_reboot="no"
  local expected_overlay expected_journal remote_host local_rsyslog_disabled

  expected_overlay="$(state_value OVERLAY_REQUESTED)"
  expected_journal="$(state_value JOURNAL_MODE)"
  remote_host="$(state_value REMOTE_SYSLOG_HOST)"
  local_rsyslog_disabled="$(state_value LOCAL_RSYSLOG_DISABLED)"

  echo
  echo "=== Pre-production readiness checks ==="

  echo
  echo "[1] fstab sanity: mount -a"
  if mount -a; then ok "mount -a succeeded"; else warn "mount -a failed"; failures=$((failures+1)); fi

  echo
  echo "[2] Managed fstab entries (# sdcard_tune)"
  grep -n 'sdcard_tune' /etc/fstab || true

  echo
  echo "[3] Swap configuration"
  swapon --show || true
  if zram_swap_active; then ok "zram swap present"; else warn "zram swap not present"; failures=$((failures+1)); fi
  if detect_rpi_swap_backend; then ok "Detected Raspberry Pi rpi-swap backend"; else ok "rpi-swap not detected; zram-tools path in use/available"; fi

  echo
  echo "[4] tmpfs mounts"
  local fstype fstype2
  fstype="$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)"
  if [[ "$fstype" == "tmpfs" ]]; then ok "/tmp is tmpfs"; else warn "/tmp is not tmpfs (fstype=${fstype}); reboot may be required"; must_reboot="yes"; fi

  fstype2="$(findmnt -n -o FSTYPE /var/tmp 2>/dev/null || true)"
  if [[ -n "$fstype2" ]]; then
    if [[ "$fstype2" == "tmpfs" ]]; then ok "/var/tmp is tmpfs"; else warn "/var/tmp is not tmpfs (fstype=${fstype2}); reboot may be required"; must_reboot="yes"; fi
  fi
  df -h /tmp /var/tmp 2>/dev/null || true

  echo
  echo "[5] journald storage + cap"
  if [[ -f /etc/systemd/journald.conf.d/99-sdcard-tune.conf ]]; then
    ok "journald drop-in present"
    grep -E '^(Storage|SystemMaxUse|RuntimeMaxUse|ForwardToSyslog)=' /etc/systemd/journald.conf.d/99-sdcard-tune.conf || true
  else
    warn "journald drop-in not found"
    failures=$((failures+1))
  fi

  if [[ "$expected_journal" == "volatile" ]]; then
    if grep -q '^Storage=volatile$' /etc/systemd/journald.conf.d/99-sdcard-tune.conf 2>/dev/null; then
      ok "journald configured volatile for OverlayFS"
    else
      warn "Expected volatile journald but config does not say Storage=volatile"
      failures=$((failures+1))
    fi
    du -sh /run/log/journal 2>/dev/null || true
  elif [[ "$expected_journal" == "persistent" ]]; then
    if grep -q '^Storage=persistent$' /etc/systemd/journald.conf.d/99-sdcard-tune.conf 2>/dev/null; then
      ok "journald configured persistent"
    else
      warn "Expected persistent journald but config does not say Storage=persistent"
      failures=$((failures+1))
    fi
  fi
  journalctl --disk-usage || true

  echo
  echo "[6] OverlayFS + boot protection"
  if maintenance_marker_present; then
    if overlay_active; then
      warn "MAINTENANCE MODE is scheduled for the next boot; OverlayFS is still active until reboot."
      must_reboot="yes"
    else
      warn "MAINTENANCE MODE ACTIVE: root filesystem is writable."
      if boot_is_readonly; then
        warn "Boot is still read-only; the maintenance helper should remount it writable. Check sdcard-tune-maintenance-boot.service."
        failures=$((failures+1))
      else
        ok "boot partition is writable for maintenance"
      fi
      info "Protection remains disabled across reboots until:"
      info "  sudo bash $0 --restart-overlayfs"
    fi
  elif [[ "$expected_overlay" == "yes" ]]; then
    if overlay_active; then
      ok "PROTECTED MODE: root OverlayFS is active"
      show_overlay_ram_mounts
    elif [[ "$phase" == "preboot" ]] && overlay_configured; then
      warn "OverlayFS is configured but not active until reboot (expected at this stage)"
      must_reboot="yes"
    else
      warn "OverlayFS was requested but is not active"
      must_reboot="yes"
      failures=$((failures+1))
    fi

    if boot_is_readonly; then
      ok "boot partition is mounted read-only"
    elif [[ "$phase" == "preboot" ]]; then
      warn "boot partition is still writable until reboot/remount (expected at this stage)"
      must_reboot="yes"
    else
      warn "boot partition is not currently read-only"
      failures=$((failures+1))
    fi
  else
    if overlay_active; then
      warn "OverlayFS is active but this script state does not say it was requested"
    else
      ok "root OverlayFS is not active"
    fi
  fi

  echo
  echo "[6b] Extra persistent mounts"
  local extra_mounts
  extra_mounts="$(list_extra_persistent_mounts)"
  if [[ -n "$extra_mounts" ]]; then
    warn "Additional persistent mounts detected:"
    printf '%s\n' "$extra_mounts"
    if overlay_active; then
      warn "Review these mounts carefully with OverlayFS enabled."
    fi
  else
    ok "No unexpected persistent mounts detected"
  fi

  echo
  echo "[7] Remote forensic logging"
  if [[ -n "$remote_host" ]]; then
    if [[ -f "$(remote_syslog_managed_file)" ]] && systemctl is-active --quiet rsyslog.service; then
      ok "rsyslog remote forwarding is configured and service is active"
      rsyslogd -N1 || { warn "rsyslog config validation failed"; failures=$((failures+1)); }
      if grep -q 'KeepAlive="on"' "$(remote_syslog_managed_file)" 2>/dev/null; then
        ok "remote TCP keepalive enabled"
      else
        warn "remote TCP keepalive is not enabled"
        failures=$((failures+1))
      fi
      if verify_rsyslog_restart_policy; then
        ok "rsyslog restart-on-failure policy active"
      else
        warn "rsyslog restart-on-failure policy missing/inactive"
        failures=$((failures+1))
      fi
      info "Send a test with: logger 'sdcard-tune remote test from $(hostname)'"
      info "Receipt must be confirmed on the remote collector."
    else
      warn "Remote syslog expected but rsyslog managed config/service is missing"
      failures=$((failures+1))
    fi
  else
    if [[ "$expected_overlay" == "yes" && "$expected_journal" == "volatile" ]]; then
      warn "No remote collector configured: logs survive only for the current boot."
      if [[ "$local_rsyslog_disabled" == "yes" ]]; then
        if rsyslog_service_present && systemctl is-active --quiet rsyslog.service 2>/dev/null; then
          warn "rsyslog was meant to be disabled but is active; it may create uncapped local text logs in the RAM overlay"
          failures=$((failures+1))
        else
          ok "Traditional local rsyslog file logging is disabled/absent"
        fi
      fi
    else
      ok "No managed remote collector configured"
    fi
  fi

  echo
  echo "[8] logrotate scheduling"
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
  echo "[9] Kernel log scan (high-signal I/O/ext4/mmc errors only)"
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
  if [[ "$must_reboot" == "yes" ]]; then warn "A reboot is recommended/required to validate boot-time behaviour."; fi

  return "$failures"
}

# -------------------- main --------------------

need_root

MODE="apply"
case "${1:-}" in
  "") MODE="apply" ;;
  --verify) MODE="verify" ;;
  --disable-overlayfs-next-boot) MODE="disable-overlay" ;;
  --restart-overlayfs) MODE="restart-overlay" ;;
  *)
    die "Unknown argument: ${1}. Supported: --verify, --disable-overlayfs-next-boot, --restart-overlayfs"
    ;;
esac

# Fail before creating backup/log directories or modifying configuration.
is_raspberry_pi_os || die "Unsupported platform. This script currently supports Raspberry Pi OS only. No changes were made."
overlay_apply_supported || die "raspi-config OverlayFS support is unavailable. This Raspberry Pi OS installation is not supported by this script; no changes were made."
if generic_zram_generator_present; then
  die "Unsupported swap backend: generic systemd-zram-generator detected without Raspberry Pi rpi-swap. This script intentionally does not guess generic zram-generator configuration. No changes were made."
fi

RAM_KB="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
RAM_MB="$((RAM_KB / 1024))"

# Defaults tuned for Pi-class devices including Zero 2 W (512MB).
# Runtime journal limits are deliberately much smaller than the old persistent
# cap because, under OverlayFS, this storage is real RAM (/run).
if (( RAM_MB <= 768 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=64
  DEF_VARTMP_MB=32
  DEF_JOURNAL_CAP_MB=50
  DEF_RUNTIME_JOURNAL_CAP_MB=16
  DEF_REMOTE_QUEUE=1000
elif (( RAM_MB <= 1024 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=128
  DEF_VARTMP_MB=64
  DEF_JOURNAL_CAP_MB=100
  DEF_RUNTIME_JOURNAL_CAP_MB=24
  DEF_REMOTE_QUEUE=1500
elif (( RAM_MB <= 4096 )); then
  DEF_ZRAM_PCT=50
  DEF_TMP_MB=256
  DEF_VARTMP_MB=128
  DEF_JOURNAL_CAP_MB=200
  DEF_RUNTIME_JOURNAL_CAP_MB=64
  DEF_REMOTE_QUEUE=3000
else
  DEF_ZRAM_PCT=25
  DEF_TMP_MB=512
  DEF_VARTMP_MB=256
  DEF_JOURNAL_CAP_MB=300
  DEF_RUNTIME_JOURNAL_CAP_MB=128
  DEF_REMOTE_QUEUE=5000
fi

STAMP="$(ts)"
BACKUP_DIR="/var/backups/sdcard_longevity_tune/${STAMP}"
mkdir -p "$BACKUP_DIR"
LOGFILE="${BACKUP_DIR}/run.log"

exec > >(tee -a "$LOGFILE") 2>&1

trap 'rc=$?; echo; echo "ERROR: command failed (exit=${rc}) at line ${LINENO}: ${BASH_COMMAND}"; echo "Log: ${LOGFILE}"; exit $rc' ERR

info "Detected RAM: ${RAM_MB} MB"
info "Backups: ${BACKUP_DIR}"
info "Log: ${LOGFILE}"
info "Platform: Raspberry Pi OS"
info "Supported Raspberry Pi OS OverlayFS automation: available"

echo

if [[ "$MODE" == "verify" ]]; then
  run_readiness_checks
  exit $?
elif [[ "$MODE" == "disable-overlay" ]]; then
  enter_overlay_maintenance
  exit 0
elif [[ "$MODE" == "restart-overlay" ]]; then
  restart_overlay_protection
  exit 0
fi

if overlay_active; then
  die "Root OverlayFS is already active. Changes made now would be ephemeral. Disable OverlayFS, reboot to the writable root, then run this script again. (--verify is safe while overlay is active.)"
fi

ZRAM_PCT="$(read_default "ZRAM size as % of RAM" "${DEF_ZRAM_PCT}")"
ZRAM_ALGO="$(read_default "ZRAM compression algo for zram-tools only (auto/lz4/zstd/lzo-rle)" "auto")"
TMP_MB="$(read_default "tmpfs size for /tmp in MB (0 to skip)" "${DEF_TMP_MB}")"
VARTMP_MB="$(read_default "tmpfs size for /var/tmp in MB (0 to skip)" "${DEF_VARTMP_MB}")"
JOURNAL_CAP_MB="$(read_default "persistent journald cap in MB (when persistent logging is possible)" "${DEF_JOURNAL_CAP_MB}")"
RUNTIME_JOURNAL_CAP_MB="$(read_default "RAM journald cap in MB (RuntimeMaxUse)" "${DEF_RUNTIME_JOURNAL_CAP_MB}")"

numeric_or_die "$ZRAM_PCT" "ZRAM %"
numeric_or_die "$TMP_MB" "tmpfs /tmp MB"
numeric_or_die "$VARTMP_MB" "tmpfs /var/tmp MB"
numeric_or_die "$JOURNAL_CAP_MB" "persistent journald cap MB"
numeric_or_die "$RUNTIME_JOURNAL_CAP_MB" "runtime journald cap MB"

if (( TMP_MB > (RAM_MB * 60 / 100) )) && (( TMP_MB != 0 )); then warn "/tmp tmpfs >60% of RAM; consider lowering it."; fi
if (( VARTMP_MB > (RAM_MB * 60 / 100) )) && (( VARTMP_MB != 0 )); then warn "/var/tmp tmpfs >60% of RAM; consider lowering it."; fi
if (( RUNTIME_JOURNAL_CAP_MB > (RAM_MB * 15 / 100) )); then warn "Runtime journal cap is >15% of RAM; consider lowering it on small Pis."; fi

OVERLAY_ENABLE="no"
EXTRA_MOUNTS="$(list_extra_persistent_mounts)"
OVERLAY_DEFAULT="yes"
if [[ -n "$EXTRA_MOUNTS" ]]; then
  echo
  warn "Extra persistent mounts detected:"
  printf '%s\n' "$EXTRA_MOUNTS"
  warn "OverlayFS defaults to NO for unusual mount layouts."
  OVERLAY_DEFAULT="no"
fi

OVERLAY_ENABLE="$(read_default "Enable Raspberry Pi OS read-only root OverlayFS + read-only boot? (yes/no)" "$OVERLAY_DEFAULT")"
yesno_or_die "$OVERLAY_ENABLE" "OverlayFS choice"

if [[ "$OVERLAY_ENABLE" == "yes" && -n "$EXTRA_MOUNTS" ]]; then
  warn "You explicitly selected OverlayFS despite extra persistent mounts."
  OVERLAY_OVERRIDE="$(read_default "Confirm OverlayFS enablement on this unusual layout? (yes/no)" "no")"
  yesno_or_die "$OVERLAY_OVERRIDE" "OverlayFS extra-mount confirmation"
  [[ "$OVERLAY_OVERRIDE" == "yes" ]] || OVERLAY_ENABLE="no"
fi

JOURNAL_MODE="persistent"
REMOTE_SYSLOG_HOST=""
REMOTE_SYSLOG_PORT="514"
REMOTE_QUEUE_SIZE="$DEF_REMOTE_QUEUE"
DISABLE_LOCAL_RSYSLOG="no"
VARLOG_SEPARATE="no"

if varlog_is_separate_persistent_fs; then
  VARLOG_SEPARATE="yes"
fi

if [[ "$OVERLAY_ENABLE" == "yes" ]]; then
  if [[ "$VARLOG_SEPARATE" == "yes" ]]; then
    JOURNAL_MODE="persistent"
    ok "/var/log is on a separate writable filesystem; local persistent journald can survive OverlayFS reboots."
  else
    JOURNAL_MODE="volatile"
    warn "/var/log is part of the root filesystem. Under OverlayFS it will be RAM-backed and cannot provide cross-boot persistence."
    warn "Local journald will therefore be Storage=volatile and capped at ${RUNTIME_JOURNAL_CAP_MB}M."

    REMOTE_SYSLOG_HOST="$(read_default "Remote syslog host/IP for cross-boot forensic logs (blank = none)" "")"
    validate_host_or_die "$REMOTE_SYSLOG_HOST"

    if [[ -n "$REMOTE_SYSLOG_HOST" ]]; then
      REMOTE_SYSLOG_PORT="$(read_default "Remote syslog TCP port" "514")"
      numeric_or_die "$REMOTE_SYSLOG_PORT" "remote syslog port"
      (( REMOTE_SYSLOG_PORT >= 1 && REMOTE_SYSLOG_PORT <= 65535 )) || die "Remote syslog port must be 1..65535"
      REMOTE_QUEUE_SIZE="$(read_default "Remote syslog in-RAM queue size (messages)" "$DEF_REMOTE_QUEUE")"
      numeric_or_die "$REMOTE_QUEUE_SIZE" "remote syslog queue size"
      (( REMOTE_QUEUE_SIZE >= 1 )) || die "Remote syslog queue size must be at least 1"
    else
      echo
      warn "WITHOUT A REMOTE COLLECTOR, JOURNAL HISTORY WILL DISAPPEAR AT EVERY REBOOT/POWER LOSS."
      warn "You will still have a bounded journal for the current boot, but not the previous boot that may explain a failure."
      KEEP_OVERLAY="$(read_default "Continue with OverlayFS and current-boot-only logs? (yes/no)" "no")"
      yesno_or_die "$KEEP_OVERLAY" "volatile-only logging choice"
      if [[ "$KEEP_OVERLAY" != "yes" ]]; then
        info "OverlayFS disabled for this run so local persistent logs are retained."
        OVERLAY_ENABLE="no"
        JOURNAL_MODE="persistent"
      else
        if rsyslog_service_present; then
          DISABLE_LOCAL_RSYSLOG="$(read_default "Disable traditional local rsyslog file logging under OverlayFS? (yes/no)" "yes")"
          yesno_or_die "$DISABLE_LOCAL_RSYSLOG" "local rsyslog choice"
          if [[ "$DISABLE_LOCAL_RSYSLOG" != "yes" ]]; then
            warn "Leaving rsyslog active may create /var/log text files outside journald's RuntimeMaxUse cap."
          fi
        fi
      fi
    fi
  fi
fi

FORWARD_TO_SYSLOG="no"
[[ -n "$REMOTE_SYSLOG_HOST" ]] && FORWARD_TO_SYSLOG="yes"

echo
info "Planned changes:"
info "  - Swap: use Raspberry Pi rpi-swap when present; otherwise zram-tools"
info "  - Disable dphys-swapfile disk swap (important for RAM-backed OverlayFS)"
info "  - /tmp tmpfs: ${TMP_MB}M (0 means unchanged)"
info "  - /var/tmp tmpfs: ${VARTMP_MB}M (0 means unchanged)"
info "  - journald mode: ${JOURNAL_MODE}"
if [[ "$JOURNAL_MODE" == "persistent" ]]; then
  info "      persistent cap: ${JOURNAL_CAP_MB}M; early/runtime cap: ${RUNTIME_JOURNAL_CAP_MB}M"
else
  info "      RAM cap: ${RUNTIME_JOURNAL_CAP_MB}M; no local cross-boot journal"
fi
if [[ -n "$REMOTE_SYSLOG_HOST" ]]; then
  info "  - Remote forensic log copy: tcp://${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}"
  info "      bounded memory queue: ${REMOTE_QUEUE_SIZE} messages; no disk spool"
  info "      managed rsyslog rule stops later local rsyslog file duplication"
else
  info "  - Remote forensic log copy: none"
  if [[ "$OVERLAY_ENABLE" == "yes" && "$JOURNAL_MODE" == "volatile" ]]; then
    if [[ "$DISABLE_LOCAL_RSYSLOG" == "yes" ]]; then
      info "  - Traditional local rsyslog file logging: DISABLE (prevents uncapped RAM-overlay logs)"
    else
      info "  - Traditional local rsyslog file logging: unchanged"
    fi
  fi
fi
info "  - logrotate installed + scheduled (for direct-to-file application logs)"
if [[ "$OVERLAY_ENABLE" == "yes" ]]; then
  info "  - Raspberry Pi OS root OverlayFS: ENABLE"
  info "  - Boot partition write protection: ENABLE"
  info "  - Root/boot changes made after reboot will disappear / be rejected until OverlayFS is disabled for maintenance"
else
  info "  - Root OverlayFS: unchanged/disabled by this script"
fi

echo
CONFIRM="$(read_default "Proceed? (yes/no)" "no")"
yesno_or_die "$CONFIRM" "Proceed choice"
[[ "$CONFIRM" == "yes" ]] || die "Aborted by user."

echo

NEED_REBOOT="no"

# ---- Swap configuration ----
if detect_rpi_swap_backend; then
  ok "Raspberry Pi rpi-swap detected; will not use zram-tools to avoid conflicts."
  disable_conflicting_zramswap

  ZRAM_MIB="$(( (RAM_MB * ZRAM_PCT) / 100 ))"
  (( ZRAM_MIB < 64 )) && ZRAM_MIB=64
  write_rpi_swap_dropin "$ZRAM_MIB"
  NEED_REBOOT="yes"
else
  if zram_swap_active; then
    warn "zram swap is already active, but rpi-swap not detected; leaving existing zram config unchanged to avoid disruption."
  else
    apt_install_if_missing zram-tools
    configure_zram_tools "$ZRAM_PCT" "$ZRAM_ALGO" "100"
    start_and_verify_zramswap
  fi
fi

# ---- Disable disk swap ----
disable_dphys_swapfile_only

# ---- tmpfs mounts ----
if (( TMP_MB == 0 )); then
  fstab_remove_managed_line /tmp
else
  fstab_upsert_managed_line /tmp "tmpfs /tmp tmpfs nosuid,nodev,noatime,mode=1777,size=${TMP_MB}M 0 0  # sdcard_tune"
fi

if (( VARTMP_MB == 0 )); then
  fstab_remove_managed_line /var/tmp
else
  fstab_upsert_managed_line /var/tmp "tmpfs /var/tmp tmpfs nosuid,nodev,noatime,mode=1777,size=${VARTMP_MB}M 0 0  # sdcard_tune"
fi

mount_best_effort /tmp
mount_best_effort /var/tmp

if grep -qE '^tmpfs[[:space:]]+/tmp[[:space:]]+tmpfs.*# sdcard_tune' /etc/fstab; then
  [[ "$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)" == "tmpfs" ]] || NEED_REBOOT="yes"
fi
if grep -qE '^tmpfs[[:space:]]+/var/tmp[[:space:]]+tmpfs.*# sdcard_tune' /etc/fstab; then
  [[ "$(findmnt -n -o FSTYPE /var/tmp 2>/dev/null || true)" == "tmpfs" ]] || NEED_REBOOT="yes"
fi

# ---- Remote syslog first, then journald forwarding ----
if [[ -n "$REMOTE_SYSLOG_HOST" ]]; then
  configure_remote_syslog "$REMOTE_SYSLOG_HOST" "$REMOTE_SYSLOG_PORT" "$REMOTE_QUEUE_SIZE"
else
  remove_managed_remote_syslog
  if [[ "$OVERLAY_ENABLE" == "yes" && "$JOURNAL_MODE" == "volatile" && "$DISABLE_LOCAL_RSYSLOG" == "yes" ]]; then
    disable_local_rsyslog
  elif [[ "$OVERLAY_ENABLE" == "yes" && "$JOURNAL_MODE" == "volatile" ]] && rsyslog_service_present && systemctl is-active --quiet rsyslog.service 2>/dev/null; then
    warn "rsyslog.service remains active; traditional /var/log files are not bounded by journald RuntimeMaxUse."
  fi
fi

# ---- journald ----
write_journald_dropin "$JOURNAL_MODE" "$JOURNAL_CAP_MB" "$RUNTIME_JOURNAL_CAP_MB" "$FORWARD_TO_SYSLOG"
if [[ "$JOURNAL_MODE" == "persistent" ]]; then
  ensure_persistent_journal_dir
fi
restart_and_verify_journald

# ---- logrotate ----
ensure_logrotate_active

# ---- persistent maintenance helper ----
install_maintenance_boot_helper

# ---- persistent script state before root becomes immutable ----
write_state_file "$OVERLAY_ENABLE" "$JOURNAL_MODE" "$RUNTIME_JOURNAL_CAP_MB" "$JOURNAL_CAP_MB" "$REMOTE_SYSLOG_HOST" "$REMOTE_SYSLOG_PORT" "$DISABLE_LOCAL_RSYSLOG"

# ---- Enable OverlayFS last, after every persistent change has been made ----
if [[ "$OVERLAY_ENABLE" == "yes" ]]; then
  enable_rpi_overlayfs
  NEED_REBOOT="yes"
fi

ok "Apply complete."

# ---- readiness checks ----
# Before the first reboot, OverlayFS/boot-ro are expected to show as not yet active.
run_readiness_checks preboot || true

echo
if [[ "$NEED_REBOOT" == "yes" ]]; then
  warn "Reboot required/recommended for OverlayFS, boot protection, swap generator config, and boot-time validation."
  REB="$(read_default "Reboot now? (yes/no)" "no")"
  yesno_or_die "$REB" "Reboot choice"
  if [[ "$REB" == "yes" ]]; then
    info "Rebooting now. After reboot, run:"
    info "  sudo bash $0 --verify"
    sync
    reboot
  else
    info "After reboot, run:"
    info "  sudo bash $0 --verify"
  fi
else
  info "If you want to validate boot-time behaviour anyway, reboot and run:"
  info "  sudo bash $0 --verify"
fi
