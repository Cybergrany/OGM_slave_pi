#!/usr/bin/env bash
# rpi-disable-popups.sh
# Disables desktop popup notifications on Raspberry Pi OS “most flavors”:
# - Bookworm Wayland (wf-panel-pi): sets [panel] notify_enable=false
# - Bullseye/Buster X11 (lxpanel): sets notifications=0 in panel config
# - Fallback: disables common notification daemons via ~/.config/autostart overrides
#
# Usage:
#   ./rpi-disable-popups.sh          # disable
#   ./rpi-disable-popups.sh enable   # re-enable

set -euo pipefail

MODE="${1:-disable}"

have() { command -v "$1" >/dev/null 2>&1; }
running() { pgrep -x "$1" >/dev/null 2>&1; }

backup_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  local bdir="$HOME/.config/rpi-disable-popups-backups"
  mkdir -p "$bdir"
  cp -a "$f" "$bdir/$(basename "$f").$(date +%Y%m%d-%H%M%S).bak"
}

# Set key=value inside a named INI section (create section if missing).
set_ini_key_in_section() {
  local file="$1" section="$2" key="$3" value="$4"
  mkdir -p "$(dirname "$file")"
  [ -f "$file" ] || printf '[%s]\n' "$section" >"$file"
  backup_file "$file"

  local tmp; tmp="$(mktemp)"
  awk -v section="$section" -v key="$key" -v value="$value" '
    BEGIN { in=0; done=0 }
    function emit_if_needed() { if(in && !done) { print key"="value; done=1 } }
    /^\[[^]]+\]/ {
      emit_if_needed()
      in = ($0 == "["section"]")
      print
      next
    }
    {
      if(in && $0 ~ "^[[:space:]]*"key"[[:space:]]*=") {
        if(!done) { print key"="value; done=1 }
        next
      }
      print
    }
    END {
      emit_if_needed()
      if(!done) {
        if(!in) { print ""; print "["section"]" }
        print key"="value
      }
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

disable_wf_panel() {
  local val="$1" # true/false
  # Common locations across Bookworm revisions
  local files=(
    "$HOME/.config/wf-panel-pi.ini"
    "$HOME/.config/wf-panel-pi/wf-panel-pi.ini"
  )
  local did=0
  for f in "${files[@]}"; do
    if [ -f "$f" ] || running wf-panel-pi; then
      set_ini_key_in_section "$f" "panel" "notify_enable" "$val"
      did=1
    fi
  done
  return "$did"
}

disable_lxpanel() {
  local val="$1" # 0/1
  local profiles=(LXDE-pi LXDE)
  local did=0

  for p in "${profiles[@]}"; do
    local sys="/etc/xdg/lxpanel/$p/panels/panel"
    local user="$HOME/.config/lxpanel/$p/panels/panel"
    if [ -f "$sys" ] || [ -f "$user" ] || running lxpanel; then
      mkdir -p "$(dirname "$user")"
      if [ ! -f "$user" ] && [ -f "$sys" ]; then
        cp -n "$sys" "$user"
      fi
      if [ -f "$user" ]; then
        backup_file "$user"
        if grep -q '^notifications=' "$user"; then
          sed -i -E "s/^notifications=.*/notifications=$val/" "$user"
        else
          printf '\nnotifications=%s\n' "$val" >>"$user"
        fi
        did=1
      fi
    fi
  done

  return "$did"
}

# Disable common notification daemons by overriding their autostart .desktop entries.
set_autostart_hidden() {
  local name="$1" hidden="$2" # true/false
  local dir="$HOME/.config/autostart"
  local f="$dir/$name"
  mkdir -p "$dir"
  if [ "$hidden" = "true" ]; then
    cat >"$f" <<EOF
[Desktop Entry]
Type=Application
Name=Disabled by rpi-disable-popups
Hidden=true
X-GNOME-Autostart-enabled=false
EOF
  else
    rm -f "$f"
  fi
}

apply_autostart_overrides() {
  local hidden="$1" # true/false
  # Names vary by desktop; these cover most Pi OS installs and common alternates.
  local entries=(
    "lxqt-notificationd.desktop"
    "notification-daemon.desktop"
    "dunst.desktop"
    "mako.desktop"
    "xfce4-notifyd.desktop"
    "mate-notification-daemon.desktop"
  )
  for e in "${entries[@]}"; do
    set_autostart_hidden "$e" "$hidden"
  done
}

restart_bits() {
  # Restart panels/daemons if running (best-effort).
  if running wf-panel-pi; then pkill -x wf-panel-pi || true; fi
  if running lxpanel; then
    if have lxpanelctl; then lxpanelctl restart || true; else pkill -x lxpanel || true; fi
  fi
  for p in dunst mako notification-daemon lxqt-notificationd xfce4-notifyd; do
    if running "$p"; then pkill -x "$p" || true; fi
  done
}

case "$MODE" in
  disable)
    # Wayland Pi Desktop (Bookworm)
    disable_wf_panel "false" >/dev/null 2>&1 || true
    # X11 LXDE (Bullseye/Buster)
    disable_lxpanel "0" >/dev/null 2>&1 || true
    # Fallback across desktops: stop notification daemons from autostarting
    apply_autostart_overrides "true"
    restart_bits
    ;;
  enable)
    disable_wf_panel "true" >/dev/null 2>&1 || true
    disable_lxpanel "1" >/dev/null 2>&1 || true
    apply_autostart_overrides "false"
    restart_bits
    ;;
  *)
    echo "Usage: $0 [disable|enable]" >&2
    exit 2
    ;;
esac