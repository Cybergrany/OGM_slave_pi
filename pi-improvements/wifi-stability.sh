#!/usr/bin/env bash
set -euo pipefail

# Harden Raspberry Pi Wi-Fi for fixed-location use:
# - disable Wi-Fi powersave
# - disable brcmfmac firmware roaming
# - keep NetworkManager retrying autoconnects indefinitely
#
# Raspberry Pi OS Trixie special handling:
# Raspberry Pi OS Trixie uses a Raspberry Pi-patched NetworkManager/Netplan
# persistence path. On installs where that exact stack is detected, avoid
# per-profile nmcli writes and install a protected Netplan fallback under
# /usr/lib/netplan. The fallback is named 89-* so the normal 90-NM-* profile
# remains authoritative while healthy. Other installs retain the original per-profile behaviour.
#
# Assumes:
# - NetworkManager is in use
# - onboard Wi-Fi is driven by brcmfmac
#
# Notes:
# - On affected Raspberry Pi OS Trixie installs, changes are applied on reboot.
# - On other installs, NetworkManager is restarted so profile changes apply now.
# - brcmfmac roamoff=1 always takes effect on the next boot.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if ! command -v nmcli >/dev/null 2>&1; then
  echo "nmcli not found. This script expects NetworkManager."
  exit 1
fi

atomic_write() {
  local path="$1"
  local mode="$2"
  local dir tmp

  dir="$(dirname "$path")"
  install -d -m 0755 "$dir"
  tmp="$(mktemp "$dir/.wifi-stability.XXXXXX")"

  if ! cat >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi

  chown root:root "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path"
}

RPI_NETPLAN_BASE=""
RPI_NM_VERSION=""

is_affected_rpios_trixie_stack() {
  local VERSION_CODENAME=""
  local base=""
  local nm_version=""

  # Raspberry Pi OS 32-bit may identify as Raspbian while 64-bit may identify
  # simply as Debian. /etc/rpi-issue is therefore used as the Pi OS marker.
  [[ -r /etc/os-release ]] || return 1
  [[ -r /etc/rpi-issue ]] || return 1

  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${VERSION_CODENAME:-}" == "trixie" ]] || return 1
  grep -q '^Raspberry Pi reference ' /etc/rpi-issue || return 1

  command -v netplan >/dev/null 2>&1 || return 1

  # Detect Raspberry Pi OS's shipped Netplan -> NetworkManager integration.
  for base in \
      /usr/lib/netplan/00-network-manager-all.yaml \
      /lib/netplan/00-network-manager-all.yaml; do
    if [[ -s "$base" ]] && \
       grep -Eq '^[[:space:]]*renderer:[[:space:]]*NetworkManager([[:space:]]*#.*)?$' "$base"; then
      RPI_NETPLAN_BASE="$base"
      break
    fi
  done
  [[ -n "$RPI_NETPLAN_BASE" ]] || return 1

  # Fail closed: only enable the workaround for Raspberry Pi's patched NM build.
  command -v dpkg-query >/dev/null 2>&1 || return 1
  nm_version="$(dpkg-query -W -f='${Version}' network-manager 2>/dev/null || true)"
  [[ -n "$nm_version" && "$nm_version" == *'+rpt'* ]] || return 1

  RPI_NM_VERSION="$nm_version"
  return 0
}

find_wifi_netplan_source() {
  local f

  # Prefer the currently-working Raspberry Pi/NetworkManager-generated profile.
  # Its netdef/UUID matches the live connection, and the protected 89-* copy is
  # naturally overridden by the normal 90-NM-* file while that file is healthy.
  if [[ -d /etc/netplan ]]; then
    while IFS= read -r f; do
      if [[ -s "$f" ]] && grep -Eq '^[[:space:]]*wifis:[[:space:]]*$' "$f"; then
        printf '%s\n' "$f"
        return 0
      fi
    done < <(find /etc/netplan -maxdepth 1 -type f -name '90-NM-*.yaml' -print 2>/dev/null | sort)
  fi

  # If the generated profile is already damaged/missing, fall back to Raspberry
  # Pi Imager/cloud-init's original network configuration.
  for f in /boot/firmware/network-config /boot/network-config; do
    if [[ -s "$f" ]] && grep -Eq '^[[:space:]]*wifis:[[:space:]]*$' "$f"; then
      printf '%s\n' "$f"
      return 0
    fi
  done

  # Finally accept another explicit Netplan Wi-Fi definition if present.
  if [[ -d /etc/netplan ]]; then
    while IFS= read -r f; do
      if [[ -s "$f" ]] && grep -Eq '^[[:space:]]*wifis:[[:space:]]*$' "$f"; then
        printf '%s\n' "$f"
        return 0
      fi
    done < <(find /etc/netplan -maxdepth 1 -type f -name '*.yaml' ! -name '90-NM-*.yaml' -print 2>/dev/null | sort)
  fi

  return 1
}

validate_netplan_candidate() {
  local candidate="$1"
  local base="$2"
  local root output

  root="$(mktemp -d)"
  output="$(mktemp)"

  install -d -m 0755 "$root/lib/netplan"
  install -m 0644 "$base" "$root/lib/netplan/00-network-manager-all.yaml"
  install -m 0600 "$candidate" "$root/lib/netplan/89-wifi-stability-fallback.yaml"

  if netplan generate --root-dir "$root" >"$output" 2>&1; then
    rm -rf "$root"
    rm -f "$output"
    return 0
  fi

  echo "netplan validation output:" >&2
  sed 's/^/  /' "$output" >&2 || true
  rm -rf "$root"
  rm -f "$output"
  return 1
}

echo "Writing global NetworkManager Wi-Fi powersave config..."
atomic_write /etc/NetworkManager/conf.d/90-wifi-stability-powersave.conf 0644 <<'NM_POWERSAVE_EOF'
[connection-wifi-stability]
match-device=type:wifi
wifi.powersave=2
NM_POWERSAVE_EOF

echo "Writing brcmfmac roaming config..."
atomic_write /etc/modprobe.d/brcmfmac.conf 0644 <<'BRCMFMAC_EOF'
options brcmfmac roamoff=1
BRCMFMAC_EOF

FALLBACK_TARGET=/usr/lib/netplan/89-wifi-stability-fallback.yaml
AUTOCONNECT_CONFIG=/etc/NetworkManager/conf.d/90-wifi-stability-autoconnect.conf

if is_affected_rpios_trixie_stack; then
  echo "Detected affected Raspberry Pi OS Trixie NetworkManager/Netplan stack."
  echo "  NetworkManager: ${RPI_NM_VERSION}"
  echo "  Netplan base:   ${RPI_NETPLAN_BASE}"
  echo "Using Trixie-safe persistence path (no per-profile nmcli modifications)."

  echo "Writing global infinite autoconnect retry policy..."
  atomic_write "$AUTOCONNECT_CONFIG" 0644 <<'NM_AUTOCONNECT_EOF'
# Managed by wifi-stability.sh for the Raspberry Pi OS Trixie NM/Netplan stack.
[main]
autoconnect-retries-default=0
NM_AUTOCONNECT_EOF

  FALLBACK_SOURCE="$(find_wifi_netplan_source || true)"

  if [[ -n "$FALLBACK_SOURCE" ]]; then
    echo "Preparing persistent Netplan fallback from:"
    echo "  $FALLBACK_SOURCE"

    CANDIDATE="$(mktemp)"
    {
      echo "# Managed by wifi-stability.sh"
      echo "# Raspberry Pi OS Trixie Wi-Fi persistence fallback."
      echo "# Original source: $FALLBACK_SOURCE"
      cat "$FALLBACK_SOURCE"
    } >"$CANDIDATE"
    chmod 0600 "$CANDIDATE"

    if ! validate_netplan_candidate "$CANDIDATE" "$RPI_NETPLAN_BASE"; then
      rm -f "$CANDIDATE"
      echo >&2
      echo "ERROR: candidate fallback did not pass 'netplan generate' validation." >&2
      echo "No fallback was installed." >&2
      exit 1
    fi

    if [[ -f "$FALLBACK_TARGET" ]] && cmp -s "$CANDIDATE" "$FALLBACK_TARGET"; then
      echo "Protected Netplan fallback is already up to date:"
      echo "  $FALLBACK_TARGET"
    else
      atomic_write "$FALLBACK_TARGET" 0600 <"$CANDIDATE"
      echo "Installed protected Netplan fallback:"
      echo "  $FALLBACK_TARGET"
    fi

    rm -f "$CANDIDATE"
  elif [[ -s "$FALLBACK_TARGET" ]] && \
       grep -q '^# Managed by wifi-stability.sh$' "$FALLBACK_TARGET" && \
       grep -Eq '^[[:space:]]*wifis:[[:space:]]*$' "$FALLBACK_TARGET"; then
    echo "No source Netplan Wi-Fi file is currently available, but the previously"
    echo "installed protected fallback is intact:"
    echo "  $FALLBACK_TARGET"
  else
    echo >&2
    echo "ERROR: affected Raspberry Pi OS Trixie stack detected, but no" >&2
    echo "usable Wi-Fi Netplan source was found." >&2
    echo >&2
    echo "Expected one of:" >&2
    echo "  /boot/firmware/network-config" >&2
    echo "  /boot/network-config" >&2
    echo "  a non-empty Wi-Fi YAML under /etc/netplan" >&2
    echo >&2
    echo "Refusing to report success without installing the persistence fallback." >&2
    exit 1
  fi

  echo
  echo "Not restarting NetworkManager on this Trixie stack."
  echo "Reboot once to apply all settings and verify Wi-Fi reconnects:"
  echo "  sudo reboot"
else
  # Keep Trixie-specific mitigation inactive on other Pi/Linux flavours.
  if [[ -f "$AUTOCONNECT_CONFIG" ]] && \
     grep -q '^# Managed by wifi-stability.sh for the Raspberry Pi OS Trixie NM/Netplan stack\.$' \
       "$AUTOCONNECT_CONFIG"; then
    rm -f "$AUTOCONNECT_CONFIG"
  fi

  if [[ -f "$FALLBACK_TARGET" ]] && \
     grep -q '^# Managed by wifi-stability.sh$' "$FALLBACK_TARGET"; then
    rm -f "$FALLBACK_TARGET"
  fi

  # Preserve the original behaviour on unaffected NetworkManager-based installs.
  echo "No affected Raspberry Pi OS Trixie persistence stack detected."
  echo "Using standard per-profile NetworkManager hardening."

  echo "Updating existing Wi-Fi connection profiles..."
  mapfile -t WIFI_PROFILE_UUIDS < <(
    nmcli -t -f UUID,TYPE connection show |
      awk -F: '$2=="802-11-wireless"{print $1}'
  )

  if [[ "${#WIFI_PROFILE_UUIDS[@]}" -eq 0 ]]; then
    echo "No existing Wi-Fi profiles found."
  else
    for uuid in "${WIFI_PROFILE_UUIDS[@]}"; do
      profile_name="$(nmcli -g connection.id connection show "$uuid" 2>/dev/null || printf '%s' "$uuid")"
      echo "  -> $profile_name"
      nmcli connection modify "$uuid" \
        connection.autoconnect yes \
        connection.autoconnect-retries 0 \
        802-11-wireless.powersave 2
    done
  fi

  echo "Restarting NetworkManager..."
  systemctl restart NetworkManager

  echo
  echo "Done."
  echo "Reboot the Pi once to apply brcmfmac roamoff=1:"
  echo "  sudo reboot"
fi
