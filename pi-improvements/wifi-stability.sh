#!/usr/bin/env bash
set -euo pipefail

# Harden Raspberry Pi Wi-Fi for fixed-location use:
# - disable Wi-Fi powersave
# - disable firmware roaming
# - set Wi-Fi autoconnect retries to infinite
#
# Assumes:
# - Raspberry Pi OS using NetworkManager
# - onboard Wi-Fi driven by brcmfmac
#
# Notes:
# - powersave + autoconnect changes apply immediately after NetworkManager restart
# - roamoff=1 is applied on next boot

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if ! command -v nmcli >/dev/null 2>&1; then
  echo "nmcli not found. This script expects NetworkManager."
  exit 1
fi

echo "Writing global NetworkManager Wi-Fi powersave config..."
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/10-wifi-powersave.conf <<'EOF'
[connection-wifi]
match-device=type:wifi
wifi.powersave=2
EOF

echo "Writing brcmfmac roaming config..."
install -d -m 0755 /etc/modprobe.d
cat >/etc/modprobe.d/brcmfmac.conf <<'EOF'
options brcmfmac roamoff=1
EOF

echo "Updating existing Wi-Fi connection profiles..."
mapfile -t WIFI_PROFILES < <(nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="802-11-wireless"{print $1}')

if [[ "${#WIFI_PROFILES[@]}" -eq 0 ]]; then
  echo "No existing Wi-Fi profiles found."
else
  for profile in "${WIFI_PROFILES[@]}"; do
    echo "  -> $profile"
    nmcli connection modify "$profile" \
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