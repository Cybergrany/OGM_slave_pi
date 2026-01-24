#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install_pi.sh must be run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="/opt/OGM_slave_pi"
CONFIG_DIR="/etc/ogm_pi"
CONFIG_FILE="${CONFIG_DIR}/ogm_pi.yaml"
PINMAP_FILE="${CONFIG_DIR}/pinmap.json"

apt-get update
apt-get install -y \
  libmodbus \
  libmodbus-dev \
  python3 \
  python3-venv \
  python3-libgpiod

getent group ogm >/dev/null || groupadd ogm
if ! id -u ogm_pi >/dev/null 2>&1; then
  useradd -r -g ogm -d /nonexistent -s /usr/sbin/nologin ogm_pi
fi
usermod -a -G gpio,dialout ogm_pi

mkdir -p "${TARGET_DIR}"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude '.git' "${ROOT_DIR}/" "${TARGET_DIR}/"
else
  cp -a "${ROOT_DIR}/." "${TARGET_DIR}/"
fi

python3 -m venv "${TARGET_DIR}/.venv"
"${TARGET_DIR}/.venv/bin/pip" install --upgrade pip
"${TARGET_DIR}/.venv/bin/pip" install -r "${TARGET_DIR}/requirements.txt"

mkdir -p "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_FILE}" ]]; then
  cp "${TARGET_DIR}/config/ogm_pi.yaml" "${CONFIG_FILE}"
fi
if [[ ! -f "${PINMAP_FILE}" ]]; then
  echo '{}' > "${PINMAP_FILE}"
fi

cp "${TARGET_DIR}/systemd/ogm_pi.service" /etc/systemd/system/ogm_pi.service
cp "${TARGET_DIR}/systemd/ogm_pi.socket" /etc/systemd/system/ogm_pi.socket

systemctl daemon-reload
systemctl enable --now ogm_pi.socket ogm_pi.service

echo "Installed OGM_slave_pi to ${TARGET_DIR}"
echo "Edit ${CONFIG_FILE} and ${PINMAP_FILE} before using in production."
