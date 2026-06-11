#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
CONF_DIR="${CONF_DIR:-${PREFIX}/etc/yate}"
RESTART_YATE="${RESTART_YATE:-yes}"
STAMP="$(date +%Y%m%d-%H%M%S)"

YBTS_SRC="${SCRIPT_DIR}/yatebts/ybts.conf.sample"
YBLADERF_SRC="${SCRIPT_DIR}/yate/conf.d/ybladerf.conf.sample"

require_file() {
    if [ ! -f "$1" ]; then
        echo "Missing required file: $1" >&2
        exit 1
    fi
}

backup_if_exists() {
    local path="$1"
    if [ -f "$path" ]; then
        sudo cp -a "$path" "${path}.bak.${STAMP}"
        echo "Backed up $path -> ${path}.bak.${STAMP}"
    fi
}

install_config() {
    local src="$1"
    local dst="$2"
    backup_if_exists "$dst"
    sudo install -m 0644 "$src" "$dst"
    echo "Installed $dst"
}

require_file "$YBTS_SRC"
require_file "$YBLADERF_SRC"

sudo mkdir -p "$CONF_DIR"
install_config "$YBTS_SRC" "${CONF_DIR}/ybts.conf"
install_config "$YBLADERF_SRC" "${CONF_DIR}/ybladerf.conf"

sudo touch "${CONF_DIR}/snmp_data.conf" "${CONF_DIR}/tmsidata.conf"
sudo chown root:yate "${CONF_DIR}"/*.conf 2>/dev/null || true
sudo chmod g+w "${CONF_DIR}"/*.conf 2>/dev/null || true

if [ "$RESTART_YATE" = "yes" ]; then
    sudo systemctl restart yate.service
    echo "Restarted yate.service"
else
    echo "Skipped yate.service restart"
fi

echo "Done. Active configs:"
echo "  ${CONF_DIR}/ybts.conf"
echo "  ${CONF_DIR}/ybladerf.conf"
