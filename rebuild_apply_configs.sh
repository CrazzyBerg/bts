#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
CONF_DIR="${CONF_DIR:-${PREFIX}/etc/yate}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
STAMP="$(date +%Y%m%d-%H%M%S)"

YATE_DIR="${SCRIPT_DIR}/yate"
YATEBTS_DIR="${SCRIPT_DIR}/yatebts"
YBLADERF_SRC="${YATE_DIR}/conf.d/ybladerf.conf.sample"
YBTS_SRC="${YATEBTS_DIR}/ybts.conf.sample"
SERVICE_FILE="/etc/systemd/system/yate.service"

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

configure_if_needed() {
    local dir="$1"
    cd "$dir"
    if [ ! -f Makefile ]; then
        ./autogen.sh
        ./configure --prefix="$PREFIX"
    fi
}

install_config() {
    local src="$1"
    local dst="$2"
    backup_if_exists "$dst"
    sudo install -m 0644 "$src" "$dst"
    echo "Installed $dst"
}

install_service() {
    backup_if_exists "$SERVICE_FILE"
    sudo tee "$SERVICE_FILE" >/dev/null <<UNIT
[Unit]
Description=Yate
After=network.target

[Service]
Type=simple
User=root
ExecStart=${PREFIX}/bin/yate
Restart=on-failure
Nice=-20
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=80
IOSchedulingClass=realtime
IOSchedulingPriority=0
LimitRTPRIO=95
LimitNICE=-20
LimitMEMLOCK=infinity
StandardOutput=journal
StandardError=append:/var/log/yate.err

[Install]
WantedBy=multi-user.target
UNIT
    sudo touch /var/log/yate.err
    sudo chmod 644 /var/log/yate.err
    sudo systemctl daemon-reload
    echo "Installed $SERVICE_FILE"
}

require_file "$YBLADERF_SRC"
require_file "$YBTS_SRC"

echo "Rebuilding Yate with PREFIX=$PREFIX JOBS=$JOBS"
configure_if_needed "$YATE_DIR"
make -C "$YATE_DIR" -j"$JOBS"
sudo make -C "$YATE_DIR" install-noapi

echo "Rebuilding YateBTS with PREFIX=$PREFIX JOBS=$JOBS"
configure_if_needed "$YATEBTS_DIR"
make -C "$YATEBTS_DIR" -j"$JOBS"
sudo make -C "$YATEBTS_DIR" install

sudo mkdir -p "$CONF_DIR"
install_config "$YBLADERF_SRC" "${CONF_DIR}/ybladerf.conf"
install_config "$YBTS_SRC" "${CONF_DIR}/ybts.conf"
sudo touch "${CONF_DIR}/snmp_data.conf" "${CONF_DIR}/tmsidata.conf"
sudo chown root:yate "${CONF_DIR}"/*.conf 2>/dev/null || true
sudo chmod g+w "${CONF_DIR}"/*.conf 2>/dev/null || true

install_service
sudo ldconfig 2>/dev/null || true

if systemctl is-enabled yate.service >/dev/null 2>&1; then
    sudo systemctl restart yate.service
else
    sudo systemctl restart yate.service || sudo systemctl start yate.service
fi

echo "Done. Active configs:"
echo "  ${CONF_DIR}/ybts.conf"
echo "  ${CONF_DIR}/ybladerf.conf"
