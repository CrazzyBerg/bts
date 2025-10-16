#!/bin/bash

# Check if the script is being run as root (user ID 0)
if [ "$(id -u)" -eq 0 ]; then
    echo "This script must not be run as root. Please run it as a regular user."
    exit 1
fi

# Set variables
script_path=$(pwd)
username=$(id -n -u)
rules_file="/etc/udev/rules.d/90-yate.rules"
install_prefix="/usr/local"

# Install dependencies
sudo apt update
sudo apt install -y libusb-1.0-0-dev libusb-1.0-0 build-essential cmake libncurses5-dev libtecla1 libtecla-dev pkg-config git wget libgsm1-dev autoconf telnet libcurl4-openssl-dev

# Setup yate group
sudo groupadd yate
sudo usermod -a -G yate $username

# Setup bladeRF udev rules
echo 'ATTR{idVendor}=="1d50", ATTR{idProduct}=="6066", MODE="660", GROUP="yate"
ATTR{idVendor}=="2cf0", ATTR{idProduct}=="5250", MODE="660", GROUP="yate"' | sudo tee $rules_file
echo "Rules have been added to $rules_file"

# Reload udev rules
sudo udevadm control --reload-rules && sudo udevadm trigger
echo "udev rules reloaded successfully."

# Install bladeRF
cd $script_path
git clone https://github.com/Nuand/bladeRF.git ./bladeRF
cd bladeRF/host/
mkdir -p build
cd build/
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DINSTALL_UDEV_RULES=ON -DBLADERF_GROUP=yate ../
make -j$(nproc)
sudo make install
sudo ldconfig

# Update bladeRF firmware and FPGA
# *(0.15.3 and 2.4.0 are tested)*
sudo $script_path/update_bladerf.sh

# Install Yate and YateBTS
cd $script_path/yate
./autogen.sh
./configure --prefix="$install_prefix"
make -j$(nproc)
sudo make install-noapi

cd $script_path/yatebts
./autogen.sh
./configure --prefix="$install_prefix"
make -j$(nproc)
sudo make install

sudo ldconfig

sudo touch /usr/local/etc/yate/snmp_data.conf /usr/local/etc/yate/tmsidata.conf

sudo chown root:yate /usr/local/etc/yate/*.conf
sudo chmod g+w /usr/local/etc/yate/*.conf

# Set high exec priority for yate group
echo "@yate hard nice -20
@yate hard rtprio 99" | sudo tee -a /etc/security/limits.conf

# Update nftables
echo "Updating nftables..."
sudo chmod +x $script_path/update_nft.sh
sudo $script_path/update_nft.sh

# Install Yateas a service
read -p "Do you want to install the Yate as a service? (y/n): " service_install
if [[ "$service_install" =~ ^[Yy]$ ]]; then
    cd $script_path
    ./service_install.sh
fi

# Install Yate web application
read -p "Do you want to install the NiPC web application with dependencies (Apache2 and PHP)? (y/n): " nipc_install
if [[ "$nipc_install" =~ ^[Yy]$ ]]; then
    cd $script_path
    ./nipc_install.sh
fi

read -p "Do you want to install pySim for SIM card programming? (y/n): " pysim_install
if [[ "$pysim_install" =~ ^[Yy]$ ]]; then
    cd $script_path
    ./pysim_install.sh
fi

echo "== Installation has been completed successfully =="
echo "David's phone number for audio and echo test is 32843."
echo "Also, try to send an SMS to the Eliza chatbot at 35492."
echo "To telnet to the YateBTS, use the following command: telnet localhost 5038."
echo "To start the without Yate service, use the following command: sudo yate -s."
echo "Base configuration is set for the 900 MHz band, MCC=001, MNC=01. IMSI regex starts with 001."
echo "If you installed Apache2 and PHP 5.6, you can access the NiPC web application at http://{your_local_IP_or_name}/nipc/main.php."
