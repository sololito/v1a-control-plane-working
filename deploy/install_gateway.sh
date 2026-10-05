#!/usr/bin/env bash
# Install ODIVORA Linux gateway firmware on Ubuntu/Debian (the home gateway)
set -euo pipefail

REPO_DIR=${REPO_DIR:-/opt/odivora}
WAN_IFACE=${WAN_IFACE:-eth0}

sudo apt-get update
sudo apt-get install -y wireguard-tools python3 python3-venv iptables
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

cd "$REPO_DIR"
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

if [ -f /etc/odivora/gateway.env ]; then
  sudo sed -i "s/^WAN_INTERFACE=.*/WAN_INTERFACE=${WAN_IFACE}/" /etc/odivora/gateway.env
fi

if [ ! -f /etc/odivora/state.json ]; then
  echo "Run provisioning first:"
  echo "  sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py --api-base https://<API_HOST>"
fi

sudo cp firmware/linux_gateway/odivora-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "When provisioning is done: sudo systemctl enable --now odivora-gateway"
