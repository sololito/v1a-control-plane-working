#!/usr/bin/env bash
# Install ODIVORA Linux gateway firmware on Ubuntu/Debian (the home gateway)
set -euo pipefail

REPO_DIR=${REPO_DIR:-/opt/odivora}

# Autodetect the uplink: interface names vary (eth0/enp0s31f6/ens18/...).
# Defaulting to eth0 makes NAT silently never match.
WAN_IFACE=${WAN_IFACE:-$(ip -o route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')}
if [ -z "${WAN_IFACE}" ]; then
  echo "Could not detect a default-route interface; set WAN_IFACE=... explicitly" >&2
  exit 1
fi
echo "Detected WAN interface: ${WAN_IFACE}"

sudo apt-get update
sudo apt-get install -y wireguard-tools python3 python3-venv iptables

# Persist forwarding without appending a duplicate line on every run.
if ! sysctl -n net.ipv4.ip_forward | grep -qx 1; then
  sudo sysctl -w net.ipv4.ip_forward=1
fi
if ! grep -qx 'net.ipv4.ip_forward=1' /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi

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
