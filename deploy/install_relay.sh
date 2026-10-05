#!/usr/bin/env bash
# Install ODIVORA relay service on Ubuntu (a host with a public IP/UDP)
set -euo pipefail

REPO_DIR=${REPO_DIR:-/opt/odivora}
CONTROLL=${CONTROL_BIND:-0.0.0.0:9090}

sudo apt-get update
sudo apt-get install -y python3 python3-venv

cd "$REPO_DIR"
python3 -m venv venv || true
sudo mkdir -p /etc/odivora
sudo cp firmware/relay/odivora-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-relay
echo "Relay control on 0.0.0.0:9090, rendezvous UDP 3478 — check: journalctl -u odivora-relay"
