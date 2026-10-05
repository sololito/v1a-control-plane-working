# Ubuntu Deployment Guide — ODIVORA V1B (server, relay, gateway)

## 1. What goes where

You need **three Ubuntu machines** (or one big machine for dev):

| Machine | Role | What to install | Systemd unit |
|---------|------|-----------------|--------------|
| API host | Cloud control plane | `/opt/odivora` server | `odivora-api` |
| Relay host | Public UDP relay (NAT traversal) | `firmware/relay/` | `odivora-relay` |
| Home gateway | Linux/OpenWrt box on home Ethernet | `firmware/linux_gateway/` | `odivora-gateway` |

Everything lives in one repo — only a subset is used per machine.

## 2. Get the code on each Ubuntu machine

```bash
sudo git clone https://github.com/sololito/v1a-control-plane-working.git /opt/odivora
cd /opt/odivora
```

To update later:

```bash
cd /opt/odivora && sudo git pull
```

Required files per machine:

**API host** — `app/`, `migrations/`, `alembic/`, `requirements.txt`, `run_server.py`, `.env.example`, `deploy/`, `firmware/relay/` (not needed), `firmware/linux_gateway/` (not needed). Just copy the whole repo; simplest.

**Relay host** — only `firmware/relay/odivora_relay.py` + the service file are used, but copy the repo too (it's small).

**Gateway** — `app/` (agent imports it), `firmware/linux_gateway/`, `requirements.txt`.

## 3. API host setup

```bash
cd /opt/odivora
sudo bash deploy/install_server.sh
sudo nano .env
```

Minimum `.env` for production-ish:

```
APP_ENV=prod
SECRET_KEY=<64 random chars>
DATABASE_URL=sqlite:///./odivora_home.db        # or postgres+psycopg2://...
RELAY_CONTROL_URL=http://<RELAY_HOST>:9090
RELAY_PUBLIC_HOST=<RELAY_PUBLIC_IP_OR_DNS>
RELAY_PORT_START=20000
RELAY_PORT_END=20999
CORS_ORIGINS=https://your-app
```

Then:

```bash
sudo systemctl restart odivora-api
curl -s http://127.0.0.1:8000/health
```

Put nginx/caddy with TLS in front for HTTPS (`/api/v1` proxy to `127.0.0.1:8000`).

## 4. Relay host setup

```bash
cd /opt/odivora
sudo bash deploy/install_relay.sh
```

Open in the cloud firewall / security group:
- UDP `20000-20999` from anywhere (WireGuard peers)
- UDP `3478` (rendezvous, optional)
- TCP `9090` **restricted to the API host's IP only** (control plane)

## 5. Home gateway setup

```bash
cd /opt/odivora
WAN_IFACE=eth0 sudo bash deploy/install_gateway.sh
sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py \
    --api-base https://<API_HOST>
```

Follow the prompts (pairing code → claim with your user token →
generate-keys with your user token). Then:

```bash
sudo systemctl enable --now odivora-gateway
journalctl -u odivora-gateway -f
```

Expected: `[wg] wrote /etc/wireguard/wg0.conf ...`, then `[sync] +0 -0 =0 peers`.

Verify on the API: gateway shows `online` in
`GET /api/v1/me/gateways`.

## 6. First remote connection test

From a laptop/phone on mobile data/outside the home network:

1. Login → get `access_token`.
2. `GET /api/v1/me/gateways` → copy your `gateway_id`.
3. `POST /api/v1/connections` with `{"gateway_id": "<id>"}`.
4. `POST /api/v1/sessions/<session_id>/authorize-wg` → note
   `connection_path` (`relay` expected behind NAT).
5. `GET /api/v1/sessions/<session_id>/wg-config` → save the config text.
6. `sudo wg-quick up <saved>.conf` → `sudo wg show` should show a peer
   and handshake within ~1 minute.
7. `curl ifconfig.me` → must be the **home** public IP.
8. `POST /api/v1/sessions/<session_id>/handshake` → status `connected`.
9. Revoke: `DELETE /api/v1/connections/<session_id>` → tunnel dies.

On the gateway you should see `[sync] +1 -0 =0 peers` then `-1` after
revocation.

## 7. Firewall checklist

| Host | Open | Note |
|------|------|------|
| API | TCP 443 (nginx), 8000 internal | 443 exposed |
| Relay | UDP 20000-20999, UDP 3478 | TCP 9090 from API only |
| Gateway | none inbound | everything outbound |

## 8. Common issues

- `409 stale nonce` → gateway nonce resynced automatically once; if
  repeating, check that only one daemon runs.
- `Tunnel up but no internet` → `sysctl net.ipv4.ip_forward` and
  `iptables -t nat -L POSTROUTING` on the gateway.
- `cannot reach relay` → check `RELAY_PUBLIC_HOST` matches the relay's
  public IP and UDP 20000-20999 is open.
- `PublicKey/PrivateKey errors` → rerun `setup_gateway.py` generate-keys
  step; keys live in `/etc/odivora/`.

## 9. Rollback

```bash
sudo systemctl disable --now odivora-api odivora-relay odivora-gateway
sudo wg-quick down wg0 || true
```
