# 📖 ODIVORA Complete User Guide

End-to-end operating instructions for the ODIVORA Home Connectivity platform: the
cloud API, the relay, the Linux home gateway, and connecting a phone over WireGuard.

Everything in this guide was executed and verified against a live install on
`192.168.10.159`.

---

## 📑 Table of Contents

1. [How the system works](#1-how-the-system-works)
2. [Prerequisites](#2-prerequisites)
3. [Deploy the server](#3-deploy-the-server)
4. [Install the gateway](#4-install-the-gateway)
5. [Provision the gateway](#5-provision-the-gateway)
6. [Direct vs relay path](#6-direct-vs-relay-path)
7. [Connect a phone](#7-connect-a-phone)
8. [Monitor the tunnel](#8-monitor-the-tunnel)
9. [Revoke a session](#9-revoke-a-session)
10. [Uninstall / reset](#10-uninstall--reset)
11. [Troubleshooting](#11-troubleshooting)
12. [Security notes](#12-security-notes)

---

## 1. How the system works

```
   Phone ──WireGuard──> Home Gateway (wg0) ──NAT/MASQUERADE──> Internet
     │                        │
     │                        └── heartbeat + peer list (every 10s)
     │                                        │
     └──── control plane (HTTPS) ──> Cloud API (control only)
                                              │
                                        Relay (optional)
                                   UDP pair forwarder, never
                                   terminates WireGuard
```

| Component | Unit | Purpose |
|---|---|---|
| Cloud API | `odivora-api` | Accounts, gateways, sessions, peer config, billing |
| Relay | `odivora-relay` | Moves WireGuard ciphertext through NAT |
| Gateway | `odivora-gateway` | Owns `wg0`, NAT, and the real internet connection |

The relay **never decrypts** anything — it forwards opaque UDP datagrams between
the two peers. Your browsing traffic never touches the cloud.

---

## 2. Prerequisites

- Ubuntu with a working network uplink
- `root`/`sudo` access on the gateway host
- `wireguard-tools` and `iptables`
- An account on the ODIVORA cloud

---

## 3. Deploy the server

```bash
cd /opt/odivora
./venv/bin/python -m pytest tests -q          # expect: all tests pass
sudo systemctl start odivora-api odivora-relay
sudo systemctl enable odivora-api odivora-relay
```

Verify:

```bash
curl -s http://127.0.0.1:8000/health
sudo systemctl is-active odivora-api odivora-relay
```

Relevant environment variables in `/opt/odivora/.env`:

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | SQLAlchemy DB URL |
| `JWT_SECRET_KEY` | Signing key for all tokens |
| `RELAY_PUBLIC_HOST` | IP/hostname phones can reach the relay on |
| `GATEWAY_TOKEN_EXPIRE_MINUTES` | Gateway token lifetime (auto-refreshed) |

> ⚠️ Keep `.env` private: `chmod 600` and own it by the service user.

---

## 4. Install the gateway

```bash
cd /opt/odivora
sudo ./deploy/install_gateway.sh
```

The script will:

- Load the `wireguard` kernel module
- Enable IPv4 forwarding **persistently** in `/etc/sysctl.conf`
- Detect your uplink interface automatically (default-route metric) and write
  it to `/etc/odivora/gateway.env` as `WAN_INTERFACE`
- Install `/etc/systemd/system/odivora-gateway.service`
- Enable and start the unit

Verify:

```bash
sudo systemctl is-enabled odivora-gateway
sudo systemctl is-active odivora-gateway
grep WAN_INTERFACE /etc/odivora/gateway.env
```

> The installer is idempotent — re-running it will not duplicate `sysctl` lines.

---

## 5. Provision the gateway

Register the gateway to a cloud account. You need a **user access token**:

```bash
cd /opt/odivora
ACCESS=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"YourPassword"}' \
  | ./venv/bin/python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

Then run the setup script (it registers, claims, fetches keys, and writes
`/etc/odivora/`):

```bash
sudo -E ./venv/bin/python firmware/linux_gateway/setup_gateway.py \
  --api-base http://127.0.0.1:8000
```

This writes:

| File | Contents |
|---|---|
| `/etc/odivora/gateway.env` | Gateway ID, token, API base, WAN interface |
| `/etc/odivora/state.json` | Ed25519 identity, nonce counter, refreshed token |
| `/etc/odivora/wg_private_key` | **Gateway** WireGuard private key, generated on-device and never transmitted (mode `600`) |
| `/etc/wireguard/wg0.conf` | Generated gateway interface config |

The keypair step needs no user access token: the device uploads its own public
key using its gateway token.

Re-provision from scratch at any time:

```bash
sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py --reset
```

### Tell the gateway its public endpoint (optional)

If UDP 51820 is port-forwarded from your router to this host, advertise the
public endpoint so sessions can use the direct path:

```bash
echo "WG_ENDPOINT=203.0.113.7:51820" | sudo tee -a /etc/odivora/gateway.env
sudo systemctl restart odivora-gateway
```

Leave it unset and the gateway is treated as behind NAT and given a relay pair
instead. See [section 6](#6-direct-vs-relay-path).

---

## 6. Direct vs relay path

| Path | When it is used | Endpoint the phone dials |
|---|---|---|
| `direct` | `WG_ENDPOINT` is advertised | your public IP + forwarded UDP port |
| `relay` | Gateway is behind NAT/CGNAT | `RELAY_PUBLIC_HOST:phone_port` |

`POST /api/v1/connections` accepts `"connection_path": "direct" | "relay"`.
If you request `direct` without a declared `WG_ENDPOINT`, the API returns
`409` rather than handing out a tunnel that cannot work.

For `relay`, the authorize response includes:

```json
"relay": {
  "relay_host": "203.0.113.7",
  "phone_port": 20014,
  "gateway_port": 20015
}
```

---

## 7. Connect a phone

### Step 1 — Create a connection session

```bash
API=http://127.0.0.1:8000
GID=<gateway-id from /etc/odivora/gateway.env>

SID=$(curl -s -X POST $API/api/v1/connections \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"gateway_id\":\"$GID\",\"connection_path\":\"relay\"}" \
  | ./venv/bin/python -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "session: $SID"
```

### Step 2 — Authorize the WireGuard peer

```bash
curl -s -X POST $API/api/v1/sessions/$SID/authorize-wg \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" -d '{}'
```

Response (abridged):

```json
{
  "assigned_ip": "10.105.35.2",
  "gateway_tunnel_ip": "10.105.35.1",
  "gateway_public_key": "Q3qFQT3tVORp98bTgii1NZNPIdI696tOhBFbFlfYBh4=",
  "client_private_key": "wEV7Gq5UheS9hUAoasUFbLx0bZQjBLhW0qJQPJrJdVw=",
  "listen_port": 51820,
  "connection_path": "relay",
  "relay": { "phone_endpoint": "203.0.113.7:20014" }
}
```

### Step 3 — Confirm the handshake

```bash
curl -s -X POST $API/api/v1/sessions/$SID/handshake \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" -d '{}'
# {"status":"connected","message":"WireGuard tunnel confirmed connected"}
```

### Step 4 — Configure the phone

Build the WireGuard config. For `direct`, the endpoint is your advertised
`WG_ENDPOINT`; for `relay`, it is `phone_endpoint`:

```ini
[Interface]
PrivateKey = <client_private_key>
Address    = <assigned_ip>/32
DNS       = 1.1.1.1

[Peer]
PublicKey          = <gateway_public_key>
Endpoint           = <phone_endpoint or WG_ENDPOINT>
AllowedIPs         = 0.0.0.0/0
PersistentKeepalive = 15
```

Import this into the WireGuard app on the phone.

> **DNS note:** if a client inherits a `127.0.0.53` (systemd-resolved) resolver
> address, DNS will fail inside the tunnel because that stub listener is
> reachable only from the host's own loopback. Use a real resolver
> (`1.1.1.1` / `8.8.8.8`) or a split-DNS entry for the tunnel.

---

## 8. Monitor the tunnel

```bash
# Gateway interface and peers
sudo wg show wg0

# NAT and forwarding rules (must be exactly one each, not growing)
sudo iptables -t nat -S POSTROUTING | grep MASQUERADE
sudo iptables -S FORWARD | grep wg0

# Agent activity: heartbeat + peer sync
sudo journalctl -u odivora-gateway -f --no-pager
```

Expected agent log lines:

```
[net] wg=wg0 wan=enp0s31f6 tunnel=10.105.35.0/24
[wg] wrote /etc/wireguard/wg0.conf (Address 10.105.35.1/24)
[wg] brought wg0 up
[sync] +1 -0 =0        # one peer added, none removed
[sync] +0 -1 =0        # one peer removed
```

The gateway polls every `SYNC_INTERVAL` seconds (default 10) and re-applies
missing `wg0`, NAT, and forwarding rules. If the gateway token is rejected
(401/403) it silently re-authenticates using its Ed25519 identity and logs:

```
[auth] token rejected (401) — refreshing via Ed25519 challenge
```

If the gateway's nonce counter ever goes stale (e.g. after restoring a backup),
it resumes from the server's counter and logs:

```
[hb] stale nonce — resumed counter at N
```

---

## 9. Revoke a session

```bash
curl -s -X DELETE $API/api/v1/connections/$SID \
  -H "Authorization: Bearer $ACCESS"
# {"ok":true,"status":"revoked"}
```

Within one poll interval the agent removes the peer from `wg0` and the tunnel
immediately stops passing traffic:

```bash
sudo wg show wg0 peers        # expect no peer lines
# phone: ping fails, 100% packet loss
```

---

## 10. Uninstall / reset

```bash
sudo systemctl disable --now odivora-gateway
sudo ip link del wg0 2>/dev/null
sudo rm -f /etc/odivora/gateway.env /etc/odivora/state.json \
           /etc/odivora/wg_private_key /etc/wireguard/wg0.conf
sudo systemctl disable --now odivora-api odivora-relay
```

Remove the gateway from the cloud:

```bash
curl -s -X DELETE $API/api/v1/me/gateways/$GID -H "Authorization: Bearer $ACCESS"
```

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `odivora-gateway` won't start | Missing `GATEWAY_ID`/`GATEWAY_TOKEN` | Re-run `setup_gateway.py` |
| No `wg0` after reboot | Interface not restored | Agent auto-heals; check `[wg] brought wg0 up`. Set `wg-quick@wg0` enabled as a fallback. |
| Phone handshakes but no internet | No NAT, or forwarding disabled | `sudo sysctl -w net.ipv4.ip_forward=1`; check `MASQUERADE` rule exists |
| DNS fails but IPs ping | Client uses `127.0.0.53` resolver | Set `DNS = 1.1.1.1` in the client config |
| `409 direct requires wg_endpoint` | Requested direct without advertising an endpoint | Advertise `WG_ENDPOINT`, or use `relay` |
| `403 session limit reached` | User already has an active session | Revoke the previous session first |
| Rules keep multiplying in iptables | Should not happen | `sudo iptables -t nat -D POSTROUTING ...` then restart; agent is idempotent |
| Gateway token rejected repeatedly | Ed25519 identity lost | Restore `/etc/odivora/state.json`, else re-run `setup_gateway.py --reset` |

Useful logs:

```bash
sudo journalctl -u odivora-gateway -n 50 --no-pager
sudo journalctl -u odivora-api -n 50 --no-pager
sudo journalctl -u odivora-relay -n 50 --no-pager
```

---

## 12. Security notes

- **Gateway private keys never leave the gateway.** The device generates its own
  X25519 keypair in `setup_gateway.py`, keeps the private half in
  `/etc/odivora/wg_private_key` (mode `600`, root-owned directory `700`), and
  uploads only the 44-character public half to
  `POST /api/v1/gateways/{id}/wg-public-key`. There is no private-key column in
  the database at all (removed in migration `006`).
- **The relay cannot read your traffic.** It forwards encrypted UDP blobs only.
- **Gateways auto-heal their token** via an Ed25519 signed challenge, so long
  running installs do not need manual re-pairing.
- **Rotate `JWT_SECRET_KEY`** if it is ever exposed; it signs every user,
  gateway, and session token.

### Upgrading from the old key flow

`POST /gateways/{id}/generate-keys` now returns **410 Gone**. Servers that ran
the earlier code may still hold a WireGuard private key in the database:

```bash
./venv/bin/python - <<'PY'
import sqlite3
c = sqlite3.connect("odivora_home.db")
for line in open("migrations/006_no_wg_private_key.sql"):
    s = line.strip()
    if s.startswith(("ALTER", "CREATE", "UPDATE")):
        try:
            c.execute(s.rstrip(";"))
        except Exception:
            pass
c.commit()
PY
```

This nulls any stored key and drops the column. Then re-key each gateway so its
server-side public key matches the key it actually holds:

```bash
sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py --api-base http://<API_IP>:8000
```

Revoke any active sessions first — re-keying is refused while sessions exist, so
a stolen owner token cannot repoint a live tunnel.