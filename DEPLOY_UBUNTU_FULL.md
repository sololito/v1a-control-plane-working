# ODIVORA V1B — Full Ubuntu Setup Guide (per machine)

This guide assumes **three Ubuntu 22.04/24.04 machines**, or fewer:

| Role | Machine | Bare minimum |
|------|---------|--------------|
| A | Cloud API (control plane) | python3, venv, git |
| B | Relay (UDP forwarder) | python3, venv, git, public UDP |
| C | Home gateway | python3, venv, git, wireguard-tools, iptables |

If you have only two machines, put **B + C together** (functional test) or
**A + B together** (most realistic: gateway sits alone behind NAT).

All commands below are run on the target machine as root or with `sudo`.

---

## 0. Common first step on EVERY machine

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y git python3 python3-venv python3-pip curl
git --version && python3 --version        # sanity check
sudo git clone https://github.com/sololito/v1a-control-plane-working.git /opt/odivora
cd /opt/odivora
python3 -m venv venv
sudo ./venv/bin/pip install --upgrade pip
sudo ./venv/bin/pip install -r requirements.txt
```

That covers **Python + all Python libraries** from `requirements.txt`
(FastAPI, uvicorn, SQLAlchemy, cryptography, pydantic, httpx...).

---

## Machine A — Cloud API (control plane)

```bash
cd /opt/odivora
sudo cp .env.example .env
sudo nano .env
```

Minimum `.env`:

```
APP_ENV=prod
SECRET_KEY=<run: openssl rand -hex 32>
DATABASE_URL=sqlite:///./odivora_home.db
RELAY_CONTROL_URL=http://<MACHINE_B_IP>:9090
RELAY_PUBLIC_HOST=<MACHINE_B_PUBLIC_IP_OR_DNS>
RELAY_PORT_START=20000
RELAY_PORT_END=20999
CORS_ORIGINS=*
```

Apply the DB schema (including 005 V1B):

```bash
./venv/bin/python - <<'PY'
import sqlite3
c = sqlite3.connect("odivora_home.db")
for f in ["migrations/001_init.sql","migrations/002_billing.sql",
          "migrations/003_production.sql","migrations/004_crypto_signalling.sql",
          "migrations/005_v1b_wireguard.sql"]:
    for line in open(f):
        s = line.strip()
        if s.startswith(("ALTER","CREATE")):
            try: c.execute(s.rstrip(";"))
            except Exception: pass
c.commit()
print("schema applied")
PY
```

Install + start the service:

```bash
sudo cp deploy/odivora-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-api
sudo journalctl -u odivora-api -f
curl -s http://127.0.0.1:8000/health          # expect {"status":"ok"}
```

Optional HTTPS front door:

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
# reverse proxy 443 -> 127.0.0.1:8000, then:
sudo certbot --nginx -d api.yourdomain.com
```

Run the smoke test from another terminal:

```bash
./venv/bin/python scripts/e2e_smoke_test.py --api-base http://127.0.0.1:8000
```

---

## Machine B — Relay (UDP pair-forwarder)

```bash
cd /opt/odivora
sudo apt-get install -y python3
sudo cp firmware/relay/odivora-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-relay
sudo journalctl -u odivora-relay -f
ss -lunp | grep -E '3478|9090'            # rendezvous + control up
```

Firewall / security group:

| Port | Purpose | Source |
|------|---------|--------|
| UDP 20000-20999 | WireGuard pairs | any |
| UDP 3478 | rendezvous (STUN-lite), optional | any |
| TCP 9090 | relay control API | **Machine A IP only** |

Quick sanity from Machine A:

```bash
curl -X PUT http://<MACHINE_B_IP>:9090/session/test \
  -H 'Content-Type: application/json' \
  -d '{"phone_port": 20000, "gateway_port": 20001}'
curl -X DELETE http://<MACHINE_B_IP>:9090/session/test
```

---

## Machine C — Home gateway (Linux/OpenWrt)

```bash
sudo apt-get install -y wireguard-tools iptables
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

cd /opt/odivora
sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py \
    --api-base http://<MACHINE_A_IP>:8000
```

Follow the prompts:

1. It prints a **PAIRING CODE**. Claim it from your ODIVORA account:

   ```bash
   curl -X POST http://<MACHINE_A_IP>:8000/api/v1/me/gateways/<GATEWAY_ID>/claim \
     -H "Authorization: Bearer <your_user_access_token>" \
     -H "Content-Type: application/json" \
     -d '{"pairing_code": "<PAIRING_CODE>"}'
   ```

2. Paste the returned `gateway_token` into the setup script.
3. Paste your user access token so it can call `generate-keys`.
4. It writes:
   - `/etc/odivora/state.json` (gateway id, token, nonce counter)
   - `/etc/odivora/wg_private_key` (chmod 600)
   - `/etc/odivora/gateway.env` (API base, gateway id/token, WG/WAN ifaces)

Edit the env file if the WAN iface is not `eth0`:

```bash
sudo nano /etc/odivora/gateway.env
```

Start the gateway service:

```bash
sudo cp firmware/linux_gateway/odivora-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-gateway
sudo journalctl -u odivora-gateway -f
```

You should see:

```
[wg] wrote /etc/wireguard/wg0.conf (Address 10.<a>.<b>.1/24 ...)
[sync] +0 -0 =0 peers
```

Verify WireGuard is listening:

```bash
sudo wg show
ip a show wg0
```

---

## 1. End-to-end test with the real setup

From the phone (or a laptop acting as the phone):

```bash
API=http://<MACHINE_A_IP>:8000
TOKEN=<your_user_access_token>

# session
SID=$(curl -s -X POST $API/api/v1/connections \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"gateway_id": "<GATEWAY_ID>"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# authorize + allocate tunnel IP / relay pair
curl -s -X POST $API/api/v1/sessions/$SID/authorize-wg \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'

# download wg-quick config
curl -s $API/api/v1/sessions/$SID/wg-config \
  -H "Authorization: Bearer $TOKEN" > odivora.conf

# on the phone/laptop:
sudo wg-quick up odivora.conf
sudo wg show                            # endpoint = relay:<phone_port>
curl ifconfig.me                        # must equal home ISP public IP

# confirm state on the cloud
curl -X POST $API/api/v1/sessions/$SID/handshake \
  -H "Authorization: Bearer $TOKEN"

# revoke => tunnel dies, peer removed on gateway
curl -X DELETE $API/api/v1/connections/$SID \
  -H "Authorization: Bearer $TOKEN"
```

On **Machine C** you should now see:

```
[sync] +1 -0 =0 peers     # authorize
[sync] -1 +0 =0 peers     # revoke
```

---

## 2. Update workflow (later)

On any machine after you push new code from Windows:

```bash
cd /opt/odivora
sudo git pull
sudo ./venv/bin/pip install -r requirements.txt
sudo systemctl restart odivora-api          # A
sudo systemctl restart odivora-relay        # B
sudo systemctl restart odivora-gateway      # C
```

## 3. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `register gateway` 500 | DB missing V1B columns → apply `migrations/005_v1b_wireguard.sql` |
| `stale nonce (replay?)` | daemon restarted; it auto-resyncs once. If looping, check only one daemon |
| Phone authorizes but `wg show` empty | gateway daemon not running → `journalctl -u odivora-gateway`; relay control URL wrong in `.env` |
| Tunnel up, no internet | `net.ipv4.ip_forward` off, or iptables NAT missing → `sudo iptables -t nat -L POSTROUTING -v` |
| Cannot reach relay | UDP 20000-20999 blocked, or `RELAY_PUBLIC_HOST` wrong |

## 4. Rollback

```bash
sudo systemctl disable --now odivora-api odivora-relay odivora-gateway
sudo wg-quick down wg0 || true
```
