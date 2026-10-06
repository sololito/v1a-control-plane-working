# ODIVORA Linux Home Gateway — Install, Provision, Run, Test

This is the **first real V1B data-plane gateway**. It runs on a normal
Linux machine (Ubuntu 22.04/24.04, Debian 12, or an OpenWrt x86-64 box)
plugged into the home router with Ethernet.

It registers itself with the ODIVORA Cloud, keeps an outbound heartbeat,
brings up WireGuard (`wg0`), syncs authorized phone peers from the Cloud,
and NATs their traffic out through the home connection — exactly the
architecture in `Next_phase.txt`.

```
Phone (mobile data)
      │  WireGuard (UDP 51820, outbound from both sides)
      ▼
Linux gateway  ── NAT ──▶  home router  ──▶  home ISP  ──▶  Internet
      ▲
      │ HTTPS (heartbeat, peer sync, config)
  ODIVORA Cloud
```

## 0. Requirements

| Component | Notes |
|-----------|-------|
| Ubuntu 22.04/24.04 or Debian 12 (x86-64 or ARM) | OpenWrt x86-64 also supported (`DEVICE_KIND=openwrt`) |
| Ethernet to the home router | it will get a LAN IP via DHCP |
| `wireguard-tools` | `wg`, `wg-quick` |
| Python 3.10+ | runs the gateway agent |
| Outbound HTTPS to the ODIVORA API | no inbound port-forward on the router |

The home TP-Link/Tenda router needs **nothing** configured.

## 1. Prepare the machine

```bash
sudo apt update
sudo apt install -y wireguard-tools python3 python3-venv git iptables
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

Find your WAN-facing LAN interface (the one plugged into the router):

```bash
ip a
```

Assume it is `eth0` below — substitute yours.

## 2. Get the code and a venv

```bash
sudo mkdir -p /opt/odivora
sudo git clone <your-repo-url> /opt/odivora    # or copy the repo folder
cd /opt/odivora
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt
```

## 3. One-time provisioning

```bash
cd /opt/odivora
sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py \
    --api-base https://<your-api-host>
```

The script will:

1. generate an Ed25519 device identity and `POST /api/v1/gateways/register`
   → prints a **PAIRING CODE**,
2. wait while you claim the gateway from your account:

   ```bash
   curl -X POST https://<api-host>/api/v1/me/gateways/<GATEWAY_ID>/claim \
     -H "Authorization: Bearer <your_user_access_token>" \
     -H "Content-Type: application/json" \
     -d '{"pairing_code": "<PAIRING_CODE>"}'
   ```

3. take the `gateway_token` from the claim response,
4. generate the WireGuard keypair **on the device** and register only the
   public half:

   ```bash
   ./venv/bin/python -c "
   from app.gateway.keypair import generate_wg_keypair, store_wg_private_key_locally
   k = generate_wg_keypair()
   store_wg_private_key_locally(k['private_key'])
   print(k['public_key'])"
   ```

   then upload the printed public key with the gateway token:

   ```bash
   curl -X POST http://<API_IP>:8000/api/v1/gateways/<ID>/wg-public-key \
     -H "Authorization: Bearer <gateway_token>" \
     -H "Content-Type: application/json" \
     -d '{"wg_public_key": "<PUBLIC_KEY>"}'
   ```

   The private key stays in `/etc/odivora/wg_private_key` (`chmod 600`) and is
   never transmitted. `setup_gateway.py` does all of this automatically.
5. write `/etc/odivora/gateway.env` (API base, gateway id/token,
   interface names, sync interval).

Amend `/etc/odivora/gateway.env` if the WAN interface is not `eth0`:

```bash
sudo nano /etc/odivora/gateway.env
# WAN_INTERFACE=eth0
# GATEWAY_TOKEN=...
```

## 4. Start the daemon

```bash
sudo cp firmware/linux_gateway/odivora-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-gateway
sudo journalctl -u odivora-gateway -f
```

Expected first lines:

```
[wg] wrote /etc/wireguard/wg0.conf (Address 10.<a>.<b>.1/24, ...)
[sync] +0 -0 =0 peers
```

## 5. Connect a phone from outside the home

On any device with ODIVORA access (same account that claimed the gateway):

```bash
# 1. create a session to your home gateway
curl -X POST https://<api-host>/api/v1/connections \
  -H "Authorization: Bearer <user_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"gateway_id": "<GATEWAY_ID>"}'

# 2. authorize it as a WireGuard peer
curl -X POST https://<api-host>/api/v1/sessions/<SESSION_ID>/authorize-wg \
  -H "Authorization: Bearer <user_access_token>" -H "Content-Type: application/json" -d '{}'

# 3. download the wg-quick config
curl https://<api-host>/api/v1/sessions/<SESSION_ID>/wg-config \
  -H "Authorization: Bearer <user_access_token>"
```

Import the config into the WireGuard app (or `sudo wg-quick up <file>.conf`
on a laptop on mobile hotspot). On the gateway you should see:

```
[sync] +1 -0 =0 peers
```

Then confirm the handshake from the API and test egress:

```bash
curl -X POST https://<api-host>/api/v1/sessions/<SESSION_ID>/handshake \
  -H "Authorization: Bearer <user_access_token>"
# on the phone: curl ifconfig.me  ->  must equal the HOME connection's public IP
```

## 6. Verify / troubleshoot

| Check | Command |
|-------|---------|
| Daemon running | `systemctl status odivora-gateway` |
| Gateway online in cloud | `curl -s https://<api>/api/v1/me/gateways -H "Authorization: Bearer <token>"` |
| wg0 up | `sudo wg show` |
| NAT rules | `sudo iptables -t nat -L POSTROUTING -v` |
| Heartbeat | last lines of `journalctl -u odivora-gateway` |
| Stale nonce 409 | counter auto-resyncs once; check clock correctness |

Rollback: `sudo systemctl disable --now odivora-gateway`, `sudo wg-quick down wg0`.

## 7. Acceptance test (V1B Definition of Done)

1. Phone on mobile data, tunnel up → `ifconfig.me` shows the home ISP's IP.
2. Kill the session (`DELETE /connections/{id}` or `revoke-wg`) → within
   one sync interval the peer disappears from `wg show` and the phone
   returns to mobile data.
3. Revoke the device/gateway → daemon starts failing with 401, tunnel
   stops being re-established.

If all three pass, V1B's first real remote connection is proven.
