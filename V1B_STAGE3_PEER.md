# V1B Stage 3: Dynamic Peer Configuration & Tunnel Addressing

## Objective
Implement the minimum mechanism required to authorize a phone as a WireGuard peer
for its selected gateway, allocate collision-free tunnel IPs, and track the peer
lifecycle (authorize → handshake → connected → revoke). This completes the
control-plane side of the V1B data plane; the kernel-level WireGuard config on the
gateway is driven from these coordination endpoints.

## 🔐 Critical Security Principle

> **Private keys never leave the phone or the gateway.**
>
> - The gateway private key stays on the gateway device (see Stage 2).
> - The phone's private key is generated on the phone (`wg genkey`). In demo/test
>   flows the API may mint a client keypair so the endpoint remains usable, but
>   production clients generate their own and submit only the public key.
> - The backend stores: gateway public key, phone peer public key, assigned IP,
>   timestamps, disconnect reason. Nothing else.

## 📁 Files Changed/Created

### 1. `app/gateway/ip_alloc.py` (NEW)
**Deterministic, collision-free tunnel IP allocator.**

- `gateway_tunnel_network(gateway_id)` → `10.<second>.<third>.0/24`
  - `<second>` is 64–127 (from SHA-1 of the gateway ID) to avoid clashes with
    typical LAN `10.0.x`/`10.1.x` ranges.
- `gateway_tunnel_ip(gateway_id)` → first host (`.1`), held by the gateway.
- `allocate_tunnel_ip(db, gateway)` → first free `.2+` address not held by any
  **active** session (requested|authorized|connecting|connected).

Properties:
| Property | Guarantee |
|----------|-----------|
| Collision between two active peers | ❌ Impossible (allocator excludes in-use IPs) |
| Peer reusing gateway's `.1` | ❌ Impossible (`.1` pre-marked used) |
| Same IP served to two gateways | ✅ Allowed — each gateway has its own /24 |
| Freed IP reused after revoke/expire | ✅ Yes (non-active sessions don't count) |
| Exhaustion | RuntimeError if /24 full (254 concurrent peers per gateway) |

### 2. `app/routers/sessions_wg.py` (REWRITTEN)
**Per-session WireGuard peer lifecycle endpoints.**

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/sessions/{id}/authorize-wg` | Authorize phone as WG peer; returns peer config incl. allocated IP |
| `POST /api/v1/sessions/{id}/handshake` | Mark session CONNECTED on first WG handshake |
| `POST /api/v1/sessions/{id}/revoke-wg` | Revoke peer, stamp reason, free the IP |

Fixes vs. the placeholder version:
- `datetime` imported at module scope (`revoke_wg_peer` previously raised `NameError`).
- Broken `os.sys_time()` placeholder removed.
- `session.gateway` attribute access replaced with an explicit query (models have
  no SQLAlchemy `relationship()`s — the old code would have raised `AttributeError`).
- Static `"10.0.0.2"` replaced with real allocator.
- State guards: terminal sessions cannot be re-authorized (409); double
  authorize is rejected (409); double handshake rejected (409).
- `phone_public_key` accepted in request body (real flow); validated as base64
  32-byte X25519 public key; demo keypair only when omitted.
- Structured `SessionEvent` (`peer_created`, `tunnel_connected`, `peer_revoked`)
  + `AuditLog` entries emitted — **no keys, tokens, or secrets logged**.

### 3. `app/models.py` (FIXED)
- `Gateway.wg_private_key` changed `nullable=False` → `nullable=True`.
  The old constraint made every gateway registration fail with
  `NOT NULL constraint failed: gateways.wg_private_key` (broke V1A tests).

### 4. `tests/test_stage3_peer.py` (NEW)
Five scenarios: distinct IP allocation + handshake/revoke lifecycle, freed-IP
reuse, unauthorized-user denial, duplicate-peer rejection, gateway IP vs. peer IP
non-collision.

## 🌐 Addressing Scheme

```text
Per gateway:   10.<a>.<b>.0/24        (a = 64..127, derived from gateway ID)
  .1           gateway tunnel interface (wg0)
  .2 .. .254   phone peers (one per active session)

Phone config (wg-quick):
  [Interface]
  PrivateKey = <phone private key, on phone only>
  Address    = 10.<a>.<b>.N/32
  DNS        = 1.1.1.1            # see DNS section

  [Peer]
  PublicKey  = <gateway public key>
  Endpoint   = <gateway public endpoint or relay>:51820
  AllowedIPs = 0.0.0.0/0          # full tunnel (V1B priority)
  PersistentKeepalive = 25
```

## 🛣️ Gateway Routing & NAT (Linux)

Run on the gateway (Linux, Ethernet to home router via DHCP):

```bash
# 1. Enable forwarding
sysctl -w net.ipv4.ip_forward=1

# 2. Bring up wg0 with the gateway keypair + tunnel IP
wg genkey | tee /etc/wireguard/privatekey | chmod 600 /etc/wireguard/privatekey
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.<a>.<b>.1/24
ListenPort = 51820
PrivateKey = <contents of privatekey>
EOF
wg-quick up wg0

# 3. Add phone peers (from authorize-wg calls; re-sync from Cloud on each event)
wg set wg0 peer <phone_pubkey> allowed-ips 10.<a>.<b>.N/32

# 4. NAT out through the home router interface
iptables -t nat -A POSTROUTING -s 10.<a>.<b>.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

OpenWrt equivalent uses `/etc/config/network` WireGuard sections + firewall
`masq` on the WAN zone. The customer's TP-Link/Tenda router needs **no**
changes: outbound WireGuard/UDP 51820 (or a pre-established hole-punched/relayed
channel) is used, and the router sees only a normal LAN client.

## 🧭 DNS Choice (documented per V1B §11)

- First implementation: **home resolver is pushed to the phone** (the LAN
  router's IP, e.g. `AllowedIPs = 0.0.0.0/0` routes DNS through the tunnel, so
  the router resolves exactly as it does for any home device).
- Alternative: a fixed secure resolver (`1.1.1.1`) if the phone must keep
  working when the home router's DNS is down.
- Requirement enforced: with full tunnel (`AllowedIPs = 0.0.0.0/0`), DNS
  requests cannot leak over mobile data — they ride the tunnel.

## 🔄 Session Lifecycle (V1B interpretation)

```text
REQUESTED ──authorize-wg──▶ AUTHORIZED ──handshake──▶ CONNECTED ──revoke/expire──▶ REVOKED/EXPIRED
                                 │                            │
                                 └──────── unsafe states ─────┘   (no peer config issued,
                                                                     IP not allocated)
```

`CONNECTED` in V1B means the WireGuard/data-plane tunnel has actually been
established (handshake confirmed), not merely control-plane authorization.

## ✅ Testing

```bash
cd C:\wifi_gateway
.\venv\Scripts\python.exe -m pytest tests\test_stage3_peer.py -q   # stage 3
.\venv\Scripts\python.exe -m pytest tests -q                       # full suite (32 passed)
```

## 📸 Verification Checklist

1. `POST /api/v1/sessions/{id}/authorize-wg` returns `assigned_ip`,
   `gateway_public_key`, `client_private_key` (demo only), and **never** a
   gateway private key.
2. Two concurrent sessions on the same gateway get **different** IPs.
3. Revoking a session lets its IP be reused by the next session.
4. `POST /sessions/{id}/handshake` flips status to `connected` and stamps
   `wg_handshake_at`; a second call returns 409.
5. A stranger's token gets 403 on both authorize and revoke.
6. `SessionEvent` rows show `peer_created`/`tunnel_connected`/`peer_revoked`
   with no key material in `detail`.

## 📦 What's Next (Stage 4)

- Gateway-side peer sync daemon (apply `wg set` commands on the gateway when
  sessions change, instead of manual config).
- Connection path: DIRECT vs RELAY abstraction + relay bring-up behind CGNAT.
- NAT traversal (UDP hole punching / keepalive) for home gateways without a
  public IP.
- Bandwidth/latency benchmark procedure of §16.
- Prometheus metrics for tunnel events (currently AuditLog/SessionEvent only).

---

*V1B Stage 3 complete: dynamic peer authorization, collision-free tunnel IP
allocation, and the authorize→handshake→revoke lifecycle are implemented and
tested. The backend coordinates peers; private keys remain on their devices.*
