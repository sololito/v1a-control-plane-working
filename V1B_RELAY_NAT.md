# V1B NAT Traversal & Relay Fallback (CONCERN.txt)

## Problem Being Fixed

Previously V1B assumed the gateway's WireGuard endpoint is directly
reachable (`Phone ↔ WireGuard ↔ Home Gateway` with no relay). That breaks
whenever **both** peers are behind NAT/CGNAT — i.e. almost every real
deployment. The home gateway cannot accept inbound UDP unless the router
forwards a port, which we explicitly forbid.

## Design (smallest change that makes it actually work)

```text
Phone ─── outbound UDP ──▶  Relay (public UDP service)  ◀── outbound UDP ─── Gateway
                              ▲
                     encrypted-at-the-endpoints only;
                     the relay never decrypts anything
                              │
                     ODIVORA Cloud = control plane only
                     (auth, peers, session state) — never in the data path
```

Connection paths are modelled explicitly:

| `connection_path` | Meaning |
|-------------------|---------|
| `direct` | Phone reaches the gateway's public endpoint directly |
| `relay`  | Both peers reachable only via the relay's UDP pair-forwarder |
| `failed` / session `failed` | No path could be established |
| `unknown` | Not decided yet (set at session creation) |

The decision is made server-side in `POST /sessions/{id}/authorize-wg`:

- Gateway has `ip_metadata.wg_endpoint` (public endpoint known) → **direct**
- Otherwise → **relay** (works behind TP-Link/Tenda NAT and CGNAT)
- User-requested `direct` with no `wg_endpoint` → 409 with a clear error.

## Relay mechanics (per session)

1. Cloud allocates a UDP port pair `(phone_port, gateway_port)` and tells
   the relay (`PUT /session/{id}`). Also returns the pair to the phone in
   the `wg-config` endpoint payload and to the gateway via
   `GET /gateways/{id}/peers`.
2. Phone's WireGuard peer endpoint = `relay:phone_port`.
   Gateway's peer endpoint = `relay:gateway_port`.
3. The relay copies datagrams between the two sockets. Both sides see the
   relay address as the peer endpoint; WireGuard is untouched and stays
   encrypted end-to-end. The relay stores no keys, no payload, no logs.
4. On `revoke-wg`, Cloud frees the pair (`DELETE /session/{id}`) and stops
   forwarding.

Direct-path reachability works without a public IP hint only by chance, so
the first implementation optimizes for **reliability**: relay by default.
Hole-punching DIRECT upgrades are a later optimization; the session model
already carries the `direct|relay` distinction so no rewrite is needed.

## API contract changes

`POST /api/v1/sessions/{id}/authorize-wg` response now also includes:

```json
{
  "connection_path": "relay",
  "relay": {"relay_host": "...", "phone_port": 20000, "gateway_port": 20001,
            "phone_endpoint": "...:20000", "gateway_endpoint": "...:20001"}
}
```

`GET /api/v1/gateways/{id}/peers` rows now include:

```json
{"session_id": "...", "peer_public_key": "...", "allowed_ip": ".../32",
 "status": "authorized", "connection_path": "relay",
 "endpoint": "relay-public:20001", "expires_at": "..."}
```

`GET /api/v1/sessions/{id}/wg-config` builds `[Peer] Endpoint =` from the
session's path: gateway public endpoint for `direct`, relay phone endpoint
for `relay`.

## Relay deployment

The relay is a **separate service** (never the API server), with a public
UDP listener and a control listener:

```bash
sudo apt install -y python3
sudo cp firmware/relay/odivora_relay.py /opt/odivora/firmware/relay/
sudo cp firmware/relay/odivora-relay.service /etc/systemd/system/
sudo systemctl enable --now odivora-relay
```

Set on the API server (`.env`):

```
RELAY_CONTROL_URL=http://<relay-host>:9090
RELAY_PUBLIC_HOST=<relay-public-ip-or-dns>
RELAY_PORT_START=20000
RELAY_PORT_END=20999
```

Requirements on the gateway side are unchanged: no port forwarding, no
static IP, no DDNS, no router config. The gateway opens *outbound* UDP to
the relay, so TP-Link/Tenda NAT and CGNAT both work.

## Security

- Relay sees only WireGuard ciphertext → can't read user traffic.
- Relay control API must be firewalled to the API server's egress IP.
- WireGuard handshake authentication still protects both endpoints.
- Revocation removes peers and frees relay pairs immediately.

## Acceptance test (CONCERN.txt §)

Gateway behind a normal router + phone on mobile data:

1. Phone: `POST /connections` → `authorize-wg` → `wg-config` (Endpoint =
   `<relay>:<phone_port>`), import and connect.
2. Cloud marks session `authorized`, path `relay`.
3. Gateway daemon polls `/peers`, adds peer with `endpoint =
   <relay>:<gateway_port>`.
4. Phone browses internet; egress IP is the **home** public IP.
5. `revoke-wg` → relay pair freed, peer removed from `wg show`, phone
   falls back to mobile data.

## Rollback / migration

- Dev: with `RELAY_CONTROL_URL` empty, allocation is local-only and the
  path is recorded as `relay` without an HTTP call — existing setups keep
  working.
- Prod: point `RELAY_CONTROL_URL` at the relay host; existing sessions
  without `relay_info` keep `connection_path` as before.

## TODOs

- STUN hole-punching "DIRECT upgrade" (rendezvous UDP echo is already in
  `odivora_relay.py`; track public endpoint via heartbeat metadata).
- Relay horizontal scaling (port-pair allocation in Redis).
- UDP bandwidth limiting/abuse controls on the relay.
- QUIC/HTTP-3 relay transport for very restrictive networks.
