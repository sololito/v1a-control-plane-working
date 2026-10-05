# V1B Stage 4: Gateway Data-Plane Sync, Routing/NAT, Connection Paths

## Objective
Close the loop between Cloud coordination (Stage 3) and the actual gateway
WireGuard interface. The gateway now pulls its authorized peer set from the
Cloud and reconciles the local `wg0` interface, plus ensures IP forwarding and
NAT so remote phones can reach the internet through the home connection.
Connection paths are modelled as DIRECT/RELAY/UNKNOWN without breaking the
existing session state machine.

## 🔐 Security Principle (unchanged)
The daemon handles **no private keys**. It only reads peer public keys and
assigned tunnel IPs from the Cloud, and drives `wg set`. All Cloud→gateway
calls carry the gateway bearer token; the peers endpoint rejects non-gateway
tokens (401) and ID mismatches (403).

## 📁 Files Created/Changed

### 1. `app/routers/gateway_wg.py` — `GET /api/v1/gateways/{id}/peers` (NEW)
Gateway-token authenticated (`get_current_gateway`). Returns only active
sessions (`requested|authorized|connecting|connected`) that have a peer public
key and assigned IP:

```json
{"gateway_id": "...", "peers": [{"session_id": "...", "peer_public_key": "...",
  "allowed_ip": "10.70.3.14/32", "status": "connected", "expires_at": "..."}]}
```

### 2. `app/gateway/dataplane.py` (NEW)
Kernel-touching operations behind a `CommandRunner` protocol:

| Component | Role |
|-----------|------|
| `LinuxDataPlane` | `sysctl net.ipv4.ip_forward=1`, iptables NAT MASQUERADE + forward rules |
| `OpenWrtDataPlane` | same reconcile; uci/firewall-reload NAT hook for OpenWrt (MT7981/MT7986) |
| `SubprocessRunner` / `InMemoryRunner` | real gateway execution / unit-test recorder |
| `sync_peers(desired)` | adds new peers, removes stale ones, keeps the rest; idempotent |

`sync_peers` never touches the gateway's own key material — only peer
public keys + `/32` allowed IPs.

### 3. `app/gateway/daemon.py` (NEW)
Polls `GET /gateways/{id}/peers` every `--interval` seconds, runs
`ensure_forwarding()` + `ensure_nat()` (idempotent), then `sync_peers()`.
Errors are logged and the loop survives (never dies on a transient failure).

```bash
python -m app.gateway.daemon \
  --api-base https://api.odivora.example \
  --gateway-id <uuid> --token <gateway_token> \
  --kind linux --interval 10
```

WebSocket push (already exists at `/ws/gateways/{id}`) is the future trigger;
polling is the reliable baseline.

### 4. `app/paths.py` (NEW)
`plan_connection_path(gateway_online, gateway_has_endpoint, relay_available=False)`:

| Situation | Path |
|-----------|------|
| Online + endpoint hint | `direct` |
| Online, no endpoint, relay exists | `relay` (Phase-2 placeholder) |
| Offline / unknown endpoint | `unknown` |

No relay infrastructure is built; the session model's `connection_path`
(`direct|relay|unknown`) already carries the result unchanged.

### 5. `tests/test_stage4_gateway.py` (NEW)
1. Peers endpoint: gateway-token auth, 401 for user tokens, empty→1→empty
   across authorize/revoke, no private material in payload.
2. Data-plane reconcile: adds missing, removes stale, idempotent second run.
3. Linux NAT/forwarding commands issued.
4. Path planner direct/relay/unknown decisions.

## 🔄 V1B Data-Plane Flow (Stage 4)

```text
Phone ──authorize-wg──▶ Cloud ◀── GET /gateways/{id}/peers ── Gateway daemon
                          ▲                                     │
                          │                              wg set wg0 peer …
                          ▼                                     ▼
                    session state machine              wg0 up + forwarding + NAT
```

## ✅ Verification

```bash
cd C:\wifi_gateway
.\venv\Scripts\python.exe -m pytest tests\test_stage4_gateway.py -q  # 4 passed
.\venv\Scripts\python.exe -m pytest tests -q                         # 36 passed
```

Manual on a real Linux gateway:
1. Start server, register/claim/heartbeat, generate keys.
2. Create session + `authorize-wg` from the phone.
3. Run the daemon; observe `[sync] +1 -0 =0 peers`.
4. `wg show wg0 peers` lists the phone's pubkey with its `/32`.
5. Revoke the session → daemon removes the peer on the next poll.

## 📦 What's Next (Stage 5)

- End-to-end acceptance test on real equipment (§15): phone on mobile data →
  home gateway → home ISP, verify egress IP == home IP.
- CGNAT/relay prototype decision (§12/§13).
- Benchmark procedure + metrics exposure (§16).
- Mobile test client packaging (§18): generated wg-quick config download.

---

*V1B Stage 4 complete: gateway daemon reconciles peers from the Cloud,
forwarding/NAT are automated, and connection paths are abstracted.
Ready for the first real end-to-end connectivity test (Stage 5).*
