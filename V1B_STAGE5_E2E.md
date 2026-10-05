# V1B Stage 5: End-to-End Acceptance, Test Client, Benchmarking

## Objective
Turn the stage-1→4 control-plane into a provable data plane: a phone
outside the home authenticates, receives a config, establishes a real
WireGuard tunnel, and egresses through the home ISP. Server-side, the
last missing piece was the mobile/test-client config contract (§18);
the acceptance test and benchmarks (§15/§16) are now scripted.

## 📁 Files Created/Changed

### 1. `GET /api/v1/sessions/{id}/wg-config` (NEW, `app/routers/sessions_wg.py`)
Returns a ready-to-import wg-quick config for the phone:

- `[Interface]`: `Address = <assigned_ip>/32`, `DNS = 1.1.1.1`, private key
  **placeholder** (phone generates its own; never returned by the Cloud).
- `[Peer]`: gateway public key, endpoint (from gateway `ip_metadata.wg_endpoint`
  when set, else `<gateway-public-ip>:<listen_port>`),
  `AllowedIPs = 0.0.0.0/0` (full tunnel), `PersistentKeepalive = 25`.

Guards: user must own the session's gateway (403), session must not be
terminal (409), and `authorize-wg` must have run first (409). Emits a
`config_issued` SessionEvent.

### 2. `tests/test_stage5_config.py` (NEW)
- Valid config contains assigned IP, `[Interface]`/`[Peer]`, full-tunnel
  `AllowedIPs`, no private key material.
- Other user → 403.
- Authorize-first requirement → 409.

### 3. `scripts/benchmark.py` (NEW)
Repeatable §16 procedure: ping RTT/jitter/loss to a reference IP and
through the tunnel, optional iperf3 download/upload against a host on the
home LAN, printed as a Markdown table. No hard-coded numbers — record
observations only.

## ✅ End-to-End Acceptance Procedure (§15) — DoD

On the home gateway (Linux, already configured by Stage 4):

```bash
# Control plane up, gateway online, keys generated, daemon running
python -m app.gateway.daemon --api-base http://<cloud>:8000 \
    --gateway-id <gid> --token <gtok> --kind linux
```

On the phone (mobile data, outside home):

1. Register/login to ODIVORA, `POST /connections` with the home gateway ID.
2. `POST /api/v1/sessions/{id}/authorize-wg` → copy assigned IP + keys.
3. `GET /api/v1/sessions/{id}/wg-config` → save as `odivora.conf`.
4. Install the config into WireGuard (mobile app import / `wg-quick up`).
5. `POST /api/v1/sessions/{id}/handshake` → status `connected`.
6. Browse; `curl ifconfig.me` — the egress IP **must equal the home
   connection's public IP**, not the mobile carrier's.
7. `POST /sessions/{id}/revoke-wg` → tunnel dies, peer removed by the daemon,
   internet falls back to mobile data. **Revocation works.**
8. Re-check with the device/gateway revoked: authorization must now fail.

## 📊 Benchmark Procedure (§16)

1. Baseline: phone directly on mobile data — `python scripts/benchmark.py --ref-ip 1.1.1.1 --iperf-server <home-host>`.
2. Tunnelled: same command from the phone with the tunnel up (`--gateway-ip <tunnel-.1>`).
3. LAN baseline (optional): same host on home Wi-Fi.
4. Record tunnel-establishment time (handshake endpoint latency), gateway
   CPU/RAM via `top`, sustained throughput, jitter, packet loss.
5. Paste results into your report — never present illustrative numbers as
   measurements.

## 🔐 Security Notes (unchanged invariants)

- Gateway + phone private keys are generated and stored **on their devices**.
- The backend holds only public keys, tunnel IPs, timestamps, audit rows.
- `wg-config` returns a private-key placeholder, never a key.
- Full tunnel (`0.0.0.0/0`) routes DNS through the tunnel (no mobile-data
  DNS leak).

## 📦 What's Next (Stage 6)

- RELAY / CGNAT prototype decision (§12/§13): when DIRECT is impossible.
- Partner gateway grants in the phone UX + marketplace readiness (V2).
- Prometheus export of session/tunnel metrics.
- ESP32 integration: control-plane only for now; data plane stays on
  Linux/OpenWrt (e.g. MT7981).

---

*V1B Stage 5 complete: test-client config contract, E2E acceptance
procedure, and benchmarking are in place. Definition of Done (§15) is
ready to be executed on real hardware.*
