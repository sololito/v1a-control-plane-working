# ODIVORA Home Connectivity — V1 Working Principle

V1 answers one question: **can a phone outside the home ask our cloud for permission
to reach its own home gateway, with the cloud verifying identity — before any tunnel exists?**
There is no data-plane yet (no WireGuard traffic, no relay bytes, no M-Pesa charges).

## 1. Roles

```
Phone (mobile app / curl) ──HTTPS──▶ ODIVORA cloud (this repo, :8000)
                                         ▲
Home gateway (ESP32, `firmware/esp32_gateway/esp32_gateway.ino`) ──HTTPS──▶ same cloud
```

* **Cloud** = identity + authentication + authorization + coordination + session records.
  Never required to carry user traffic later.
* **Gateway** = small device on home Wi-Fi. Makes **outbound HTTPS only** — works behind
  NAT/CGNAT, no port forwarding, no public IP needed.
* **Phone** = any mobile client with the user's access token.

## 2. Bring-up sequence (what you do with real hardware)

1. Flash the ESP32 (`WIFI_SSID`/`WIFI_PASS`/`SERVER` at top of the `.ino`), open Serial 115200.
2. Device `POST /api/v1/gateways/register` → cloud stores pubkey fingerprint, returns
   `gateway_id` + one-time 6-digit **pairing code** (Serial shows it, 15-min TTL, 5 tries max).
3. You claim from phone/laptop: `POST /me/gateways/{id}/claim {pairing_code}` →
   ownership set + `gateway_token` returned **to you**.
4. Paste into Serial: `TOKEN <jwt>` → device stores it (Preferences, survives reboot).
5. Device heartbeats every 60 s: `POST /gateways/heartbeat` (Bearer + zero-padded
   monotonic `nonce`, heap/RSSI health). Cloud marks it `online`; silence >~120 s
   reads as offline. Counters survive 9→10 crossings and reboots (audited resync);
   true replays still get 409.
6. From outside the home (phone data, not home Wi-Fi): `POST /connections {gateway_id}` →
   cloud checks owner-or-grant + active subscription + `online` + session cap → returns
   `session_token` (`authorized`). Device sees it in its inbox
   (`GET /gateways/{id}/sessions`, polled ~every 5 min); the session token holder
   confirms binding via `POST /connections/{id}/verify`.
7. Walk states: `authorized → connecting → connected → disconnecting → disconnected`
   (`PATCH /connections/{id}`). WS (`/ws/...`) also broadcasts each change; polling
   `GET /connections` is always the truth.

## 3. Trust model (what the cloud actually checks)

* Users: bcrypt password, short access JWT (15 m) + rotating refresh (30 d, reuse revokes
  device). Each phone install = separate `user_devices` row, individually revocable.
* Gateway pairing: knowing the `gateway_id` alone can never claim it — the hashed,
  expiring pairing code is required, attempts are capped and audited.
* Gateway runtime: Bearer token (60 m) today; single-use Ed25519 `nonce → verify`
  challenge exists (`POST /gateways/{id}/nonce|auth/verify`) for the crypto upgrade.
  Heartbeat `nonce` already rejects replays (409).
* Every connection re-checks **server-side**: ownership/grant, live subscription,
  gateway `online`, per-plan session cap (free = 1). The phone is never trusted.

## 4. V1 limits (by design, not bugs)

* **Signalling only** — `tunnel.provider` is `null` (or WireGuard keygen plumbing with
  `TUNNEL_PROVIDER=wireguard`, no daemon). A successful V1 test ends at `verify: ok`,
  not at browsable traffic.
* **Free entitlements**: 2 gateways / 1 active session per user. 2nd concurrent
  session → 403, silent gateway → 409. Billing is stubbed (`BILLING_LIVE=false`).
* **No port-forward path**: `DIRECT`/`RELAY` are labels only; relay infra is later.
* Lifetimes: pairing 15 m, access 15 m, gateway/session tokens 60 m, refresh reuse
  grace 30 s. Login 5-fails/15-min lockout; pairing 5-tries lockout.

## 5. “Did my home gateway work?” checklist

* Serial shows `heartbeat ok (N)` with N increasing → cloud sees it (`GET /me/gateways`
  shows `online` + fresh `last_seen`; `/admin` → Active users/Stats agree).
* External `POST /connections` → 200 + `verify` → `ok` → states walk cleanly.
* Kill heartbeats 3 min → next `POST /connections` → 409 offline (detection works).
* `pytest -q` → 25 green (same flows the hardware exercises, simulated).

## 6. What V1 deliberately leaves for later

WireGuard/relay data-plane, M-Pesa live flip (creds + callback URL), partner-marketplace
rules beyond grants, ESP32 Ed25519 signing on-device, admin alerting stack. See
`TODO_NEXT_PHASE.md`. Success = the hardware above completes §5 and the mobile app
can later plug into the same endpoints unchanged.
