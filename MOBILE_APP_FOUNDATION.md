# Mobile app foundation — connectivity & audit contract

Status: implemented server-side (API + admin portal). The native client is not
built yet; this document is the contract it must satisfy.

## 1. The connectivity rule we agreed on

**The user supplies their own initial internet access.** The phone reaches the
ODIVORA cloud over whatever IP connectivity it already has (mobile data, home
Wi-Fi, hotel Wi-Fi, a friend's hotspot). Only after the cloud has authorised
the session does the tunnel to the home gateway come up.

```
📱 phone ── user's own internet ──▶ ☁ ODIVORA cloud ──▶ 🏠 home gateway
                                     (signalling,        (WireGuard tunnel
                                      auth, audit)        endpoint)
```

Consequences the client must respect:

| # | Rule |
|---|------|
| 1 | No internet ⇒ no cloud ⇒ no connection setup. The app must say so plainly ("check your mobile data/Wi-Fi"), not spin forever. |
| 2 | The app must keep talking to the cloud on the **underlying** network (heartbeats, session status, WS signalling). A full-tunnel WireGuard config routes everything through home, so a `0.0.0.0/0` tunnel must keep the cloud signalling path reachable (policy route, or API traffic pinned to the physical interface). |
| 3 | The cloud never decides to open a tunnel on its own: it authorises, the phone proposes keys, the gateway installs the peer. |
| 4 | Losing internet mid-session = losing the tunnel. On reconnect the app re-authenticates (refresh token) and re-requests the session; it must not replay a stale peer config. |
| 5 | Nothing about authorisation lives in the app. A modified APK still hits the same server-side checks. |

## 2. Client boot sequence

1. Ensure IP connectivity exists (any network). Fail fast with a clear message.
2. `POST /api/v1/auth/login` (or `/auth/register` on first run) — send
   `device_name`, and `imei` / `mac_address` **if the OS lets you read them**.
   → `{access_token, refresh_token, device_id}`.
3. `POST /api/v1/me/device-identity` — update identifiers whenever they change
   (or when the IP changes). IMEI/MAC are optional; a rejected value comes back
   in `rejected[]` and never fails the call.
4. `GET /api/v1/me/gateways` → pick the home gateway. `POST /api/v1/connections`
   → `{id, session_token, tunnel}`.
5. `POST /api/v1/sessions/{id}/authorize-wg` with the phone's own WireGuard
   **public** key (the private key is generated on the phone and never sent).
6. Configure WireGuard, then `POST /api/v1/sessions/{id}/handshake`.
7. While connected: report destinations — `POST /api/v1/me/visits`
   (`session_id` + `sites[]`, first ten are kept).
8. Teardown: `POST /api/v1/sessions/{id}/revoke-wg`, `POST /auth/logout`.

## 3. What the audit trail records about a device

| Item | Source | Field |
|------|--------|-------|
| IP address | **Server-observed** from the connection (last `X-Forwarded-For` hop behind the proxy) — never taken from the request body | `user_devices.ip_address`, `audit_logs.ip` |
| IMEI | Self-reported by the app (OS-restricted; often unreadable) | `user_devices.imei` |
| MAC address | Self-reported by the app (OS-restricted; randomized per-network on modern OSes) | `user_devices.mac_address` |
| User agent | Self-reported | `user_devices.user_agent` |
| First 10 sites visited | Self-reported by the app for a live session (the cloud cannot see plaintext inside the tunnel) | `device_visits` (`rank` 1..10, one row per distinct host) |

Notes:

* IMEI/MAC are **forensic hints, not proof of identity** — a rooted client can
  lie. The IP is the only identifier the server derives itself.
* The first-ten cap is enforced server-side: reports beyond the cap are
  accepted, counted, and answered with `reason: "limit_reached"`, but never
  stored. Duplicates and unparseable entries are dropped too.
* Rotation is audited: changing an IMEI/MAC writes `device.imei_changed` /
  `device.mac_changed` with the previous value in `detail`.

## 4. Endpoints the app calls

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/auth/register`, `/auth/login` | session + optional first identifiers |
| POST | `/api/v1/me/device-identity` | report/refresh `imei`, `mac_address`, `device_name`, `user_agent` |
| GET | `/api/v1/me/devices` | own device list incl. recorded identifiers |
| POST | `/api/v1/connections` | open a session to a gateway |
| POST | `/api/v1/sessions/{id}/authorize-wg` | join the tunnel as a peer |
| POST | `/api/v1/sessions/{id}/handshake` | confirm the tunnel is up |
| POST | `/api/v1/me/visits` | report destinations (first ten kept per session) |
| POST | `/api/v1/sessions/{id}/revoke-wg` | leave the tunnel |

## 5. Admin portal (audit trail)

JSON API (admin bearer token required):

| Path | Purpose |
|------|---------|
| `GET /api/v1/admin/audit` | filtered trail: `action` (supports `prefix.*`), `actor`, `resource_type`, `resource_id`, `ip`, `since`, `until`; returns `{total, items[]}` with IP + detail |
| `GET /api/v1/admin/devices` | every device with IP / IMEI / MAC / user-agent / last seen; `q` searches those fields |
| `GET /api/v1/admin/tunnels` | one row per tunnel (gateway): owner, sessions, devices, sites recorded, last handshake |
| `GET /api/v1/admin/tunnels/{gateway_id}/audit` | **full report for one tunnel**: owner, sessions, per-session device (IP/IMEI/MAC), first ten sites per session, related audit rows; `?session_id=` narrows to one peer |
| `GET /api/v1/admin/tunnels/{gateway_id}/audit/print` | the same report as self-contained printable HTML |
| `GET /api/v1/admin/sessions/{session_id}/audit/print` | printable report for a single tunnel session |

In the UI (`/admin`): **Tunnels** → *print report* opens the printable page
(it is fetched with the admin token and rendered into a new tab, so the token
never appears in a URL), **Devices** → identifier search, **Audit** → action/IP
filters.

## 6. Deliberate limits

* No per-packet or per-URL capture: the cloud only ever receives what the client
  volunteers (first ten hosts per session) plus connection metadata.
* No IMEI/MAC collection on platforms that refuse to expose them — the audit
  report shows `—` rather than inventing values.
* The report prints only what is stored; there is no hidden retention — rows
  live in `audit_logs`, `user_devices` and `device_visits` until you purge them.
