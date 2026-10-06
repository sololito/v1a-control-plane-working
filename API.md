# API v1 (`/api/v1`)

## Auth / users
- POST /auth/register {email,password,display_name?,device_name?,imei?,mac_address?} -> {access,refresh,device_id,user_id}
- POST /auth/login {email,password,device_name?,imei?,mac_address?} -> same (creates new device row per login/installation)
- POST /auth/refresh {refresh_token} -> rotated pair (also refreshes the device's recorded IP)
- POST /auth/logout (auth)
- GET /me (auth) | GET /me/devices (shows recorded ip/imei/mac) | POST /me/devices | DELETE /me/devices/{id} (per-device revoke)
- POST /me/device-identity {imei?,mac_address?,device_name?,device_type?,user_agent?} (auth) -> {applied,rejected,...} — self-reported forensics; IP is server-observed, never taken from the body. Invalid IMEI/MAC land in `rejected[]` instead of failing.
- POST /me/visits {session_id,sites[]} (auth) -> {stored,total,limit:10,sites,ignored} — first TEN distinct sites per tunnel session are kept; later/duplicate/unusable entries are counted but not stored.

## Gateways
- POST /gateways/register {device_type,public_key,algorithm?,firmware_version?} -> {gateway_id,pairing_code,expires_at} (code shown once)
- POST /me/gateways/{id}/claim {pairing_code} (auth) -> {gateway_token} (gateway bearer)
- GET /me/gateways (auth)
- POST /gateways/heartbeat (gateway auth) {firmware_version?,health?,ip_hint?,nonce?,wg_endpoint?} (nonce monotonic anti-replay; `wg_endpoint="host:port"` advertises a public endpoint to enable the direct path)
- POST /gateways/{id}/wg-public-key (gateway auth) {wg_public_key} — register the device's OWN WireGuard public key (44-char base64). The private key is generated on-device and never leaves it. 409 if replacing the key while sessions are active.
- POST /gateways/{id}/generate-keys — **410 Gone** (removed: it generated and stored gateway private keys server-side; use wg-public-key)
- POST /gateways/{id}/nonce (public) -> {nonce,expires_at} Ed25519 challenge
- POST /gateways/{id}/auth/verify {nonce,signature} -> {gateway_token} (single-use nonce)
- GET /gateways/{id}/configuration (gateway auth) -> {tunnel:{provider:null|wireguard}}
- GET /gateways/{id}/sessions (gateway auth) -> device inbox: non-terminal sessions for this gateway (no token material)
- POST /gateways/{id}/events (gateway auth)
- POST /me/gateways/{id}/revoke (auth) | POST /me/gateways/{id}/reactivate (auth)
- POST /me/gateways/{id}/grants {email,access_type} (owner) — PARTNER/BUSINESS share

## Connections (signalling; WS live + polling fallback)
- POST /connections {gateway_id,connection_path?} (auth) -> {id,status=authorized,session_token,tunnel,expires_at} — 403 if not owner/granted/entitled/capped, 409 if offline
- GET /connections?limit&offset | GET /connections/{id} | PATCH /connections/{id} {status,reason?} | DELETE /connections/{id}
- POST /connections/{id}/verify {gateway_id,session_token} (gateway) — pre-tunnel check
- WS /ws/gateways/{id}?token= (gateway) + WS /ws/mobile?token= (user) — session events broadcast

## Billing (M-Pesa Daraja stubs — V1 free untouched)
- GET /billing/plans -> [{plan,price,currency,entitlements}]
- GET /me/subscription (auth) -> current free sub
- POST /me/billing/mpesa/initiate {plan,phone} (auth) -> {checkout_request_id,live:false} (no charge sent)
- POST /billing/mpesa/callback (public, Daraja-shaped) -> {ResultCode:0} idempotent; records receipt only

## Admin / health / audit trail
- GET /admin/users|/users/active|/gateways|/sessions|/stats|/alerts, POST /admin/users/{id}/disable|/enable, POST /admin/devices/{id}/revoke, POST /admin/sessions/{id}/revoke, POST /admin/gateways/{id}/revoke, POST /admin/jobs/sweep (admin)
- GET /admin/audit?action=auth.*&actor=&resource_type=&resource_id=&ip=&since=&until=&limit=&offset= -> {total,items[{at,action,actor_type,actor,resource_type,resource,ip,detail}]}
- GET /admin/devices?user_id=&status=&q= -> {total,items[{id,email,device_name,ip_address,imei,mac_address,user_agent,last_seen,...}]} (`q` matches IP/IMEI/MAC/name)
- GET /admin/tunnels?status= -> [{gateway_id,owner_email,sessions_total,sessions_active,devices_total,sites_recorded,...}] — one row per tunnel
- GET /admin/tunnels/{gateway_id}/audit?session_id=&limit= -> full report for one tunnel (owner, sessions, device IP/IMEI/MAC, first ten sites per session, audit rows)
- GET /admin/tunnels/{gateway_id}/audit/print -> **printable HTML** report for that tunnel
- GET /admin/sessions/{session_id}/audit/print -> printable HTML report for one tunnel session
- UI: GET /admin (login + active users / stats+alerts / gateways / tunnels / devices / sessions / audit / ops) — Tunnels tab prints the per-tunnel audit report
- GET /health /ready /metrics (JSON) /metrics/prometheus (Prometheus text), GET /

Auth: `Authorization: Bearer <access|gateway>`. All authZ server-side. Full OpenAPI at /docs.
