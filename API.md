# API v1 (`/api/v1`)

## Auth / users
- POST /auth/register {email,password,display_name?,device_name?} -> {access,refresh,device_id,user_id}
- POST /auth/login -> same (creates new device row per login/installation)
- POST /auth/refresh {refresh_token} -> rotated pair
- POST /auth/logout (auth)
- GET /me (auth) | GET /me/devices | POST /me/devices | DELETE /me/devices/{id} (per-device revoke)

## Gateways
- POST /gateways/register {device_type,public_key,algorithm?,firmware_version?} -> {gateway_id,pairing_code,expires_at} (code shown once)
- POST /me/gateways/{id}/claim {pairing_code} (auth) -> {gateway_token} (gateway bearer)
- GET /me/gateways (auth)
- POST /gateways/heartbeat (gateway auth) {firmware_version?,health?,ip_hint?,nonce?} (nonce monotonic anti-replay)
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

## Admin / health
- GET /admin/users|/users/active|/gateways|/sessions|/audit|/stats|/alerts, POST /admin/users/{id}/disable|/enable, POST /admin/devices/{id}/revoke, POST /admin/sessions/{id}/revoke, POST /admin/gateways/{id}/revoke, POST /admin/jobs/sweep (admin)
- UI: GET /admin (login + active users / stats+alerts / gateways / sessions / audit / ops)
- GET /health /ready /metrics (JSON) /metrics/prometheus (Prometheus text), GET /

Auth: `Authorization: Bearer <access|gateway>`. All authZ server-side. Full OpenAPI at /docs.
