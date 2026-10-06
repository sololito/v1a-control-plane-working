# TODO — next phase (V1 hardening -> V2)
- [x] Ed25519 challenge-response on heartbeat (nonce sign/verify) for ESP32.
- [x] WebSocket signalling gateway<->mobile via cloud (polling stays as fallback).
- [x] WireGuard provider plumbing (keygen + peer config; daemon/relay later). Set TUNNEL_PROVIDER=wireguard.
- [x] Redis sliding-window rate-limit + refresh-token rotation grace (30s prev-hash window).
- [x] Alembic wiring (alembic.ini + alembic/env.py; baseline 001..004 SQL kept).
- [x] Partner grants prep (gateway_grants + PARTNER/BUSINESS access types; marketplace later).
- [ ] M-Pesa Daraja LIVE flip (needs sandbox creds + public callback URL):
  - [ ] Paste Daraja sandbox creds into `.env` (see BILLING_MPESA.md — never commit secrets)
  - [ ] Expose public HTTPS callback URL (`https://<you>/api/v1/billing/mpesa/callback`, ngrok for sandbox)
  - [ ] Set `BILLING_LIVE=true`, restart API, `POST /me/billing/mpesa/initiate` with test phone `254708374149`
  - [ ] Approve STK on test phone, verify callback `success` + new paid Subscription row
  - [ ] Prod: switch `MPESA_ENV=production`, Lipa-na-M-Pesa shortcode/passkey, IP-allowlist + callback auth, C2B reconcile
- [ ] Partner/public hotspot policy in authz.py + tests.
- [x] Admin UI (minimal) + Prometheus metrics + alerting on offline/failed sessions.
- [x] Mobile app foundation: client supplies its own initial internet access to reach the
  cloud, then joins the tunnel (`MOBILE_APP_FOUNDATION.md`); `POST /me/device-identity` +
  `POST /me/visits` contract in place.
- [x] Admin audit trail: device IP/IMEI/MAC logging, first-ten-sites per tunnel session,
  filtered `/admin/audit`, per-tunnel JSON + printable report (`/admin/tunnels/{id}/audit/print`).
- [ ] ESP32 pairing firmware + mobile CONNECT_TO_HOME_GATEWAY flow against this API.
