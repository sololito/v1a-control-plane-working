# Architecture

Modular monolith, stateless API (DB holds session truth, horizontally scalable).

```
Mobile -> FastAPI (/api/v1) -> [auth|users|gateways|sessions|subs|admin] -> Postgres
Gateway -> FastAPI (register/heartbeat/events/config) -> Postgres (+ gateway_events)
jobs.expire_sessions / mark_offline_gateways -> background (Celery later)
TunnelProvider (Null now, WireGuard/Relay later) — signalling only in V1

V1B data plane: phone <-> WireGuard <-> gateway, with DIRECT when the
gateway has a public endpoint and RELAY (UDP pair-forwarder, no decryption)
otherwise. See V1B_RELAY_NAT.md and firmware/relay/.
```

Components map 1:1 to Guide §1. Each router+service has clear boundary so it can split to microservice later.

- Users: 1 user -> N devices, N gateways, N sessions, 1..N subscriptions.
- Gateway lifecycle: unregistered->pairing->registered->online->offline->revoked. Outbound heartbeat, no port-forward.
- Session: requested->authorized->connecting->connected->disconnecting->disconnected (+failed/expired/revoked). Path: direct|relay|unknown.
- Policy layer `app/authz.py`: V1 `PERSONAL_GATEWAY` (owner check); future types raise 403 with explicit TODO.
- Entitlements: `User -> Subscription -> entitlements JSON -> connection auth`. No payment provider coupling.
- Observability: structured logs, /health /ready /metrics stub, audit_logs + gateway/session events.

## ER (summary)
users(1)-*(user_devices, gateways?, connection_sessions, subscriptions); gateways(1)-*(credentials, events); connection_sessions(1)-*(session_events); audit_logs append-only.

Scaling: stateless API replicas + Postgres indexes + Redis for ephemeral/rate-limit + job abstraction. No in-memory session truth.
