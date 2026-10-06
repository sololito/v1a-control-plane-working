# ODIVORA Home Connectivity — V1 Foundation

Modular monolith backend for secure home-gateway access. Cloud does identity/auth/coordination; data-plane (WireGuard/relay) plugs in later.

## Stack & why
- **Python 3.11 + FastAPI**: productivity, validation, OpenAPI, WebSocket-ready, good Postgres support.
- **SQLAlchemy + Alembic/SQL migrations + PostgreSQL**: normalized schema, indexes for heartbeats/sessions.
- **SQLite** for local dev/tests (same models); **Postgres** canonical in `migrations/001_init.sql`.
- **PyJWT (HS256) + passlib/bcrypt**: short access (15m), long refresh (30d) device-bound, gateway (60m) + session tokens (60m). Revocation via DB.
- **cryptography / Ed25519-ready**: gateway pubkey + fingerprint stored; V1 uses pairing-code + bearer gateway token, challenge-response stub for ESP32 next.
- **Redis (optional)**: ephemeral state/rate-limit; in-memory fallback now.
- **pytest + httpx TestClient**: integration tests.
- **Docker + compose**: api + postgres:16 + redis:7.

## Structure
```
app/main.py routers/{auth,users,gateways,connections,admin,health} authz.py tunnel.py
app/{config,db,models,schemas,security,deps,jobs}.py  migrations/001_init.sql  tests/
```

## Quickstart (Windows, no Docker required)
```powershell
python -m venv .venv; .\.venv\Scripts\Activate
pip install -r requirements.txt
copy .env.example .env 2>$null; if ($LASTEXITCODE -ne 0) { echo ".env.example not found, using defaults" }
python -m scripts.seed
python run_server.py
# Access via your local IP (shown on startup), e.g. http://192.168.1.50:8000/docs
pytest -q
```

## Docker
```powershell
$env:SECRET_KEY="long-random-prod-secret-min-32-chars"; docker compose up --build
```

## Mobile app foundation & audit trail
- The phone supplies **its own initial internet access** to reach the cloud; the cloud
  then coordinates the WireGuard tunnel to the home gateway (see `MOBILE_APP_FOUNDATION.md`).
- Every device is audited: server-observed IP, self-reported IMEI/MAC (OS permitting),
  and the **first ten sites** it visited per tunnel session (`device_visits`).
- Admin portal (`/admin`): audit filters, device identifier search, and a **printable
  audit report per tunnel** (`/api/v1/admin/tunnels/{id}/audit/print`).
- Android test client (`mobile/`, Kotlin + Compose): control-plane milestone that proves
  auth/gateway/session/signalling against this API and hands the tunnel config to the
  official WireGuard app — builds a debug APK with `./gradlew :app:assembleDebug`, see
  `mobile/README.md`.

See ARCHITECTURE.md, API.md, MOBILE_APP_FOUNDATION.md, SECURITY.md, DEPLOYMENT.md, TODO_NEXT_PHASE.md.
# v1a-control-plane-working
