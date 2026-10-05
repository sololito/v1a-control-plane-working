# Deployment (production)
> For a fresh Ubuntu box with the V1B WireGuard relay/gateway stack, use
> **DEPLOY_UBUNTU_V1B.md** and the scripts in `deploy/`. This file remains
> the reference for scaling/ops notes.

- Env: copy `.env.example` -> `.env`. Prod must set: `APP_ENV=prod`, `SECRET_KEY` (32+ random),
  `DATABASE_URL=postgresql+psycopg2://...`, `REDIS_URL`, `CORS_ORIGINS=https://your-app`.
- DB: `psql -f migrations/001_init.sql && psql -f migrations/002_billing.sql && psql -f migrations/003_production.sql`.
- Run: `docker compose up --build` (api+postgres16+redis7) or `uvicorn app.main:app --host 0.0.0.0 --port 8000` behind TLS proxy.
- Health: `/health` (liveness), `/ready` (db+redis), `/metrics` (counts). Admin sweep: `POST /api/v1/admin/jobs/sweep` (cron every 1-2 min: expire sessions, mark gateways offline).
- Scale: stateless replicas + LB, Postgres indexes (003), Redis limiter shared. No in-memory truth except rate buckets (Redis in prod).
