"""Modular monolith entrypoint. Stateless API; session state lives in DB."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db import Base, SessionLocal, engine
from app.middleware import request_id_middleware
from app.routers import auth, users, gateways, connections, admin, billing, health, ws, admin_ui, gateway_wg, sessions_wg

settings = get_settings()
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

if settings.app_env == "prod" and len(settings.secret_key) < 32:
    raise RuntimeError("SECRET_KEY must be >=32 chars in prod")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Lifespan-scoped, not import-scoped: uvicorn --reload re-imports the
    # module, and a thread started at import would leak on every reload.
    from app import maintenance
    maintenance.start(SessionLocal)
    try:
        yield
    finally:
        maintenance.stop()


app = FastAPI(title="ODIVORA Home Connectivity", version="1.0.0",
              docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)
app.middleware("http")(request_id_middleware)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()] \
    if settings.cors_origins != "*" else ["*"]
# Cookies/credentials require explicit origins — never "*" + credentials in prod.
allow_creds = origins != ["*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"],
                   allow_headers=["*"], allow_credentials=allow_creds)

# Create tables for dev/SQLite (Alembic/Postgres migrations are canonical for prod).
Base.metadata.create_all(bind=engine)
# Add columns that appeared after a dev database was first created (create_all
# only creates missing tables). No-op on a fresh database; see app/schema_guard.py.
from app.schema_guard import ensure_additive_schema  # noqa: E402
ensure_additive_schema(engine)

P = settings.api_v1_prefix
app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix=P)
app.include_router(users.router, prefix=P)
app.include_router(gateways.router, prefix=P)
app.include_router(connections.router, prefix=P)
app.include_router(billing.router, prefix=P)
app.include_router(admin.router, prefix=P)
app.include_router(ws.router)
app.include_router(admin_ui.router)
app.include_router(gateway_wg.router, prefix="/api/v1")
app.include_router(sessions_wg.router, prefix="/api/v1")


from fastapi.responses import RedirectResponse

@app.get("/")
def root():
    return RedirectResponse(url="/admin")
