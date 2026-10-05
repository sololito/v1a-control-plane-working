"""Liveness/readiness + metrics (JSON + Prometheus text)."""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
from app import models
from app.db import engine, get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "odivora-home-connectivity"}


@router.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        state = "up"
    except Exception as e:
        state = f"down: {e}"
    redis_state = "disabled"
    try:
        from app.ratelimit import _get_redis
        r = _get_redis()
        redis_state = "up" if r is not None else "fallback-memory"
    except Exception as e:
        redis_state = f"down: {e}"
    ok = state == "up"
    return {"db": state, "redis": redis_state,
            "status": "ready" if ok else "degraded"}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)):
    active = ("requested", "authorized", "connecting", "connected")
    return {
        "gateways_online": db.query(models.Gateway).filter(models.Gateway.status == "online").count(),
        "gateways_total": db.query(models.Gateway).count(),
        "sessions_active": db.query(models.ConnectionSession).filter(
            models.ConnectionSession.status.in_(active)).count(),
        "users_total": db.query(models.User).count(),
    }


def _collect_counts(db: Session, failed_window_minutes: int = 60) -> dict:
    active = ("requested", "authorized", "connecting", "connected")
    since = datetime.utcnow() - timedelta(minutes=failed_window_minutes)
    return {
        "gateways_online": db.query(models.Gateway).filter(models.Gateway.status == "online").count(),
        "gateways_offline": db.query(models.Gateway).filter(models.Gateway.status == "offline").count(),
        "gateways_total": db.query(models.Gateway).count(),
        "sessions_active": db.query(models.ConnectionSession).filter(
            models.ConnectionSession.status.in_(active)).count(),
        "sessions_failed_total": db.query(models.ConnectionSession).filter(
            models.ConnectionSession.status == "failed").count(),
        "sessions_failed_recent": db.query(models.ConnectionSession).filter(
            models.ConnectionSession.status == "failed",
            models.ConnectionSession.requested_at >= since).count(),
        "users_total": db.query(models.User).count(),
    }


@router.get("/metrics/prometheus")
def metrics_prometheus(db: Session = Depends(get_db),
                       failed_window_minutes: int = Query(60, ge=5, le=1440)):
    """Prometheus exposition format. Scrape this path; JSON /metrics kept for compat."""
    c = _collect_counts(db, failed_window_minutes)
    lines = [
        "# HELP odivora_gateways_online Gateways currently online",
        "# TYPE odivora_gateways_online gauge",
        f"odivora_gateways_online {c['gateways_online']}",
        "# HELP odivora_gateways_offline Gateways offline",
        "# TYPE odivora_gateways_offline gauge",
        f"odivora_gateways_offline {c['gateways_offline']}",
        "# HELP odivora_gateways_total Total gateways",
        "# TYPE odivora_gateways_total gauge",
        f"odivora_gateways_total {c['gateways_total']}",
        "# HELP odivora_sessions_active Active connection sessions",
        "# TYPE odivora_sessions_active gauge",
        f"odivora_sessions_active {c['sessions_active']}",
        "# HELP odivora_sessions_failed_total Failed sessions (all time)",
        "# TYPE odivora_sessions_failed_total counter",
        f"odivora_sessions_failed_total {c['sessions_failed_total']}",
        "# HELP odivora_sessions_failed_recent Failed sessions in window",
        "# TYPE odivora_sessions_failed_recent gauge",
        f"odivora_sessions_failed_recent {c['sessions_failed_recent']}",
        "# HELP odivora_users_total Total users",
        "# TYPE odivora_users_total gauge",
        f"odivora_users_total {c['users_total']}",
    ]
    return Response(content="\n".join(lines) + "\n",
                    media_type="text/plain; version=0.0.4")
