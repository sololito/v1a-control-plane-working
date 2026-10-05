"""Background job abstraction (expiry sweeps). Swap to Celery/RQ later."""
from datetime import datetime
from sqlalchemy.orm import Session
from app import models


def expire_sessions(db: Session) -> int:
    now = datetime.utcnow()
    rows = db.query(models.ConnectionSession).filter(
        models.ConnectionSession.expires_at < now,
        models.ConnectionSession.status.in_(["requested", "authorized", "connecting"])).all()
    n = 0
    for s in rows:
        s.status = "expired"
        s.ended_at = now
        db.add(models.SessionEvent(session_id=s.id, event="expired", detail="{}"))
        n += 1
    db.commit()
    return n


def mark_offline_gateways(db: Session, offline_after_seconds: int = 120) -> int:
    # Called periodically; gateways missing heartbeat go offline.
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(seconds=offline_after_seconds)
    rows = db.query(models.Gateway).filter(
        models.Gateway.status == "online", models.Gateway.last_seen < cutoff).all()
    for g in rows:
        g.status = "offline"
    db.commit()
    return len(rows)
