"""Background job abstraction (expiry sweeps). Swap to Celery/RQ later."""
from datetime import datetime, timedelta
from sqlalchemy import and_, or_
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


def prune_gateway_events(db: Session, retention_days: int) -> int:
    """Delete gateway-reported events older than the retention window.

    Age is measured from `received_at` where the Cloud has it: a sensor with a
    broken clock must not be able to keep its own rows alive forever by
    stamping them into the future. Server-generated rows (heartbeat, ...) have
    no `received_at` and age from `created_at`, which is the Cloud's clock.
    """
    if retention_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    q = db.query(models.GatewayEvent).filter(or_(
        and_(models.GatewayEvent.received_at.isnot(None),
             models.GatewayEvent.received_at < cutoff),
        and_(models.GatewayEvent.received_at.is_(None),
             models.GatewayEvent.created_at < cutoff)))
    n = q.delete(synchronize_session=False)
    db.commit()
    return n
