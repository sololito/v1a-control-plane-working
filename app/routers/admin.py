"""Admin: paginated lists, user/device/session control, stats, job sweep."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app import jobs, models
from app.db import SessionLocal, get_db
from app.deps import require_admin

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
def list_users(_=Depends(require_admin), db: Session = Depends(get_db),
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = db.query(models.User).order_by(models.User.created_at.desc()).offset(offset).limit(limit).all()
    return [{"id": str(u.id), "email": u.email, "is_active": u.is_active,
             "is_admin": u.is_admin} for u in rows]


@router.post("/users/{user_id}/disable")
def disable_user(user_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    u.is_active = False
    db.add(models.AuditLog(actor_type="admin", actor_id="admin", action="admin.user_disable",
                           resource_type="user", resource_id=str(u.id)))
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/enable")
def enable_user(user_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    u.is_active = True
    db.commit()
    return {"ok": True}


@router.get("/gateways")
def list_gateways(_=Depends(require_admin), db: Session = Depends(get_db),
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                  status: str | None = None):
    q = db.query(models.Gateway)
    if status:
        q = q.filter(models.Gateway.status == status)
    rows = q.order_by(models.Gateway.created_at.desc()).offset(offset).limit(limit).all()
    return [{"id": str(g.id), "status": g.status, "owner": str(g.owner_user_id),
             "last_seen": g.last_seen} for g in rows]


@router.get("/sessions")
def list_sessions(_=Depends(require_admin), db: Session = Depends(get_db),
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = (db.query(models.ConnectionSession).order_by(
        models.ConnectionSession.requested_at.desc()).offset(offset).limit(limit).all())
    return [{"id": str(s.id), "status": s.status, "gateway_id": str(s.gateway_id),
             "user_id": str(s.user_id)} for s in rows]


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    from datetime import datetime
    s = db.query(models.ConnectionSession).filter(models.ConnectionSession.id == session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    if s.status not in ("disconnected", "expired", "revoked", "failed"):
        s.status = "revoked"
        s.ended_at = datetime.utcnow()
        db.add(models.SessionEvent(session_id=s.id, event="revoked", detail='{"by":"admin"}'))
        db.commit()
    return {"ok": True, "status": s.status}


@router.post("/devices/{device_id}/revoke")
def revoke_device_admin(device_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    from datetime import datetime
    d = db.query(models.UserDevice).filter(models.UserDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="device not found")
    d.status = "revoked"
    d.refresh_token_hash = None
    d.revoked_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.get("/audit")
def list_audit(_=Depends(require_admin), db: Session = Depends(get_db),
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = (db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc())
            .offset(offset).limit(limit).all())
    return [{"action": r.action, "actor": r.actor_id, "resource": r.resource_id,
             "at": r.created_at} for r in rows]


@router.get("/stats")
def stats(_=Depends(require_admin), db: Session = Depends(get_db)):
    return {
        "users": db.query(models.User).count(),
        "gateways_online": db.query(models.Gateway).filter(models.Gateway.status == "online").count(),
        "gateways_total": db.query(models.Gateway).count(),
        "sessions_active": db.query(models.ConnectionSession).filter(
            models.ConnectionSession.status.in_(["requested", "authorized", "connecting",
                                                 "connected"])).count(),
    }


@router.get("/users/active")
def active_users(_=Depends(require_admin), db: Session = Depends(get_db),
                 limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                 presence_minutes: int = Query(15, ge=1, le=1440)):
    """Active users: is_active + device last_seen within window, with presence summary.

    Returns per user: devices active count, last_seen max, gateways owned, sessions active.
    """
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(minutes=presence_minutes)
    users = (db.query(models.User).filter(models.User.is_active == True)  # noqa: E712
             .order_by(models.User.created_at.desc()).offset(offset).limit(limit).all())
    out = []
    for u in users:
        devs = db.query(models.UserDevice).filter(
            models.UserDevice.user_id == u.id,
            models.UserDevice.status == "active").all()
        recent = [d for d in devs if d.last_seen and d.last_seen >= cutoff]
        if not recent:
            continue
        gw_count = db.query(models.Gateway).filter(
            models.Gateway.owner_user_id == u.id,
            models.Gateway.status != "revoked").count()
        sess_active = db.query(models.ConnectionSession).filter(
            models.ConnectionSession.user_id == u.id,
            models.ConnectionSession.status.in_(["requested", "authorized",
                                                 "connecting", "connected"])).count()
        out.append({"id": str(u.id), "email": u.email, "is_admin": u.is_admin,
                    "devices_active": len(devs),
                    "devices_seen_recently": len(recent),
                    "last_seen": max(d.last_seen for d in recent),
                    "gateways_owned": gw_count, "sessions_active": sess_active})
    out.sort(key=lambda r: r["last_seen"], reverse=True)
    return out


@router.get("/alerts")
def alerts(_=Depends(require_admin), db: Session = Depends(get_db),
           offline_minutes: int = Query(10, ge=1, le=1440),
           failed_window_minutes: int = Query(60, ge=5, le=1440),
           failed_threshold: int = Query(10, ge=1, le=10000)):
    """Operational alerts: offline gateways + failed-session spikes. Used by UI + Alertmanager."""
    from datetime import datetime, timedelta
    from app.config import get_settings
    s = get_settings()
    now = datetime.utcnow()
    out = []
    # 1. Gateways silent past threshold (expected online/registered but no heartbeat).
    cutoff = now - timedelta(minutes=offline_minutes)
    silent = (db.query(models.Gateway)
              .filter(models.Gateway.status.in_(["online", "registered"]),
                      models.Gateway.last_seen != None,  # noqa: E711
                      models.Gateway.last_seen < cutoff).all())
    for g in silent:
        out.append({"severity": "warning", "type": "gateway_offline",
                    "gateway_id": str(g.id), "owner": str(g.owner_user_id),
                    "last_seen": g.last_seen,
                    "message": f"gateway {str(g.id)[:8]} silent >{offline_minutes}m"})
    never = (db.query(models.Gateway)
             .filter(models.Gateway.status.in_(["online", "registered"]),
                     models.Gateway.last_seen == None).all())  # noqa: E711
    for g in never:
        out.append({"severity": "info", "type": "gateway_never_seen",
                    "gateway_id": str(g.id),
                    "message": f"gateway {str(g.id)[:8]} never heartbeated"})
    # 2. Failed sessions spike in window.
    since = now - timedelta(minutes=failed_window_minutes)
    failed_n = (db.query(models.ConnectionSession)
                .filter(models.ConnectionSession.status == "failed",
                        models.ConnectionSession.requested_at >= since).count())
    if failed_n >= failed_threshold:
        out.append({"severity": "critical", "type": "sessions_failed_spike",
                    "count": failed_n, "window_minutes": failed_window_minutes,
                    "message": f"{failed_n} failed sessions in {failed_window_minutes}m"})
    return {"alerts": out, "count": len(out),
            "thresholds": {"offline_minutes": offline_minutes,
                           "failed_window_minutes": failed_window_minutes,
                           "failed_threshold": failed_threshold,
                           "heartbeat_offline_after_seconds": s.heartbeat_offline_after_seconds}}


@router.post("/gateways/{gateway_id}/revoke")
def admin_revoke(gateway_id: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if gw:
        gw.status = "revoked"
        db.commit()
    return {"ok": True}


@router.post("/jobs/sweep")
def sweep(_=Depends(require_admin)):
    db = SessionLocal()
    try:
        expired = jobs.expire_sessions(db)
        offline = jobs.mark_offline_gateways(db)
        return {"expired": expired, "marked_offline": offline}
    finally:
        db.close()
