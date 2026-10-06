"""Admin: paginated lists, user/device/session control, stats, job sweep.

Also owns the audit trail: filtered audit queries and the per-tunnel audit
report (JSON + printable HTML) — see app/audit_report.py for the report shape.
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app import jobs, models
from app.audit_report import build_tunnel_report, gateway_event_row, render_report_html
from app.config import get_settings
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
               limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               action: str | None = Query(None, description="exact or 'prefix.*' match"),
               actor: str | None = None, resource_type: str | None = None,
               resource_id: str | None = None, ip: str | None = None,
               since: datetime | None = None, until: datetime | None = None):
    """Filtered audit trail. Every row keeps its IP and resource pointers so a
    device, user or tunnel can be traced end to end."""
    q = db.query(models.AuditLog)
    if action:
        if action.endswith("*"):
            q = q.filter(models.AuditLog.action.like(action[:-1] + "%"))
        else:
            q = q.filter(models.AuditLog.action == action)
    if actor:
        q = q.filter(models.AuditLog.actor_id == actor)
    if resource_type:
        q = q.filter(models.AuditLog.resource_type == resource_type)
    if resource_id:
        q = q.filter(models.AuditLog.resource_id == resource_id)
    if ip:
        q = q.filter(models.AuditLog.ip == ip)
    if since:
        q = q.filter(models.AuditLog.created_at >= since)
    if until:
        q = q.filter(models.AuditLog.created_at <= until)
    total = q.count()
    rows = q.order_by(models.AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [{"id": str(r.id), "action": r.action, "actor_type": r.actor_type,
                       "actor": r.actor_id, "resource_type": r.resource_type,
                       "resource": r.resource_id, "ip": r.ip, "detail": r.detail,
                       "at": r.created_at} for r in rows]}


@router.get("/devices")
def list_devices(_=Depends(require_admin), db: Session = Depends(get_db),
                 limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                 user_id: str | None = None, status: str | None = None,
                 q: str | None = Query(None, description="match IP / IMEI / MAC / name")):
    """Every registered device with the identifiers needed for forensics."""
    query = db.query(models.UserDevice)
    if user_id:
        query = query.filter(models.UserDevice.user_id == user_id)
    if status:
        query = query.filter(models.UserDevice.status == status)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(models.UserDevice.ip_address.ilike(like) |
                             models.UserDevice.imei.ilike(like) |
                             models.UserDevice.mac_address.ilike(like) |
                             models.UserDevice.device_name.ilike(like))
    total = query.count()
    rows = query.order_by(models.UserDevice.created_at.desc()).offset(offset).limit(limit).all()
    users = {str(u.id): u.email for u in db.query(models.User).all()}
    return {"total": total, "items": [{
        "id": str(d.id), "user_id": str(d.user_id),
        "email": users.get(str(d.user_id)),
        "device_name": d.device_name, "device_type": d.device_type, "status": d.status,
        "ip_address": d.ip_address, "imei": d.imei, "mac_address": d.mac_address,
        "user_agent": d.user_agent, "last_seen": d.last_seen,
        "identity_updated_at": d.identity_updated_at, "created_at": d.created_at,
        "revoked_at": d.revoked_at} for d in rows]}


@router.get("/tunnels")
def list_tunnels(_=Depends(require_admin), db: Session = Depends(get_db),
                 limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                 status: str | None = None):
    """One row per tunnel (a tunnel terminates on one home gateway)."""
    q = db.query(models.Gateway)
    if status:
        q = q.filter(models.Gateway.status == status)
    rows = q.order_by(models.Gateway.created_at.desc()).offset(offset).limit(limit).all()
    out = []
    for g in rows:
        sessions = db.query(models.ConnectionSession).filter(
            models.ConnectionSession.gateway_id == g.id).all()
        owner = db.query(models.User).filter(models.User.id == g.owner_user_id).first() \
            if g.owner_user_id else None
        active = ("requested", "authorized", "connecting", "connected")
        device_ids = {s.device_id for s in sessions if s.device_id}
        visits = db.query(models.DeviceVisit).filter(
            models.DeviceVisit.gateway_id == g.id).count()
        try:
            meta = json.loads(g.ip_metadata or "{}") or {}
        except Exception:
            meta = {}
        out.append({
            "gateway_id": str(g.id), "status": g.status, "wg_status": g.wg_status,
            "tunnel_ip": g.tunnel_ip, "wg_public_key": g.wg_public_key,
            "remote_ip": meta.get("remote_ip") or meta.get("ip_hint"),
            "wg_last_handshake_at": g.wg_last_handshake_at, "last_seen": g.last_seen,
            "owner_id": str(g.owner_user_id) if g.owner_user_id else None,
            "owner_email": owner.email if owner else None,
            "sessions_total": len(sessions),
            "sessions_active": sum(1 for s in sessions if s.status in active),
            "devices_total": len(device_ids), "sites_recorded": visits,
        })
    return out


def _gateway_or_404(db: Session, gateway_id: str) -> models.Gateway:
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="tunnel not found")
    return gw


@router.get("/tunnels/{gateway_id}/audit")
def tunnel_audit(gateway_id: str, _=Depends(require_admin), db: Session = Depends(get_db),
                 session_id: str | None = None,
                 limit: int = Query(200, ge=1, le=500)):
    """Full audit report for one tunnel: sessions, device identifiers
    (IP/IMEI/MAC), first ten sites visited per session, and the audit trail."""
    gw = _gateway_or_404(db, gateway_id)
    session = None
    if session_id:
        session = db.query(models.ConnectionSession).filter(
            models.ConnectionSession.id == session_id,
            models.ConnectionSession.gateway_id == gw.id).first()
        if not session:
            raise HTTPException(status_code=404, detail="session not in this tunnel")
    return build_tunnel_report(db, gw, session=session, audit_limit=limit)


@router.get("/tunnels/{gateway_id}/audit/print", response_class=HTMLResponse)
def tunnel_audit_print(gateway_id: str, _=Depends(require_admin),
                       db: Session = Depends(get_db),
                       session_id: str | None = None,
                       limit: int = Query(200, ge=1, le=500)):
    """Same report as a printable HTML document (one page per tunnel)."""
    gw = _gateway_or_404(db, gateway_id)
    session = None
    if session_id:
        session = db.query(models.ConnectionSession).filter(
            models.ConnectionSession.id == session_id,
            models.ConnectionSession.gateway_id == gw.id).first()
        if not session:
            raise HTTPException(status_code=404, detail="session not in this tunnel")
    report = build_tunnel_report(db, gw, session=session, audit_limit=limit)
    return HTMLResponse(render_report_html(report))


@router.get("/sessions/{session_id}/audit/print", response_class=HTMLResponse)
def session_audit_print(session_id: str, _=Depends(require_admin),
                        db: Session = Depends(get_db),
                        limit: int = Query(200, ge=1, le=500)):
    """Printable audit report for a single tunnel session (one peer)."""
    sess = db.query(models.ConnectionSession).filter(
        models.ConnectionSession.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    gw = _gateway_or_404(db, str(sess.gateway_id))
    report = build_tunnel_report(db, gw, session=sess, audit_limit=limit)
    return HTMLResponse(render_report_html(
        report, title=f"Tunnel session audit — {str(sess.id)[:8]}"))


@router.get("/gateways/{gateway_id}/events")
def gateway_events(gateway_id: str, _=Depends(require_admin), db: Session = Depends(get_db),
                   since: datetime | None = None, until: datetime | None = None,
                   event_type: str | None = Query(None, alias="type"),
                   limit: int = Query(200, ge=1, le=500)):
    """Raw evidence the gateway itself reported: peer changes, handshakes, NAT
    failures, WAN changes — including anything it queued while the Cloud was
    unreachable and shipped afterwards (GATEWAY_EVENT_CACHE.md).

    Rows are claims by the sensor, not server-observed facts, so each one is
    returned with both the gateway's timestamp and the Cloud's.
    """
    gw = _gateway_or_404(db, gateway_id)
    # received_at is both the Cloud's timestamp and the provenance flag: rows
    # the Cloud wrote itself (heartbeat, registered, ...) are not sensor claims
    # and belong to the audit trail above, not here.
    q = db.query(models.GatewayEvent).filter(
        models.GatewayEvent.gateway_id == gw.id,
        models.GatewayEvent.received_at.isnot(None))
    if since:
        q = q.filter(models.GatewayEvent.created_at >= since)
    if until:
        q = q.filter(models.GatewayEvent.created_at <= until)
    if event_type:
        q = q.filter(models.GatewayEvent.event_type == event_type)
    total = q.count()
    rows = q.order_by(models.GatewayEvent.created_at.desc()).limit(limit).all()
    return {"total": total, "gateway_id": str(gw.id),
            "note": "gateway-reported (unverified)",
            "items": [gateway_event_row(r) for r in rows]}


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
        pruned = jobs.prune_gateway_events(db, get_settings().gateway_event_retention_days)
        return {"expired": expired, "marked_offline": offline, "events_pruned": pruned}
    finally:
        db.close()
