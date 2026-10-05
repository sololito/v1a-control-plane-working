"""Connection/session signalling API. Production: entitlement caps, pagination, strict validation."""
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app import models, schemas
from app.authz import can_access_gateway, check_subscription_entitlement
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device
from app.security import create_session_token, decode_strict, sha256_hex
from app.tunnel import get_tunnel_provider

router = APIRouter(tags=["connections"])
settings = get_settings()

VALID_TRANSITIONS = {
    "requested": {"authorized", "failed", "expired"},
    "authorized": {"connecting", "revoked", "expired", "failed"},
    "connecting": {"connected", "failed", "expired"},
    "connected": {"disconnecting", "revoked"},
    "disconnecting": {"disconnected"},
    "disconnected": set(),
    "failed": set(),
    "expired": set(),
    "revoked": set(),
}
ACTIVE_STATUSES = ("requested", "authorized", "connecting", "connected")


def _online(gw: models.Gateway) -> bool:
    if gw.status != "online" or not gw.last_seen:
        return False
    return (datetime.utcnow() - gw.last_seen).total_seconds() < settings.heartbeat_offline_after_seconds * 2


def _entitlements(db: Session, user_id) -> dict:
    sub = (db.query(models.Subscription).filter(models.Subscription.user_id == user_id)
           .order_by(models.Subscription.started_at.desc()).first())
    try:
        return json.loads(sub.entitlements) if sub and sub.entitlements else {}
    except Exception:
        return {}


@router.post("/connections", response_model=None)
async def create_connection(body: schemas.ConnectionCreate,
                            user_dev=Depends(get_current_user_device),
                            db: Session = Depends(get_db)):
    user, dev = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == body.gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="gateway not found")
    can_access_gateway(db, user.id, gw)
    check_subscription_entitlement(db, user.id)
    if not _online(gw):
        db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                               action="connection.rejected_offline",
                               resource_type="gateway", resource_id=str(gw.id)))
        db.commit()
        raise HTTPException(status_code=409, detail="gateway offline")
    if body.connection_path not in ("direct", "relay", "unknown", "failed"):
        raise HTTPException(status_code=422, detail="bad connection_path")
    ent = _entitlements(db, user.id)
    cap = int(ent.get("max_sessions", settings.session_max_active))
    active = db.query(models.ConnectionSession).filter(
        models.ConnectionSession.user_id == user.id,
        models.ConnectionSession.status.in_(ACTIVE_STATUSES)).count()
    if active >= cap:
        raise HTTPException(status_code=403, detail=f"session limit reached ({cap})")
    sess = models.ConnectionSession(
        user_id=user.id, device_id=dev.id, gateway_id=gw.id, status="authorized",
        connection_path=body.connection_path,
        authorized_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.session_token_expire_minutes))
    db.add(sess)
    db.flush()
    token = create_session_token(str(sess.id))
    sess.session_token_hash = sha256_hex(token)
    creds = get_tunnel_provider().request_credentials(str(sess.id))
    db.add(models.SessionEvent(session_id=sess.id, event="authorized",
                               detail=json.dumps({"path": sess.connection_path, "tunnel": creds})))
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="connection.create",
                           resource_type="connection_session", resource_id=str(sess.id)))
    db.commit()
    db.refresh(sess)
    try:
        from app import signalling
        await signalling.broadcast_session(str(sess.gateway_id), str(sess.user_id),
                                           "authorized", str(sess.id), sess.status)
    except Exception:
        pass
    return {"id": str(sess.id), "status": sess.status, "connection_path": sess.connection_path,
            "gateway_id": str(sess.gateway_id), "expires_at": sess.expires_at,
            "session_token": token, "tunnel": creds}


@router.get("/connections")
def list_connections(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db),
                     limit: int = Query(default=20, ge=1, le=100),
                     offset: int = Query(default=0, ge=0)):
    user, _ = user_dev
    rows = (db.query(models.ConnectionSession).filter(
        models.ConnectionSession.user_id == user.id).order_by(
        models.ConnectionSession.requested_at.desc()).offset(offset).limit(limit).all())
    return [{"id": str(s.id), "status": s.status, "gateway_id": str(s.gateway_id),
             "connection_path": s.connection_path, "requested_at": s.requested_at,
             "expires_at": s.expires_at} for s in rows]


@router.get("/connections/{session_id}")
def get_connection(session_id: str, user_dev=Depends(get_current_user_device),
                   db: Session = Depends(get_db)):
    user, _ = user_dev
    s = db.query(models.ConnectionSession).filter(models.ConnectionSession.id == session_id).first()
    if not s or str(s.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="session not found")
    if s.expires_at and s.expires_at < datetime.utcnow() and s.status not in (
            "disconnected", "expired", "revoked", "failed"):
        s.status = "expired"
        s.ended_at = datetime.utcnow()
        db.commit()
    return {"id": str(s.id), "status": s.status, "gateway_id": str(s.gateway_id),
            "connection_path": s.connection_path, "expires_at": s.expires_at,
            "disconnect_reason": s.disconnect_reason}


@router.patch("/connections/{session_id}")
async def transition_session(session_id: str, body: dict,
                             user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, _ = user_dev
    s = db.query(models.ConnectionSession).filter(models.ConnectionSession.id == session_id).first()
    if not s or str(s.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="session not found")
    target = (body.get("status") or "").lower()
    if target not in VALID_TRANSITIONS.get(s.status, set()):
        raise HTTPException(status_code=409, detail=f"illegal {s.status} -> {target}")
    reason = (body.get("reason") or "")[:120] if body.get("reason") else None
    s.status = target
    if target == "connected":
        s.connected_at = datetime.utcnow()
    if target in ("disconnected", "expired", "failed", "revoked"):
        s.ended_at = datetime.utcnow()
        s.disconnect_reason = reason
        get_tunnel_provider().revoke_credentials(str(s.id))
    db.add(models.SessionEvent(session_id=s.id, event=target,
                               detail=json.dumps({"reason": reason})))
    db.commit()
    try:
        from app import signalling
        await signalling.broadcast_session(str(s.gateway_id), str(s.user_id),
                                           target, str(s.id), s.status)
    except Exception:
        pass
    return {"id": str(s.id), "status": s.status}


@router.delete("/connections/{session_id}")
def close_connection(session_id: str, user_dev=Depends(get_current_user_device),
                     db: Session = Depends(get_db)):
    user, _ = user_dev
    s = db.query(models.ConnectionSession).filter(models.ConnectionSession.id == session_id).first()
    if not s or str(s.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="session not found")
    if s.status not in ("disconnected", "expired", "revoked", "failed"):
        s.status = "revoked"
        s.ended_at = datetime.utcnow()
        get_tunnel_provider().revoke_credentials(str(s.id))
        db.add(models.SessionEvent(session_id=s.id, event="revoked", detail="{}"))
        db.commit()
    return {"ok": True, "status": s.status}


@router.post("/connections/{session_id}/verify")
def verify_session_token(session_id: str, body: dict,
                         gw=Depends(get_current_gateway), db: Session = Depends(get_db)):
    """Gateway verifies a mobile session token before opening tunnel (crypto-ready)."""
    if str(gw.id) != str(body.get("gateway_id", gw.id)):
        raise HTTPException(status_code=403, detail="gateway mismatch")
    token = body.get("session_token", "")
    try:
        data = decode_strict(token, "session")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid session token")
    if str(data.get("sub")) != str(session_id):
        raise HTTPException(status_code=401, detail="token/session mismatch")
    s = db.query(models.ConnectionSession).filter(models.ConnectionSession.id == session_id).first()
    if not s or str(s.gateway_id) != str(gw.id):
        raise HTTPException(status_code=404, detail="session not found")
    if s.session_token_hash != sha256_hex(token):
        raise HTTPException(status_code=401, detail="token revoked")
    if s.status not in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail=f"session {s.status}")
    return {"ok": True, "session_id": str(s.id), "status": s.status,
            "user_id": str(s.user_id)}
