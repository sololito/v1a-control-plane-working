"""Connection/session signalling API. Production: entitlement caps, pagination, strict validation."""
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.authz import can_access_gateway, check_subscription_entitlement
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device
from app.security import create_session_token, decode_strict, sha256_hex
from app.ratelimit import client_ip
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
async def create_connection(body: schemas.ConnectionCreate, request: Request,
                            user_dev=Depends(get_current_user_device),
                            db: Session = Depends(get_db)):
    user, dev = user_dev
    ip = client_ip(request)
    gw = db.query(models.Gateway).filter(models.Gateway.id == body.gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="gateway not found")
    can_access_gateway(db, user.id, gw)
    check_subscription_entitlement(db, user.id)
    # Cap handling with resume. First sweep this user's sessions past their
    # validity window (they must not keep eating the cap), then: if the cap
    # allows a new session, create one as usual — but if it does not and the
    # user already holds an active session ON THIS GATEWAY, attach to it
    # instead of failing: tapping "open tunnel session" again must land you
    # in the session you already have (the free plan allows just one, so a
    # plain 403 here would lock users out of their own session). This block
    # runs before the online check so an offline gateway can never trap an
    # active session where it cannot be reached or closed.
    ent = _entitlements(db, user.id)
    cap = int(ent.get("max_sessions", settings.session_max_active))
    now = datetime.utcnow()
    fresh = []
    for row in (db.query(models.ConnectionSession)
                .filter(models.ConnectionSession.user_id == user.id,
                        models.ConnectionSession.status.in_(ACTIVE_STATUSES))
                .order_by(models.ConnectionSession.requested_at.desc()).all()):
        if row.expires_at and row.expires_at < now:
            row.status = "expired"
            row.ended_at = now
            db.add(models.SessionEvent(session_id=row.id, event="expired",
                                       detail=json.dumps({"reason": "stale_on_create"})))
        else:
            fresh.append(row)
    if len(fresh) >= cap:
        same_gw = next((r for r in fresh if str(r.gateway_id) == str(gw.id)), None)
        if same_gw is None:
            db.commit()  # persist the sweep even though the create is refused
            raise HTTPException(status_code=403, detail=f"session limit reached ({cap})")
        token = create_session_token(str(same_gw.id))
        same_gw.session_token_hash = sha256_hex(token)
        db.add(models.SessionEvent(session_id=same_gw.id, event="resumed",
                                   detail=json.dumps({"path": same_gw.connection_path})))
        db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                               action="connection.resume",
                               resource_type="connection_session",
                               resource_id=str(same_gw.id), ip=ip))
        db.commit()
        db.refresh(same_gw)
        creds = get_tunnel_provider().request_credentials(str(same_gw.id))
        return {"id": str(same_gw.id), "status": same_gw.status,
                "connection_path": same_gw.connection_path,
                "gateway_id": str(same_gw.gateway_id),
                "expires_at": same_gw.expires_at,
                "session_token": token, "tunnel": creds}
    if not _online(gw):
        db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                               action="connection.rejected_offline",
                               resource_type="gateway", resource_id=str(gw.id), ip=ip))
        db.commit()
        raise HTTPException(status_code=409, detail="gateway offline")
    if body.connection_path not in ("direct", "relay", "unknown", "failed"):
        raise HTTPException(status_code=422, detail="bad connection_path")
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
                           resource_type="connection_session", resource_id=str(sess.id), ip=ip))
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
