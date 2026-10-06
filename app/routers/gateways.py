"""Gateway lifecycle: register -> pairing -> registered -> online/offline -> revoked.

Production: pairing attempt limits, entitlement caps, nonce replay protection,
rate-limited register/claim/heartbeat.
"""
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.billing import PLANS
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device
from app.gateway_crypto import new_nonce, nonce_expiry, verify_signature
from app.ratelimit import check_rate, client_ip
from app.security import create_gateway_token, fingerprint_public_key, sha256_hex, new_pairing_code

router = APIRouter(tags=["gateways"])
settings = get_settings()


def _audit(db, actor_type, actor_id, action, rid=None, detail=None, ip=None):
    db.add(models.AuditLog(actor_type=actor_type, actor_id=actor_id, action=action,
                           resource_type="gateway", resource_id=rid, detail=detail, ip=ip))


# Fresh-boot window: a counter restarting at/below this after a high value
# is treated as a reboot resync (audited), not a replay. See heartbeat().
_REBOOT_NONCE_WINDOW = 10


def _nonce_stale(old: str | None, new: str) -> bool:
    if old is None:
        return False
    try:
        return int(new) <= int(old)
    except (TypeError, ValueError):
        return new <= old


def _looks_like_reboot(old: str | None, new: str) -> bool:
    try:
        return (old is not None and int(new) <= _REBOOT_NONCE_WINDOW
                and int(old) > _REBOOT_NONCE_WINDOW)
    except (TypeError, ValueError):
        return False


def _entitlements(db, user_id) -> dict:
    sub = (db.query(models.Subscription).filter(models.Subscription.user_id == user_id)
           .order_by(models.Subscription.started_at.desc()).first())
    try:
        return json.loads(sub.entitlements) if sub and sub.entitlements else {}
    except Exception:
        return {}


@router.post("/gateways/register")
def gateway_register(body: schemas.GatewayRegisterRequest, request: Request,
                     db: Session = Depends(get_db)):
    check_rate("gw_register", client_ip(request), settings.gateway_rate_per_minute)
    if len(body.public_key.strip()) < 16:
        raise HTTPException(status_code=422, detail="public_key too short")
    gw = models.Gateway(device_type=body.device_type, public_key=body.public_key.strip(),
                        firmware_version=(body.firmware_version or "").strip()[:40] or None,
                        status="pairing", pairing_attempts=0)
    db.add(gw)
    db.flush()
    fp = fingerprint_public_key(body.public_key)
    db.add(models.GatewayCredential(gateway_id=gw.id, algorithm=body.algorithm,
                                    public_key=body.public_key.strip(), fingerprint=fp))
    code = new_pairing_code()
    gw.pairing_code_hash = sha256_hex(code)
    gw.pairing_expires_at = datetime.utcnow() + timedelta(minutes=settings.pairing_code_ttl_minutes)
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="registered",
                               payload=json.dumps({"algorithm": body.algorithm})))
    _audit(db, "gateway", str(gw.id), "gateway.register", str(gw.id),
           ip=client_ip(request))
    db.commit()
    return {"gateway_id": str(gw.id), "pairing_code": code,
            "expires_at": gw.pairing_expires_at, "status": gw.status}


@router.get("/me/gateways")
def my_gateways(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, _ = user_dev
    gws = db.query(models.Gateway).filter(models.Gateway.owner_user_id == user.id).all()
    return [{"id": str(g.id), "device_type": g.device_type, "firmware_version": g.firmware_version,
             "status": g.status, "last_seen": g.last_seen, "created_at": g.created_at} for g in gws]


@router.post("/me/gateways/{gateway_id}/claim")
def claim_gateway(gateway_id: str, body: schemas.GatewayClaimRequest, request: Request,
                  user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    check_rate(f"gw_claim:{client_ip(request)}", gateway_id, settings.auth_rate_per_minute)
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="gateway not found")
    if gw.status == "revoked":
        raise HTTPException(status_code=403, detail="gateway revoked")
    if gw.owner_user_id is not None and str(gw.owner_user_id) != str(user.id):
        raise HTTPException(status_code=403, detail="already owned")
    if (gw.pairing_attempts or 0) >= settings.pairing_max_attempts:
        raise HTTPException(status_code=429, detail="too many pairing attempts")
    if gw.pairing_expires_at and gw.pairing_expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="pairing code expired")
    if not gw.pairing_code_hash or gw.pairing_code_hash != sha256_hex(body.pairing_code.strip()):
        gw.pairing_attempts = (gw.pairing_attempts or 0) + 1
        _audit(db, "user", str(user.id), "gateway.claim_failed", str(gw.id),
               ip=client_ip(request))
        db.commit()
        raise HTTPException(status_code=403, detail="bad pairing code")
    # Entitlement: cap gateways per plan.
    ent = _entitlements(db, user.id)
    max_gw = int(ent.get("max_gateways", 2))
    owned = db.query(models.Gateway).filter(
        models.Gateway.owner_user_id == user.id,
        models.Gateway.status != "revoked").count()
    if str(gw.owner_user_id or "") != str(user.id) and owned >= max_gw:
        raise HTTPException(status_code=403, detail=f"gateway limit reached ({max_gw})")
    gw.owner_user_id = user.id
    gw.status = "registered"
    gw.pairing_code_hash = None
    gw.pairing_attempts = 0
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="claimed",
                               payload=json.dumps({"by": str(user.id)})))
    _audit(db, "user", str(user.id), "gateway.claim", str(gw.id), ip=client_ip(request))
    db.commit()
    token = create_gateway_token(str(gw.id))
    return {"ok": True, "gateway_id": str(gw.id), "gateway_token": token}


@router.post("/gateways/heartbeat")
def heartbeat(body: schemas.HeartbeatRequest, request: Request,
              gw: models.Gateway = Depends(get_current_gateway),
              db: Session = Depends(get_db)):
    check_rate(f"gw_hb:{gw.id}", client_ip(request), settings.gateway_rate_per_minute * 2)
    if body.nonce is not None:
        # Monotonic nonce: numeric compare first (firmware sends decimal
        # counters like 1..9,10,11 where string compare would misorder),
        # lexicographic fallback for timestamp/opaque nonces.
        stale = _nonce_stale(gw.last_nonce, body.nonce)
        if stale and _looks_like_reboot(gw.last_nonce, body.nonce):
            # Counter restarted at 1 after reboot (V1 bearer flow has no
            # re-auth). Accept once into the fresh sequence and audit it.
            # Weak against replay of values 1..10 — acceptable in V1 behind
            # TLS + 60m tokens; the Ed25519 challenge path is the strong auth.
            db.add(models.GatewayEvent(gateway_id=gw.id, event_type="nonce_resync",
                                       payload=json.dumps({"from": gw.last_nonce,
                                                           "to": body.nonce})))
            _audit(db, "gateway", str(gw.id), "gateway.nonce_resync", str(gw.id))
            stale = False
        if stale:
            _audit(db, "gateway", str(gw.id), "gateway.replay_rejected", str(gw.id))
            db.commit()
            # Hand the current counter back so a rebooted agent can resume
            # from it instead of retrying the same rejected nonce forever.
            raise HTTPException(status_code=409, detail={
                "error": "stale nonce (replay?)", "last_nonce": gw.last_nonce})
        gw.last_nonce = body.nonce
    gw.last_seen = datetime.utcnow()
    gw.status = "online"
    if body.firmware_version:
        gw.firmware_version = body.firmware_version.strip()[:40]
    if body.health is not None:
        db.add(models.GatewayEvent(gateway_id=gw.id, event_type="heartbeat",
                                   payload=json.dumps({"fw": body.firmware_version})[:2000]))
        gw.health = json.dumps(body.health)[:8000]
    if body.ip_hint:
        gw.ip_metadata = json.dumps({"ip_hint": body.ip_hint.strip()[:64],
                                     "seen": str(datetime.utcnow())})
    if body.wg_endpoint is not None:
        # Merge so declaring an endpoint doesn't wipe the ip_hint.
        try:
            meta = json.loads(gw.ip_metadata or "{}")
        except Exception:
            meta = {}
        ep = body.wg_endpoint.strip()
        if ep:
            host, _, port = ep.rpartition(":")
            if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
                raise HTTPException(status_code=422,
                                    detail="wg_endpoint must be host:port")
            meta["wg_endpoint"] = ep[:128]
        else:
            meta.pop("wg_endpoint", None)
        meta["seen"] = str(datetime.utcnow())
        gw.ip_metadata = json.dumps(meta)
    # Audit trail: the address this gateway connected FROM is server-observed and
    # kept separately from ip_hint, which the gateway merely claims about itself.
    try:
        meta = json.loads(gw.ip_metadata or "{}")
    except Exception:
        meta = {}
    meta["remote_ip"] = client_ip(request)
    meta["seen"] = str(datetime.utcnow())
    gw.ip_metadata = json.dumps(meta)
    db.commit()
    return {"ok": True, "status": gw.status, "server_time": datetime.utcnow()}


@router.get("/gateways/{gateway_id}/configuration")
def gateway_config(gateway_id: str, gw: models.Gateway = Depends(get_current_gateway),
                   db: Session = Depends(get_db)):
    if str(gw.id) != str(gateway_id):
        raise HTTPException(status_code=403, detail="gateway mismatch")
    from app.tunnel import get_tunnel_provider
    tp = get_tunnel_provider()
    return {"gateway_id": str(gw.id), "status": gw.status,
            "mqtt": None, "relay": {"mode": "signalling-only"},
            "tunnel": {"provider": tp.name, **tp.server_config()}}


@router.post("/gateways/{gateway_id}/events")
def gateway_event(gateway_id: str, body: schemas.GatewayEventIn,
                  gw: models.Gateway = Depends(get_current_gateway),
                  db: Session = Depends(get_db)):
    if str(gw.id) != str(gateway_id):
        raise HTTPException(status_code=403, detail="gateway mismatch")
    if len(body.event_type) > 60:
        raise HTTPException(status_code=422, detail="event_type too long")
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type=body.event_type,
                               payload=json.dumps(body.payload or {})[:8000]))
    db.commit()
    return {"ok": True}


@router.get("/gateways/{gateway_id}/sessions")
def gateway_sessions(gateway_id: str, gw: models.Gateway = Depends(get_current_gateway),
                     db: Session = Depends(get_db)):
    """Pollable inbox for the device: non-terminal sessions addressed to it.

    The firmware polls this after heartbeat and verifies each `authorized`
    session before opening any tunnel. No token material is exposed here.
    """
    if str(gw.id) != str(gateway_id):
        raise HTTPException(status_code=403, detail="gateway mismatch")
    rows = (db.query(models.ConnectionSession)
            .filter(models.ConnectionSession.gateway_id == gw.id,
                    models.ConnectionSession.status.notin_(
                        ["disconnected", "expired", "revoked", "failed"]))
            .order_by(models.ConnectionSession.requested_at.desc())
            .limit(20).all())
    return [{"id": str(s.id), "status": s.status, "user_id": str(s.user_id),
             "connection_path": s.connection_path, "requested_at": s.requested_at,
             "expires_at": s.expires_at} for s in rows]


@router.post("/me/gateways/{gateway_id}/revoke")
def revoke_gateway(gateway_id: str, user_dev=Depends(get_current_user_device),
                   db: Session = Depends(get_db)):
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or str(gw.owner_user_id or "") != str(user.id):
        raise HTTPException(status_code=404, detail="gateway not found")
    gw.status = "revoked"
    for c in db.query(models.GatewayCredential).filter(models.GatewayCredential.gateway_id == gw.id):
        c.revoked = True
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="revoked", payload="{}"))
    _audit(db, "user", str(user.id), "gateway.revoke", str(gw.id))
    db.commit()
    return {"ok": True}


@router.post("/me/gateways/{gateway_id}/reactivate")
def reactivate_gateway(gateway_id: str, user_dev=Depends(get_current_user_device),
                       db: Session = Depends(get_db)):
    """Owner can re-activate a revoked/offline gateway back to registered (new pairing not needed)."""
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or str(gw.owner_user_id or "") != str(user.id):
        raise HTTPException(status_code=404, detail="gateway not found")
    if gw.status != "revoked":
        raise HTTPException(status_code=409, detail=f"cannot reactivate from {gw.status}")
    gw.status = "registered"
    for c in db.query(models.GatewayCredential).filter(models.GatewayCredential.gateway_id == gw.id):
        c.revoked = False
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="reactivated", payload="{}"))
    _audit(db, "user", str(user.id), "gateway.reactivate", str(gw.id))
    db.commit()
    return {"ok": True, "status": gw.status}


@router.post("/gateways/{gateway_id}/nonce")
def gateway_nonce(gateway_id: str, request: Request, db: Session = Depends(get_db)):
    """Issue single-use Ed25519 challenge. ESP32 signs `nonce` and calls /verify."""
    check_rate(f"gw_nonce:{gateway_id}", client_ip(request), 30)
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or gw.status == "revoked":
        raise HTTPException(status_code=404, detail="gateway not found")
    n = models.GatewayNonce(gateway_id=gw.id, nonce=new_nonce(), expires_at=nonce_expiry())
    db.add(n)
    db.commit()
    return {"gateway_id": str(gw.id), "nonce": n.nonce, "expires_at": n.expires_at}


@router.post("/gateways/{gateway_id}/auth/verify")
def gateway_auth_verify(gateway_id: str, body: dict, request: Request,
                        db: Session = Depends(get_db)):
    """Verify Ed25519(nonce) -> gateway bearer token. Consumes nonce (replay-safe)."""
    check_rate(f"gw_verify:{gateway_id}", client_ip(request), 30)
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or gw.status == "revoked":
        raise HTTPException(status_code=404, detail="gateway not found")
    nonce, sig = (body.get("nonce") or ""), (body.get("signature") or "")
    if not nonce or not sig:
        raise HTTPException(status_code=422, detail="nonce+signature required")
    rec = (db.query(models.GatewayNonce)
           .filter(models.GatewayNonce.gateway_id == gw.id,
                   models.GatewayNonce.nonce == nonce).first())
    if not rec or rec.used or rec.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="bad/expired nonce")
    cred = (db.query(models.GatewayCredential)
            .filter(models.GatewayCredential.gateway_id == gw.id,
                    models.GatewayCredential.revoked == False)  # noqa: E712
            .order_by(models.GatewayCredential.created_at.desc()).first())
    pubkey = (cred.public_key if cred else (gw.public_key or ""))
    if not verify_signature(pubkey, nonce, sig):
        _audit(db, "gateway", str(gw.id), "gateway.auth_failed", str(gw.id))
        db.commit()
        raise HTTPException(status_code=401, detail="bad signature")
    rec.used = True
    gw.last_seen = datetime.utcnow()
    if gw.status in ("registered", "offline"):
        gw.status = "online"
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="auth_verified", payload="{}"))
    db.commit()
    return {"gateway_token": create_gateway_token(str(gw.id)), "status": gw.status}


@router.post("/me/gateways/{gateway_id}/grants")
def create_grant(gateway_id: str, body: dict,
                 user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    """Owner shares gateway (PARTNER_GATEWAY). Grantee can then create sessions."""
    from app.authz import can_access_gateway
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or str(gw.owner_user_id or "") != str(user.id):
        raise HTTPException(status_code=404, detail="gateway not found")
    email = (body.get("email") or "").lower().strip()
    atype = (body.get("access_type") or "PARTNER_GATEWAY").upper()
    if atype not in ("PARTNER_GATEWAY", "BUSINESS_GATEWAY"):
        raise HTTPException(status_code=422, detail="bad access_type")
    grantee = db.query(models.User).filter(models.User.email == email).first()
    if not grantee:
        raise HTTPException(status_code=404, detail="grantee not found")
    g = models.GatewayGrant(gateway_id=gw.id, grantee_user_id=grantee.id, access_type=atype)
    db.add(g)
    db.add(models.GatewayEvent(gateway_id=gw.id, event_type="grant_created",
                               payload=json.dumps({"to": str(grantee.id), "type": atype})))
    db.commit()
    return {"ok": True, "grant_id": str(g.id)}


@router.get("/me/gateways/{gateway_id}/grants")
def list_grants(gateway_id: str, user_dev=Depends(get_current_user_device),
                db: Session = Depends(get_db)):
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or str(gw.owner_user_id or "") != str(user.id):
        raise HTTPException(status_code=404, detail="gateway not found")
    rows = db.query(models.GatewayGrant).filter(models.GatewayGrant.gateway_id == gw.id).all()
    return [{"id": str(r.id), "grantee": str(r.grantee_user_id),
             "type": r.access_type, "revoked": r.revoked} for r in rows]


@router.delete("/me/gateways/{gateway_id}/grants/{grant_id}")
def revoke_grant(gateway_id: str, grant_id: str, user_dev=Depends(get_current_user_device),
                 db: Session = Depends(get_db)):
    user, _ = user_dev
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw or str(gw.owner_user_id or "") != str(user.id):
        raise HTTPException(status_code=404, detail="gateway not found")
    g = db.query(models.GatewayGrant).filter(models.GatewayGrant.id == grant_id).first()
    if g:
        g.revoked = True
        db.commit()
    return {"ok": True}
