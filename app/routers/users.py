"""Users + devices: profile, per-device revocation, device forensics."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_user_device
from app.forensics import normalize_host, normalize_imei, normalize_mac
from app.ratelimit import client_ip

router = APIRouter(tags=["users"])
settings = get_settings()


@router.get("/me", response_model=schemas.UserOut)
def me(user_dev=Depends(get_current_user_device)):
    user, _ = user_dev
    return user


@router.get("/me/devices")
def my_devices(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, _ = user_dev
    devs = db.query(models.UserDevice).filter(models.UserDevice.user_id == user.id).all()
    return [{"id": str(d.id), "device_name": d.device_name, "device_type": d.device_type,
             "status": d.status, "last_seen": d.last_seen, "created_at": d.created_at,
             "ip_address": d.ip_address, "imei": d.imei, "mac_address": d.mac_address,
             "identity_updated_at": d.identity_updated_at} for d in devs]


@router.post("/me/devices")
def add_device(body: schemas.DeviceCreate, request: Request,
               user_dev=Depends(get_current_user_device),
               db: Session = Depends(get_db)):
    user, _ = user_dev
    if body.device_type not in ("mobile", "tablet", "desktop", "other"):
        raise HTTPException(status_code=422, detail="bad device_type")
    count = db.query(models.UserDevice).filter(
        models.UserDevice.user_id == user.id,
        models.UserDevice.status == "active").count()
    if count >= 10:
        raise HTTPException(status_code=403, detail="device limit reached (10)")
    d = models.UserDevice(user_id=user.id, device_name=body.device_name.strip()[:80],
                          device_type=body.device_type, ip_address=client_ip(request))
    db.add(d)
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="device.register",
                           resource_type="user_device", resource_id=str(d.id),
                           ip=client_ip(request)))
    db.commit()
    db.refresh(d)
    return {"id": str(d.id), "status": d.status}


@router.delete("/me/devices/{device_id}")
def revoke_device(device_id: str, request: Request,
                  user_dev=Depends(get_current_user_device),
                  db: Session = Depends(get_db)):
    user, cur = user_dev
    d = db.query(models.UserDevice).filter(models.UserDevice.id == device_id).first()
    if not d or str(d.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="device not found")
    d.status = "revoked"
    d.refresh_token_hash = None
    d.revoked_at = datetime.utcnow()
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="device.revoke",
                           resource_type="user_device", resource_id=str(d.id),
                           ip=client_ip(request)))
    db.commit()
    return {"ok": True, "revoked": str(d.id)}


@router.post("/me/device-identity")
def put_device_identity(body: schemas.DeviceIdentityIn, request: Request,
                        user_dev=Depends(get_current_user_device),
                        db: Session = Depends(get_db)):
    """Mobile app reports its own identifiers for the audit trail.

    IMEI/MAC are OS-restricted: Android/iOS only expose them to privileged
    apps, and some builds never do — so both are optional and a rejected value
    is reported back instead of failing the call. The client IP is taken from
    the connection, never from the body.

    Values are only ever written once per change; the previous value is kept in
    the audit log so an identifier swap is visible in the trail.
    """
    user, dev = user_dev
    ip = client_ip(request)
    applied, rejected = {}, []

    imei = normalize_imei(body.imei)
    if body.imei and not imei:
        rejected.append("imei")
    if imei and imei != dev.imei:
        applied["imei"] = imei
        if dev.imei:
            db.add(models.AuditLog(
                actor_type="user", actor_id=str(user.id), action="device.imei_changed",
                resource_type="user_device", resource_id=str(dev.id),
                detail=f'{{"from":"{dev.imei}"}}', ip=ip))
        dev.imei = imei

    mac = normalize_mac(body.mac_address)
    if body.mac_address and not mac:
        rejected.append("mac_address")
    if mac and mac != dev.mac_address:
        applied["mac_address"] = mac
        if dev.mac_address:
            db.add(models.AuditLog(
                actor_type="user", actor_id=str(user.id), action="device.mac_changed",
                resource_type="user_device", resource_id=str(dev.id),
                detail=f'{{"from":"{dev.mac_address}"}}', ip=ip))
        dev.mac_address = mac

    if body.device_name and body.device_name.strip():
        dev.device_name = body.device_name.strip()[:80]
        applied["device_name"] = dev.device_name
    if body.device_type in ("mobile", "tablet", "desktop", "other"):
        dev.device_type = body.device_type
        applied["device_type"] = dev.device_type
    if body.user_agent:
        dev.user_agent = body.user_agent.strip()[:255]
        applied["user_agent"] = dev.user_agent

    dev.ip_address = ip
    dev.identity_updated_at = datetime.utcnow()
    dev.last_seen = dev.identity_updated_at
    applied["ip_address"] = ip
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                           action="device.identity_reported",
                           resource_type="user_device", resource_id=str(dev.id),
                           detail=str(sorted(applied)).replace("'", '"'), ip=ip))
    db.commit()
    db.refresh(dev)
    return {"device_id": str(dev.id), "applied": applied, "rejected": rejected,
            "imei": dev.imei, "mac_address": dev.mac_address, "ip_address": dev.ip_address,
            "note": "IMEI/MAC are self-reported by the client and unverified; "
                    "the IP is observed by the server."}


@router.post("/me/visits")
def report_visits(body: schemas.VisitsIn, request: Request,
                  user_dev=Depends(get_current_user_device),
                  db: Session = Depends(get_db)):
    """Record the first sites a device reached through a live tunnel session.

    The cloud never sees plaintext inside a WireGuard tunnel, so the mobile
    client reports destinations itself (DNS names / URLs it resolved). Only the
    first `visit_site_limit` (10) distinct hosts per session are stored; later
    reports are accepted and counted but not persisted.
    """
    user, dev = user_dev
    ip = client_ip(request)
    sess = db.query(models.ConnectionSession).filter(
        models.ConnectionSession.id == body.session_id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    if str(sess.user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="not your session")
    if not sess.gateway_id:
        raise HTTPException(status_code=409, detail="session has no gateway (tunnel)")

    limit = settings.visit_site_limit
    existing = (db.query(models.DeviceVisit)
                .filter(models.DeviceVisit.session_id == sess.id)
                .order_by(models.DeviceVisit.rank).all())
    seen = {v.host for v in existing}
    stored = 0
    ignored = []
    for raw in body.sites:
        host, url = normalize_host(raw)
        if not host:
            ignored.append({"site": str(raw)[:80], "reason": "unusable"})
            continue
        if host in seen:
            ignored.append({"site": host, "reason": "duplicate"})
            continue
        if len(existing) >= limit:
            ignored.append({"site": host, "reason": "limit_reached"})
            continue
        row = models.DeviceVisit(
            user_id=user.id, device_id=dev.id, session_id=sess.id,
            gateway_id=sess.gateway_id, rank=len(existing) + 1, host=host,
            url=url, client_ip=ip, visited_at=datetime.utcnow())
        db.add(row)
        existing.append(row)
        seen.add(host)
        stored += 1

    if stored:
        db.add(models.AuditLog(
            actor_type="user", actor_id=str(user.id), action="tunnel.visits_reported",
            resource_type="connection_session", resource_id=str(sess.id),
            detail=f'{{"stored":{stored},"total":{len(existing)},"limit":{limit}}}', ip=ip))
    db.commit()
    return {"session_id": str(sess.id), "stored": stored,
            "total": len(existing), "limit": limit,
            "sites": [v.host for v in existing], "ignored": ignored}
