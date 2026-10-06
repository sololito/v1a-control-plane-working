"""Auth: register, login (lockout), refresh (reuse detection), logout, logout-all."""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_user_device
from app.forensics import normalize_imei, normalize_mac
from app.ratelimit import check_rate, client_ip
from app.security import (
    create_access_token, create_refresh_token, decode_strict,
    hash_password, sha256_hex, verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()

# email -> [timestamps of failures]; lockout after N in window
_fails: dict = defaultdict(list)


def _fail_key(email: str, ip: str) -> str:
    return f"{email.lower().strip()}|{ip}"


def _check_lockout(email: str, ip: str):
    now = datetime.utcnow()
    arr = _fails[_fail_key(email, ip)]
    arr[:] = [t for t in arr if now - t < timedelta(minutes=settings.login_lockout_minutes)]
    if len(arr) >= settings.login_max_attempts:
        raise HTTPException(status_code=429, detail="too many attempts, try later")


def _record_fail(email: str, ip: str):
    _fails[_fail_key(email, ip)].append(datetime.utcnow())


def _clear_fails(email: str, ip: str):
    _fails.pop(_fail_key(email, ip), None)


def _issue(user: models.User, dev: models.UserDevice, db: Session,
           ip: str | None = None):
    access = create_access_token(str(user.id), str(dev.id))
    refresh = create_refresh_token(str(user.id), str(dev.id))
    # Keep previous hash for 30s so a retried/concurrent refresh doesn't look like theft.
    if dev.refresh_token_hash:
        dev.refresh_prev_hash = dev.refresh_token_hash
        dev.refresh_prev_at = datetime.utcnow()
    dev.refresh_token_hash = sha256_hex(refresh)
    dev.last_seen = datetime.utcnow()
    if ip:  # audit trail: address this device actually reached us from
        dev.ip_address = ip
    db.add(dev)
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="auth.token_issued",
                           resource_type="user_device", resource_id=str(dev.id), ip=ip))
    db.commit()
    return {"access_token": access, "refresh_token": refresh,
            "device_id": dev.id, "user_id": user.id}


@router.post("/register", response_model=schemas.TokenResponse)
def register(body: schemas.RegisterRequest, request: Request, db: Session = Depends(get_db)):
    check_rate("auth_register", client_ip(request), settings.auth_rate_per_minute)
    email = body.email.lower().strip()
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=409, detail="email exists")
    user = models.User(email=email, password_hash=hash_password(body.password),
                       display_name=(body.display_name or "").strip()[:120] or None)
    db.add(user)
    db.flush()
    dev = models.UserDevice(user_id=user.id, device_name=body.device_name.strip()[:80],
                            ip_address=client_ip(request), imei=normalize_imei(body.imei),
                            mac_address=normalize_mac(body.mac_address))
    db.add(dev)
    db.flush()
    sub = models.Subscription(user_id=user.id, plan="free", status="active",
                              entitlements=json.dumps({"max_gateways": 2, "max_sessions": 1}))
    db.add(sub)
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="auth.register",
                           ip=client_ip(request)))
    db.commit()
    db.refresh(dev)
    return _issue(user, dev, db, ip=client_ip(request))


@router.post("/login", response_model=schemas.TokenResponse)
def login(body: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    check_rate("auth_login", client_ip(request), settings.auth_rate_per_minute)
    email = body.email.lower().strip()
    _check_lockout(email, client_ip(request))
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        _record_fail(email, client_ip(request))
        db.add(models.AuditLog(actor_type="user", actor_id=email, action="auth.login_failed",
                               ip=client_ip(request)))
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="user disabled")
    _clear_fails(email, client_ip(request))
    dev = models.UserDevice(user_id=user.id, device_name=body.device_name.strip()[:80],
                            ip_address=client_ip(request), imei=normalize_imei(body.imei),
                            mac_address=normalize_mac(body.mac_address))
    db.add(dev)
    db.flush()
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="auth.login",
                           resource_type="user_device", resource_id=str(dev.id),
                           ip=client_ip(request)))
    db.commit()
    db.refresh(dev)
    return _issue(user, dev, db, ip=client_ip(request))


@router.post("/refresh", response_model=schemas.TokenResponse)
def refresh(body: schemas.RefreshRequest, request: Request, db: Session = Depends(get_db)):
    check_rate("auth_refresh", client_ip(request), settings.auth_rate_per_minute * 2)
    try:
        data = decode_strict(body.refresh_token, "refresh")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    from uuid import UUID
    try:
        uid, did = UUID(str(data["sub"])), UUID(str(data["device_id"]))
    except Exception:
        raise HTTPException(status_code=401, detail="malformed token")
    dev = db.query(models.UserDevice).filter(models.UserDevice.id == did).first()
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user or not dev or dev.user_id != user.id or dev.status != "active":
        raise HTTPException(status_code=401, detail="device revoked")
    if dev.refresh_token_hash != sha256_hex(body.refresh_token):
        # Grace: previous token valid for 30s (concurrent refresh retry) — re-issue without revoke.
        h = sha256_hex(body.refresh_token)
        if (dev.refresh_prev_hash == h and dev.refresh_prev_at and
                datetime.utcnow() - dev.refresh_prev_at < timedelta(seconds=30)):
            return _issue(user, dev, db, ip=client_ip(request))
        # Reuse/theft: revoke device immediately.
        dev.status = "revoked"
        dev.refresh_token_hash = None
        dev.revoked_at = datetime.utcnow()
        db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                               action="auth.refresh_reuse",
                               resource_type="user_device", resource_id=str(dev.id),
                               ip=client_ip(request)))
        db.commit()
        raise HTTPException(status_code=401, detail="refresh reused — device revoked")
    return _issue(user, dev, db, ip=client_ip(request))


@router.post("/logout")
def logout(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, dev = user_dev
    dev.refresh_token_hash = None
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="auth.logout",
                           resource_type="user_device", resource_id=str(dev.id)))
    db.commit()
    return {"ok": True}


@router.post("/logout-all")
def logout_all(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, cur = user_dev
    n = 0
    for d in db.query(models.UserDevice).filter(models.UserDevice.user_id == user.id,
                                                models.UserDevice.status == "active").all():
        if str(d.id) == str(cur.id):
            continue
        d.status = "revoked"
        d.refresh_token_hash = None
        d.revoked_at = datetime.utcnow()
        n += 1
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id),
                           action="auth.logout_all"))
    db.commit()
    return {"ok": True, "revoked_others": n}
