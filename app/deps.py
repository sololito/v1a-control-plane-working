"""FastAPI dependencies: DB, current user/device, gateway auth, admin, rate-limit.

rate_limit() kept for backwards-compat; new code should use app.ratelimit.check_rate.
"""
import time
from collections import defaultdict
from typing import Optional
from uuid import UUID
import jwt as _jwt
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app import models
from app.config import get_settings
from app.db import get_db
from app.security import decode_token

settings = get_settings()

_hits: dict = defaultdict(list)


def rate_limit(request: Request):
    now = time.time()
    key = request.client.host if request.client else "anon"
    arr = _hits[key]
    arr[:] = [t for t in arr if now - t < 60.0]
    if len(arr) >= settings.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="rate limited")
    arr.append(now)


def _bearer(auth: Optional[str]) -> str:
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return auth.split(" ", 1)[1].strip()


def _decode_or_401(token: str):
    try:
        return decode_token(token)
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")


def get_current_user_device(
    authorization: Optional[str] = Header(None), db: Session = Depends(get_db)
):
    token = _bearer(authorization)
    data = _decode_or_401(token)
    if data.get("kind") != "access":
        raise HTTPException(status_code=401, detail="wrong token kind")
    try:
        uid = UUID(str(data["sub"]))
        did = UUID(str(data["device_id"]))
    except Exception:
        raise HTTPException(status_code=401, detail="malformed token")
    user = db.query(models.User).filter(models.User.id == uid).first()
    dev = db.query(models.UserDevice).filter(models.UserDevice.id == did).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user inactive")
    if not dev or dev.user_id != user.id or dev.status != "active":
        raise HTTPException(status_code=401, detail="device revoked")
    return user, dev


def get_current_gateway(
    authorization: Optional[str] = Header(None), db: Session = Depends(get_db)
):
    token = _bearer(authorization)
    data = _decode_or_401(token)
    if data.get("kind") != "gateway":
        raise HTTPException(status_code=401, detail="wrong token kind")
    try:
        gid = UUID(str(data["sub"]))
    except Exception:
        raise HTTPException(status_code=401, detail="malformed token")
    gw = db.query(models.Gateway).filter(models.Gateway.id == gid).first()
    if not gw or gw.status == "revoked":
        raise HTTPException(status_code=401, detail="gateway revoked")
    return gw


def require_admin(user_dev=Depends(get_current_user_device)):
    user, _ = user_dev
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin required")
    return user
