"""Password hashing, JWT, pairing codes, fingerprints. No secrets ever logged."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from passlib.context import CryptContext

from app.config import get_settings

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)


def verify_password(pw: str, h: str) -> bool:
    return pwd_ctx.verify(pw, h)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_pairing_code(length: int = 6) -> str:
    # Numeric short code for manual entry; hashed at rest.
    return "".join(secrets.choice("0123456789") for _ in range(length))


def _encode(payload: Dict[str, Any], expires: timedelta, kind: str) -> str:
    import uuid
    now = datetime.now(timezone.utc)
    data = dict(payload)
    data.update({"exp": now + expires, "iat": now, "kind": kind, "jti": uuid.uuid4().hex})
    return jwt.encode(data, settings.secret_key, algorithm="HS256")


def _decode(token: str, expect_kind: str) -> Dict[str, Any]:
    data = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    if data.get("kind") != expect_kind:
        raise jwt.InvalidTokenError(f"unexpected token kind, want {expect_kind}")
    return data


def create_access_token(user_id: str, device_id: str) -> str:
    return _encode({"sub": user_id, "device_id": device_id},
                   timedelta(minutes=settings.access_token_expire_minutes), "access")


def create_refresh_token(user_id: str, device_id: str) -> str:
    return _encode({"sub": user_id, "device_id": device_id},
                   timedelta(days=settings.refresh_token_expire_days), "refresh")


def create_gateway_token(gateway_id: str) -> str:
    return _encode({"sub": gateway_id},
                   timedelta(minutes=settings.gateway_token_expire_minutes), "gateway")


def create_session_token(session_id: str) -> str:
    return _encode({"sub": session_id},
                   timedelta(minutes=settings.session_token_expire_minutes), "session")


def decode_token(token: str) -> Dict[str, Any]:
    # Kind is validated by callers via expect checks where strictness matters.
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def decode_strict(token: str, kind: str) -> Dict[str, Any]:
    return _decode(token, kind)


def fingerprint_public_key(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()[:64]
