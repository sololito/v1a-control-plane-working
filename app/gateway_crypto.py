"""Gateway Ed25519 challenge-response. ESP32 signs nonce bytes; server verifies.

Public keys stored as base64 (32-byte Ed25519) or base64 of PEM/DER. Dev/test
gateways with opaque strings skip crypto and use bearer flow (forward-compat).
"""
import base64
from datetime import datetime, timedelta

NONCE_TTL_MIN = 5


def new_nonce() -> str:
    import secrets
    return secrets.token_hex(24)


def _load_pubkey(public_key: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    s = (public_key or "").strip()
    # try raw base64 32 bytes
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        pass
    # try PEM
    try:
        return serialization.load_pem_public_key(s.encode())
    except Exception:
        pass
    raise ValueError("not an Ed25519 public key (dev bearer flow)")


def verify_signature(public_key: str, nonce: str, signature_b64: str) -> bool:
    try:
        pub = _load_pubkey(public_key)
        sig = base64.b64decode(signature_b64, validate=True)
        pub.verify(sig, nonce.encode())
        return True
    except Exception:
        return False


def nonce_expiry() -> datetime:
    return datetime.utcnow() + timedelta(minutes=NONCE_TTL_MIN)
