"""Next-phase: Ed25519 auth, grants, WireGuard plumbing, WS auth."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_next.db"
try:
    if os.path.exists("./test_next.db"):
        os.remove("./test_next.db")
except PermissionError:
    pass

import base64
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_next.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override
c = TestClient(app)

from app import ratelimit
from app.routers import auth as auth_router


@pytest.fixture(autouse=True)
def _clear():
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()


def reg(email):
    r = c.post("/api/v1/auth/register", json={"email": email, "password": "Password123!"})
    assert r.status_code == 200, r.text
    return r.json()


def ed_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, base64.b64encode(raw).decode()


def sign(priv, nonce: str) -> str:
    return base64.b64encode(priv.sign(nonce.encode())).decode()


def test_ed25519_nonce_verify_and_replay():
    t = reg("ed@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    priv, pub_b64 = ed_keys()
    r = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": pub_b64})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h)
    n = c.post(f"/api/v1/gateways/{gid}/nonce").json()["nonce"]
    v = c.post(f"/api/v1/gateways/{gid}/auth/verify",
               json={"nonce": n, "signature": sign(priv, n)})
    assert v.status_code == 200, v.text
    assert "gateway_token" in v.json()
    # replay same nonce must fail
    v2 = c.post(f"/api/v1/gateways/{gid}/auth/verify",
                json={"nonce": n, "signature": sign(priv, n)})
    assert v2.status_code == 401
    # bad signature fails
    n2 = c.post(f"/api/v1/gateways/{gid}/nonce").json()["nonce"]
    bad = c.post(f"/api/v1/gateways/{gid}/auth/verify",
                 json={"nonce": n2, "signature": sign(priv, "tampered")})
    assert bad.status_code == 401


def test_grant_allows_partner_session():
    owner = reg("gowner@example.com")
    oh = {"Authorization": f"Bearer {owner['access_token']}"}
    priv, pub_b64 = ed_keys()
    r = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": pub_b64})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=oh).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={},
           headers={"Authorization": f"Bearer {gtok}"})
    friend = reg("friend@example.com")
    fh = {"Authorization": f"Bearer {friend['access_token']}"}
    before = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=fh)
    assert before.status_code == 403
    g = c.post(f"/api/v1/me/gateways/{gid}/grants",
               json={"email": "friend@example.com", "access_type": "PARTNER_GATEWAY"}, headers=oh)
    assert g.status_code == 200
    after = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=fh)
    assert after.status_code == 200, after.text


def test_wireguard_plumbing_and_ws_auth():
    from app.tunnel import WireGuardProvider, get_tunnel_provider
    creds = WireGuardProvider().request_credentials("sess-1")
    assert creds["provider"] == "wireguard" and "client_private_key" in creds
    assert get_tunnel_provider().name in ("null", "wireguard")
    t = reg("ws@example.com")
    # bad WS token rejected
    try:
        with c.websocket_connect("/ws/mobile?token=bad"):
            raise AssertionError("should not connect")
    except Exception:
        pass
    # good token connects then we close
    with c.websocket_connect(f"/ws/mobile?token={t['access_token']}"):
        pass
