"""V1B Stage 5: generated client config + end-to-end contract."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_stage5.db"
try:
    if os.path.exists("./test_stage5.db"):
        os.remove("./test_stage5.db")
except PermissionError:
    pass

import base64
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_stage5.db", connect_args={"check_same_thread": False})
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
    app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()
    auth_router._fails.clear()


def reg(email):
    r = c.post("/api/v1/auth/register", json={"email": email, "password": "Password123!"})
    assert r.status_code == 200, r.text
    return r.json()


def ed_b64():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def setup_session(email="s5owner@example.com"):
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": ed_b64()})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={}, headers={"Authorization": f"Bearer {gtok}"})
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]},
               headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    a = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert a.status_code == 200, a.text
    return h, gid, s["id"], a.json()


def test_wg_config_download_valid():
    h, gid, sid, auth = setup_session()
    r = c.get(f"/api/v1/sessions/{sid}/wg-config", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert auth["assigned_ip"] in body["config"]
    assert "[Interface]" in body["config"] and "[Peer]" in body["config"]
    assert "AllowedIPs = 0.0.0.0/0" in body["config"]
    # phone private key placeholder, not a real key
    assert "<phone private key" in body["config"]
    assert "gateway_private" not in body["config"].lower()


def test_wg_config_forbidden_for_other_user():
    h, gid, sid, auth = setup_session("s5owner2@example.com")
    other = reg("s5stranger@example.com")
    oh = {"Authorization": f"Bearer {other['access_token']}"}
    r = c.get(f"/api/v1/sessions/{sid}/wg-config", headers=oh)
    assert r.status_code == 403


def test_wg_config_requires_authorize_first():
    t = reg("s5b@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": ed_b64()})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={}, headers={"Authorization": f"Bearer {gtok}"})
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    c.post(f"/api/v1/gateways/{gid}/wg-public-key",
           json={"wg_public_key": keys["public_key"]},
           headers={"Authorization": f"Bearer {gtok}"})
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    r2 = c.get(f"/api/v1/sessions/{s['id']}/wg-config", headers=h)
    assert r2.status_code == 409


# --- WireGuard private-key containment (migration 006) ---

def _claimed_gateway(email):
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": ed_b64()})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={},
           headers={"Authorization": f"Bearer {gtok}"})
    return h, gtok, gid


def test_generate_keys_endpoint_is_gone():
    """Server-side key generation must be unavailable, not merely discouraged."""
    h, gtok, gid = _claimed_gateway("genkeys@example.com")
    r = c.post(f"/api/v1/gateways/{gid}/generate-keys", headers=h)
    assert r.status_code == 410, r.text
    assert "wg-public-key" in r.json()["detail"]


def test_wg_public_key_registration_stores_no_private_key():
    """The device uploads only a public key; the DB must hold nothing secret."""
    from app.gateway.keypair import generate_wg_keypair
    from app import models
    h, gtok, gid = _claimed_gateway("pubonly@example.com")
    gh = {"Authorization": f"Bearer {gtok}"}
    keys = generate_wg_keypair()

    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]}, headers=gh)
    assert r.status_code == 200, r.text
    body = r.text
    # Neither half of the private key may appear anywhere in the response.
    assert keys["private_key"] not in body
    import base64 as _b64
    assert _b64.b64decode(keys["private_key"]).hex()[:32] not in body

    db = TestingSession()
    try:
        gw = db.query(models.Gateway).filter(models.Gateway.id == gid).first()
        assert gw.wg_public_key == keys["public_key"]
        # The column must not exist at all on the model.
        assert not hasattr(gw, "wg_private_key")
        for col in models.Gateway.__table__.columns:
            assert "private" not in col.name, f"private column present: {col.name}"
    finally:
        db.close()


def test_wg_public_key_requires_gateway_token():
    """A user access token must not be able to set the gateway's WireGuard key."""
    h, gtok, gid = _claimed_gateway("usertoken@example.com")
    keys = __import__("app.gateway.keypair", fromlist=["x"]).generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]}, headers=h)
    assert r.status_code == 401, r.text


def test_wg_public_key_rejects_malformed_keys():
    h, gtok, gid = _claimed_gateway("badkey@example.com")
    gh = {"Authorization": f"Bearer {gtok}"}
    for bad in ("", "short", "A" * 43, "A" * 44 + "=", "!!!!" + "A" * 39 + "="):
        r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
                   json={"wg_public_key": bad}, headers=gh)
        assert r.status_code == 422, (bad, r.text)


def test_rekey_blocked_while_sessions_active():
    """A new key must not silently repoint an active tunnel (DoS / hijack)."""
    from app.gateway.keypair import generate_wg_keypair
    h, gtok, gid = _claimed_gateway("rekey@example.com")
    gh = {"Authorization": f"Bearer {gtok}"}
    k1 = generate_wg_keypair()
    assert c.post(f"/api/v1/gateways/{gid}/wg-public-key",
                  json={"wg_public_key": k1["public_key"]}, headers=gh).status_code == 200

    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    assert c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h).status_code == 200

    k2 = generate_wg_keypair()
    blocked = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
                     json={"wg_public_key": k2["public_key"]}, headers=gh)
    assert blocked.status_code == 409, blocked.text

    # Idempotent re-send of the SAME key is always fine.
    same = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
                  json={"wg_public_key": k1["public_key"]}, headers=gh)
    assert same.status_code == 200 and same.json()["status"] == "unchanged"

    # After revoking the session, rotation is allowed.
    c.delete(f"/api/v1/connections/{s['id']}", headers=h)
    ok = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
                json={"wg_public_key": k2["public_key"]}, headers=gh)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "rotated"


def test_authorized_session_never_exposes_gateway_private_key():
    h, gtok, gid = _claimed_gateway("noegress@example.com")
    gh = {"Authorization": f"Bearer {gtok}"}
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    c.post(f"/api/v1/gateways/{gid}/wg-public-key",
           json={"wg_public_key": keys["public_key"]}, headers=gh)
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    a = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert a.status_code == 200, a.text
    assert keys["private_key"] not in a.text
    cfg = c.get(f"/api/v1/sessions/{s['id']}/wg-config", headers=h)
    assert keys["private_key"] not in cfg.text
