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
    assert c.post(f"/api/v1/gateways/{gid}/generate-keys", headers=h).status_code == 200
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
    c.post(f"/api/v1/gateways/{gid}/generate-keys", headers=h)
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    r2 = c.get(f"/api/v1/sessions/{s['id']}/wg-config", headers=h)
    assert r2.status_code == 409
