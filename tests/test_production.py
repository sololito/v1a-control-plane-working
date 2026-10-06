"""Production hardening tests: lockout, reuse-revoke, pairing limits, caps, nonce, admin."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_production.db"
try:
    if os.path.exists("./test_production.db"):
        os.remove("./test_production.db")
except PermissionError:
    pass

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_production.db", connect_args={"check_same_thread": False})
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
PUB = "valid-public-key-0123456789abcdef"


import pytest
from app import ratelimit
from app.routers import auth as auth_router


@pytest.fixture(autouse=True)
def _clear_limits():
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()


def reg(email, pw="Password123!"):
    r = c.post("/api/v1/auth/register", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()


def test_login_lockout():
    reg("lock@example.com")
    for _ in range(5):
        r = c.post("/api/v1/auth/login", json={"email": "lock@example.com", "password": "WrongPass123!"})
        assert r.status_code == 401
    r = c.post("/api/v1/auth/login", json={"email": "lock@example.com", "password": "WrongPass123!"})
    assert r.status_code == 429


def test_refresh_reuse_revokes():
    t = reg("reuse@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r1 = c.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r1.status_code == 200
    # grace: immediate retry with previous token allowed once (concurrent refresh)
    r2 = c.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r2.status_code == 200
    # third reuse of the same stale token -> theft -> device revoked
    r3 = c.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r3.status_code == 401
    assert c.get("/api/v1/me", headers=h).status_code == 401


def test_pairing_bruteforce_blocked_and_gateway_cap():
    t = reg("cap@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    # brute force: 5 bad attempts then 429
    r = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": PUB})
    gid = r.json()["gateway_id"]
    for _ in range(5):
        c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": "000000"}, headers=h)
    blocked = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": "000000"}, headers=h)
    assert blocked.status_code == 429
    # gateway cap: free = 2
    claimed = 0
    for i in range(3):
        rr = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": PUB + str(i)})
        g, code = rr.json()["gateway_id"], rr.json()["pairing_code"]
        cr = c.post(f"/api/v1/me/gateways/{g}/claim", json={"pairing_code": code}, headers=h)
        if cr.status_code == 200:
            claimed += 1
    assert claimed == 2


def test_nonce_replay_and_session_verify():
    t = reg("nonce@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": PUB + "n"})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h).json()["gateway_token"]
    gh = {"Authorization": f"Bearer {gtok}"}
    assert c.post("/api/v1/gateways/heartbeat", json={"nonce": "00010"}, headers=gh).status_code == 200
    replay = c.post("/api/v1/gateways/heartbeat", json={"nonce": "00010"}, headers=gh)
    assert replay.status_code == 409
    # A 409 must carry the server's current counter so a rebooted agent can
    # resume from it rather than retrying the same rejected nonce forever.
    detail = replay.json().get("detail")
    assert isinstance(detail, dict), f"409 detail should be structured: {detail!r}"
    assert str(detail.get("last_nonce")) == "00010", detail
    resumed = str(int(detail["last_nonce"]) + 1).zfill(10)
    assert c.post("/api/v1/gateways/heartbeat", json={"nonce": resumed}, headers=gh).status_code == 200
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    v = c.post(f"/api/v1/connections/{s['id']}/verify",
               json={"gateway_id": gid, "session_token": s["session_token"]}, headers=gh)
    assert v.status_code == 200
    bad = c.post(f"/api/v1/connections/{s['id']}/verify",
                 json={"gateway_id": gid, "session_token": "bad"}, headers=gh)
    assert bad.status_code == 401


def test_cross_user_isolation_blocks_access():
    t1 = reg("iso1@example.com")
    t2 = reg("iso2@example.com")
    h1, h2 = {"Authorization": f"Bearer {t1['access_token']}"}, {"Authorization": f"Bearer {t2['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "esp32", "public_key": PUB + "i1"})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    cl = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h1)
    assert cl.status_code == 200
    gtok = cl.json()["gateway_token"]
    gh = {"Authorization": f"Bearer {gtok}"}
    assert c.post("/api/v1/gateways/heartbeat", headers=gh, json={"nonce": "1"}).status_code == 200
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h1).json()
    # user2 cannot read, verify, delete
    assert c.get(f"/api/v1/connections/{s['id']}", headers=h2).status_code == 404
    assert c.post(f"/api/v1/connections/{s['id']}/verify", headers=h2,
                  json={"gateway_id": gid, "session_token": s["session_token"]}).status_code == 401
    assert c.delete(f"/api/v1/connections/{s['id']}", headers=h2).status_code == 404


def test_gateway_token_refresh_self_heals_on_expiry():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import base64

    t = reg("heal@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode()
    r = c.post("/api/v1/gateways/register",
               json={"device_type": "esp32", "public_key": pub_b64, "algorithm": "ed25519", "firmware_version": "1.1.0"})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    cl = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h)
    assert cl.status_code == 200
    gtok1 = cl.json()["gateway_token"]
    gh1 = {"Authorization": f"Bearer {gtok1}"}
    assert c.post("/api/v1/gateways/heartbeat", headers=gh1, json={"nonce": "1"}).status_code == 200
    # Mint fresh token via challenge
    n = c.post(f"/api/v1/gateways/{gid}/nonce").json()
    sig = base64.b64encode(priv.sign(n["nonce"].encode())).decode()
    v = c.post(f"/api/v1/gateways/{gid}/auth/verify",
               json={"nonce": n["nonce"], "signature": sig})
    assert v.status_code == 200
    gtok2 = v.json()["gateway_token"]
    assert gtok2 != gtok1
    gh2 = {"Authorization": f"Bearer {gtok2}"}
    assert c.post("/api/v1/gateways/heartbeat", headers=gh2, json={"nonce": "2"}).status_code == 200


def test_admin_and_health():
    assert c.get("/health").json()["status"] == "ok"
    assert c.get("/ready").json()["status"] in ("ready", "degraded")
    m = c.get("/metrics")
    assert "sessions_active" in m.json()
