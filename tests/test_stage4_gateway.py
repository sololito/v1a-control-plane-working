"""V1B Stage 4: gateway peer-sync daemon, data-plane abstraction, path planner."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_stage4.db"
try:
    if os.path.exists("./test_stage4.db"):
        os.remove("./test_stage4.db")
except PermissionError:
    pass

import base64
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_stage4.db", connect_args={"check_same_thread": False})
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


def ed_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def make_gateway(email):
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": ed_keys()})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={},
           headers={"Authorization": f"Bearer {gtok}"})
    assert c.post(f"/api/v1/gateways/{gid}/generate-keys", headers=h).status_code == 200
    return h, gtok, gid


def test_gateway_peers_endpoint_scoped_and_token_authed():
    h, gtok, gid = make_gateway("s4owner@example.com")
    t = reg("s4user@example.com")
    uh = {"Authorization": f"Bearer {t['access_token']}"}
    # non-gateway token rejected
    bad = c.get(f"/api/v1/gateways/{gid}/peers", headers=uh)
    assert bad.status_code == 401
    # gateway token, no peers yet
    r = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    assert r.json()["peers"] == []
    # authorize one session on same gateway (owner creates connection)
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    a = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert a.status_code == 200, a.text
    r2 = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"}).json()
    assert len(r2["peers"]) == 1
    p = r2["peers"][0]
    assert p["allowed_ip"].endswith("/32") and len(p["peer_public_key"]) > 20
    assert "private" not in str(p).lower()
    # revoke clears it from active peer list
    c.post(f"/api/v1/sessions/{s['id']}/revoke-wg", headers=h)
    r3 = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"}).json()
    assert r3["peers"] == []


def test_dataplane_sync_adds_missing_and_removes_stale():
    from app.gateway.dataplane import InMemoryRunner, LinuxDataPlane, PeerSpec

    runner = InMemoryRunner(existing_peers=["OLDPEERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="])
    dp = LinuxDataPlane(runner=runner)
    desired = [PeerSpec("NEWPEERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "10.70.3.5/32", "s1")]
    result = dp.sync_peers(desired)
    assert result["added"] == ["NEWPEERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]
    assert result["removed"] and result["removed"][0].startswith("OLDPEER")
    # idempotent second run
    result2 = dp.sync_peers(desired)
    assert result2["added"] == [] and result2["removed"] == []


def test_linux_nat_idempotent():
    from app.gateway.dataplane import InMemoryRunner, LinuxDataPlane

    runner = InMemoryRunner()
    dp = LinuxDataPlane(runner=runner)
    dp.ensure_forwarding()
    dp.ensure_nat()
    cmds = [" ".join(a) for a in runner.commands]
    assert any("ip_forward=1" in c for c in cmds)
    assert any("POSTROUTING" in c and "MASQUERADE" in c for c in cmds)


def test_path_planner():
    from app.paths import plan_connection_path

    assert plan_connection_path(True, True)["path"] == "direct"
    assert plan_connection_path(False, True)["path"] == "unknown"
    assert plan_connection_path(True, False, relay_available=True)["path"] == "relay"
    assert plan_connection_path(True, False)["path"] == "unknown"
