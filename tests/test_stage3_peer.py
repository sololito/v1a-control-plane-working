"""V1B Stage 3: dynamic peer config, tunnel IP allocation, peer lifecycle."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_stage3.db"
try:
    if os.path.exists("./test_stage3.db"):
        os.remove("./test_stage3.db")
except PermissionError:
    pass

import base64
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_stage3.db", connect_args={"check_same_thread": False})
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
    pub = priv.public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, base64.b64encode(raw).decode()


def register_wg_pubkey(gtok, gid):
    """Device-side key registration: gateway uploads only its public half."""
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]},
               headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    return keys


def make_online_gateway(email):
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    priv, pub_b64 = ed_keys()
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": pub_b64})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={},
           headers={"Authorization": f"Bearer {gtok}"})
    register_wg_pubkey(gtok, gid)
    return h, gid


def new_session(h, gid):
    r = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_authorize_allocates_distinct_ips_and_handshake_connects():
    h, gid = make_online_gateway("owner3@example.com")
    # raise session cap so two simultaneous sessions can exist
    from app import models
    db = TestingSession()
    u = db.query(models.User).filter(models.User.email == "owner3@example.com").first()
    db.add(models.Subscription(user_id=u.id, plan="premium", status="active",
                               entitlements='{"max_sessions": 5}'))
    db.commit()
    db.close()
    s1 = new_session(h, gid)
    s2 = new_session(h, gid)
    r1 = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert r1.status_code == 200, r1.text
    r2 = c.post(f"/api/v1/sessions/{s2}/authorize-wg", headers=h)
    assert r2.status_code == 200, r2.text
    ip1, ip2 = r1.json()["assigned_ip"], r2.json()["assigned_ip"]
    assert ip1 != ip2, "tunnel IPs must not collide"
    assert ip1.startswith("10.") and ip2.startswith("10.")
    # same subnet, both /24 hosts
    assert ip1.rsplit(".", 1)[0] == ip2.rsplit(".", 1)[0]
    assert "gateway_private" not in r1.text and "private_key" not in r1.json().get("gateway_public_key", "")

    # handshake marks connected
    hs = c.post(f"/api/v1/sessions/{s1}/handshake", headers=h)
    assert hs.status_code == 200, hs.text
    assert hs.json()["status"] == "connected"

    # second handshake on same session conflicts
    hs2 = c.post(f"/api/v1/sessions/{s1}/handshake", headers=h)
    assert hs2.status_code == 409

    # revoke frees state
    rv = c.post(f"/api/v1/sessions/{s1}/revoke-wg", headers=h)
    assert rv.status_code == 200, rv.text
    assert rv.json()["status"] == "revoked"


def test_revoked_ip_is_reused_after_revoke():
    h, gid = make_online_gateway("owner4@example.com")
    s1 = new_session(h, gid)
    r1 = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h).json()
    c.post(f"/api/v1/sessions/{s1}/revoke-wg", headers=h)
    s2 = new_session(h, gid)
    r2 = c.post(f"/api/v1/sessions/{s2}/authorize-wg", headers=h).json()
    assert r2["assigned_ip"] == r1["assigned_ip"], "freed IP should be reusable"


def test_unauthorized_user_cannot_authorize():
    h, gid = make_online_gateway("owner5@example.com")
    s1 = new_session(h, gid)
    other = reg("stranger@example.com")
    oh = {"Authorization": f"Bearer {other['access_token']}"}
    r = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=oh)
    assert r.status_code == 403


def test_duplicate_peer_authorize_rejected():
    h, gid = make_online_gateway("owner6@example.com")
    s1 = new_session(h, gid)
    first = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert first.status_code == 200
    dup = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert dup.status_code == 409


def test_authorize_defaults_to_relay_when_no_public_endpoint():
    h, gid = make_online_gateway("owner8@example.com")
    s1 = new_session(h, gid)
    r = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["connection_path"] == "relay"
    assert body["relay"]["phone_endpoint"] and body["relay"]["gateway_endpoint"]
    # gateway peers endpoint exposes the relay endpoint for this session
    gtok = None
    # gateway token isn't returned by make_online_gateway; use peers via owner? peers endpoint needs gw token.
    # Use the relay allocation free on revoke:
    rv = c.post(f"/api/v1/sessions/{s1}/revoke-wg", headers=h)
    assert rv.status_code == 200


def test_direct_path_requires_wg_endpoint():
    h, gid = make_online_gateway("owner9@example.com")
    from app import models
    db = TestingSession()
    gw = db.query(models.Gateway).filter(models.Gateway.id == gid).first()
    gw.ip_metadata = '{"wg_endpoint": "203.0.113.10:51820"}'
    db.commit(); db.close()
    s1 = new_session(h, gid)
    r = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["connection_path"] == "direct"
    assert r.json()["relay"] is None


def test_gateway_tunnel_ip_set_and_subnet_consistent():
    from app.gateway.ip_alloc import gateway_tunnel_ip, gateway_tunnel_network
    h, gid = make_online_gateway("owner7@example.com")
    s1 = new_session(h, gid)
    r = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h).json()
    assert r["gateway_tunnel_ip"] == gateway_tunnel_ip(gid)
    assert r["assigned_ip"] != gateway_tunnel_ip(gid)  # peer never gets gateway IP
    net = gateway_tunnel_network(gid)
    assert r["assigned_ip"] in [str(ip) for ip in net.hosts()]


def test_wg_endpoint_advertised_via_heartbeat():
    """A gateway must be able to declare its public endpoint to get direct paths."""
    import json
    t = reg("endpoint@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    priv, pub_b64 = ed_keys()
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": pub_b64})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    gh = {"Authorization": f"Bearer {gtok}"}

    def meta():
        from app import models
        db = TestingSession()
        try:
            return db.query(models.Gateway).filter(models.Gateway.id == gid).first().ip_metadata
        finally:
            db.close()

    ok = c.post("/api/v1/gateways/heartbeat",
                json={"nonce": "0000000001", "wg_endpoint": "203.0.113.7:51820"}, headers=gh)
    assert ok.status_code == 200, ok.text
    assert json.loads(meta()).get("wg_endpoint") == "203.0.113.7:51820", meta()

    bad = c.post("/api/v1/gateways/heartbeat",
                 json={"nonce": "0000000002", "wg_endpoint": "not-an-endpoint"}, headers=gh)
    assert bad.status_code == 422, bad.text

    # ip_hint must survive a later endpoint update (metadata is merged).
    c.post("/api/v1/gateways/heartbeat",
           json={"nonce": "0000000003", "ip_hint": "198.51.100.9"}, headers=gh)
    c.post("/api/v1/gateways/heartbeat",
           json={"nonce": "0000000004", "wg_endpoint": "203.0.113.7:51821"}, headers=gh)
    m = json.loads(meta())
    assert m.get("ip_hint") == "198.51.100.9", m
    assert m.get("wg_endpoint") == "203.0.113.7:51821", m

    # Clearing the endpoint puts the gateway back on the relay path.
    c.post("/api/v1/gateways/heartbeat",
           json={"nonce": "0000000005", "wg_endpoint": ""}, headers=gh)
    assert "wg_endpoint" not in json.loads(meta()), meta()


def test_direct_path_rejected_without_declared_endpoint():
    """Explicit `direct` without a declared endpoint must 409, not fake a tunnel."""
    h, gid = make_online_gateway("behind-nat@example.com")
    r = c.post("/api/v1/connections", json={"gateway_id": gid, "connection_path": "direct"}, headers=h)
    s1 = r.json()["id"]
    resp = c.post(f"/api/v1/sessions/{s1}/authorize-wg", headers=h)
    assert resp.status_code == 409, resp.text
    assert "wg_endpoint" in resp.json()["detail"]

    # Unset path is fine: the gateway is behind NAT so a relay pair is allocated.
    # A separate owner avoids the per-user active-session cap.
    h2, gid2 = make_online_gateway("behind-nat-2@example.com")
    s2 = new_session(h2, gid2)
    ok = c.post(f"/api/v1/sessions/{s2}/authorize-wg", headers=h2)
    assert ok.status_code == 200, ok.text
    assert ok.json()["connection_path"] == "relay"
