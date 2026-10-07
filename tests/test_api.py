"""Integration tests vs SQLite (same models as Postgres). Covers Guide §19 core."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_odivora.db"
os.environ["PAIRING_PREFILL"] = "true"  # claim autofill endpoint is exercised below

import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

TEST_URL = "sqlite:///./test_odivora.db"
try:
    if os.path.exists("./test_odivora.db"):
        os.remove("./test_odivora.db")
except PermissionError:
    pass

engine = create_engine(TEST_URL, connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_db
client = TestClient(app)


def reg_login(email="u1@example.com", pw="Password123!"):
    r = client.post("/api/v1/auth/register", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    tok = r.json()
    return tok


def test_register_login_refresh():
    t = reg_login("a@example.com")
    assert "access_token" in t
    r = client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "Password123!"})
    assert r.status_code == 200
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": r.json()["refresh_token"]})
    assert r2.status_code == 200


def test_device_revoke_blocks():
    t = reg_login("dev@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    devs = client.get("/api/v1/me/devices", headers=h).json()
    assert len(devs) >= 1
    did = devs[0]["id"]
    # revoke own device -> access token from that device must now fail
    r = client.delete(f"/api/v1/me/devices/{did}", headers=h)
    assert r.status_code == 200
    r2 = client.get("/api/v1/me", headers=h)
    assert r2.status_code == 401


def _gateway_flow(email="gw@example.com"):
    t = reg_login(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = client.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": "pubkey-valid-" + email + "-0123456789",
        "firmware_version": "1.0"})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    c = client.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h)
    assert c.status_code == 200, c.text
    gtok = c.json()["gateway_token"]
    gh = {"Authorization": f"Bearer {gtok}"}
    hb = client.post("/api/v1/gateways/heartbeat", json={"firmware_version": "1.0"}, headers=gh)
    assert hb.status_code == 200
    return t, h, gid, gtok


def test_gateway_pairing_auth_and_revoke():
    t, h, gid, gtok = _gateway_flow("gw1@example.com")
    # bad code rejected
    r = client.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": "k2-valid-public-key-0123456789"})
    gid2 = r.json()["gateway_id"]
    bad = client.post(f"/api/v1/me/gateways/{gid2}/claim", json={"pairing_code": "000000"}, headers=h)
    assert bad.status_code == 403
    # owner can revoke
    rv = client.post(f"/api/v1/me/gateways/{gid}/revoke", headers=h)
    assert rv.status_code == 200


def test_pending_pairings_prefill():
    # Claim autofill: candidates come back with a FRESH code (register-time
    # code is rotated by the fetch); claiming consumes the candidate.
    t = reg_login("prefill@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = client.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": "k-prefill-valid-key-0123456789"})
    assert r.status_code == 200, r.text
    gid = r.json()["gateway_id"]
    pf = client.get("/api/v1/me/pending-pairings", headers=h)
    assert pf.status_code == 200, pf.text
    cand = {c["gateway_id"]: c for c in pf.json()}
    assert gid in cand
    old = client.post(f"/api/v1/me/gateways/{gid}/claim",
                      json={"pairing_code": r.json()["pairing_code"]}, headers=h)
    assert old.status_code == 403  # register-time code no longer valid
    c = client.post(f"/api/v1/me/gateways/{gid}/claim",
                    json={"pairing_code": cand[gid]["pairing_code"]}, headers=h)
    assert c.status_code == 200, c.text
    pf2 = client.get("/api/v1/me/pending-pairings", headers=h)
    assert gid not in {x["gateway_id"] for x in pf2.json()}


def test_unauthorized_gateway_access():
    _, _, gid, _ = _gateway_flow("owner@example.com")
    other = reg_login("intruder@example.com")
    oh = {"Authorization": f"Bearer {other['access_token']}"}
    # intruder cannot create connection to someone else's gateway
    r = client.post("/api/v1/connections", json={"gateway_id": gid}, headers=oh)
    assert r.status_code == 403


def test_offline_gateway_rejected_then_online_ok():
    t = reg_login("off@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = client.post("/api/v1/gateways/register", json={
        "device_type": "linux", "public_key": "k-off-valid-public-key-0123456789"})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    client.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h)
    # no heartbeat -> offline -> 409
    rej = client.post("/api/v1/connections", json={"gateway_id": gid}, headers=h)
    assert rej.status_code == 409
    # heartbeat tested in _gateway_flow; here fetch gateway token via re-claim? claim cleared code.
    # Instead directly connect after marking online via heartbeat is covered in next test.


def test_connection_lifecycle_and_concurrent():
    t, h, gid, gtok = _gateway_flow("sess@example.com")
    r1 = client.post("/api/v1/connections", json={"gateway_id": gid}, headers=h)
    assert r1.status_code == 200, r1.text
    sid = r1.json()["id"]
    # same gateway again -> resume the active session (no duplicate, no 403)
    r_cap = client.post("/api/v1/connections", json={"gateway_id": gid}, headers=h)
    assert r_cap.status_code == 200, r_cap.text
    assert r_cap.json()["id"] == sid
    # the cap still bites: a parallel session on a DIFFERENT gateway -> 403
    rg = client.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": "k-cap2-valid-key-0123456789"})
    gid2, gcode = rg.json()["gateway_id"], rg.json()["pairing_code"]
    c2 = client.post(f"/api/v1/me/gateways/{gid2}/claim",
                     json={"pairing_code": gcode}, headers=h)
    assert c2.status_code == 200, c2.text
    client.post("/api/v1/gateways/heartbeat", json={"firmware_version": "1.0"},
                headers={"Authorization": f"Bearer {c2.json()['gateway_token']}"})
    r_par = client.post("/api/v1/connections", json={"gateway_id": gid2}, headers=h)
    assert r_par.status_code == 403
    g = client.get(f"/api/v1/connections/{sid}", headers=h)
    assert g.json()["status"] == "authorized"
    # authorized -> connecting -> connected -> disconnecting -> disconnected
    for nxt in ["connecting", "connected", "disconnecting", "disconnected"]:
        p = client.patch(f"/api/v1/connections/{sid}", json={"status": nxt}, headers=h)
        assert p.status_code == 200, p.text
    # illegal transition must 409
    bad = client.patch(f"/api/v1/connections/{sid}", json={"status": "connected"}, headers=h)
    assert bad.status_code == 409
    # after disconnect, slot frees: new session allowed then revoked via DELETE
    r2 = client.post("/api/v1/connections", json={"gateway_id": gid}, headers=h)
    assert r2.status_code == 200, r2.text
    d = client.delete(f"/api/v1/connections/{r2.json()['id']}", headers=h)
    assert d.json()["status"] == "revoked"
