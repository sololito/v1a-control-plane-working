"""Firmware simulation: exact HTTP the ESP32 sketch sends (V1 bearer flow).

Simulates: register (chip-id pubkey) -> claim (user pastes token) ->
heartbeat counter 1..12 (crosses 9->10) -> reboot (counter restarts) ->
config fetch -> session create (phone) -> gateway session poll -> verify.
"""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_firmware.db"
try:
    if os.path.exists("./test_firmware.db"):
        os.remove("./test_firmware.db")
except PermissionError:
    pass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_firmware.db", connect_args={"check_same_thread": False})
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
    from app.main import app as _app
    _app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()


PUBKEY = "esp32-pubkey-ABCDEF123456-0123456789"  # shape of devicePublicKey()


def test_full_hardware_loop():
    # --- user provisions (phone/laptop) ---
    u = c.post("/api/v1/auth/register",
               json={"email": "hw@example.com", "password": "Password123!"}).json()
    uh = {"Authorization": f"Bearer {u['access_token']}"}
    # --- device first boot: register ---
    r = c.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": PUBKEY,
        "algorithm": "ed25519", "firmware_version": "1.0.0"})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    assert len(code) == 6 and code.isdigit()
    # --- user claims, pastes TOKEN to device ---
    claim = c.post(f"/api/v1/me/gateways/{gid}/claim",
                   json={"pairing_code": code}, headers=uh)
    assert claim.status_code == 200, claim.text
    gh = {"Authorization": f"Bearer {claim.json()['gateway_token']}"}
    # --- heartbeat counter 1..12 (firmware decimal counter, crosses 9->10) ---
    for n in range(1, 13):
        hb = c.post("/api/v1/gateways/heartbeat", headers=gh, json={
            "firmware_version": "1.0.0", "nonce": str(n),
            "health": {"heap": 200000, "rssi": -60}})
        assert hb.status_code == 200, f"nonce {n}: {hb.text}"
    # --- device reboot: counter restarts at 1, must resync not wedge ---
    for n in (1, 2, 3):
        hb = c.post("/api/v1/gateways/heartbeat", headers=gh, json={
            "firmware_version": "1.0.0", "nonce": str(n)})
        assert hb.status_code == 200, f"reboot nonce {n}: {hb.text}"
    # --- config fetch (firmware doFetchConfig) ---
    cfg = c.get(f"/api/v1/gateways/{gid}/configuration", headers=gh)
    assert cfg.status_code == 200 and "tunnel" in cfg.json()
    # --- phone outside home requests connection ---
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=uh)
    assert s.status_code == 200, s.text
    sid, stok = s.json()["id"], s.json()["session_token"]
    # --- device polls its sessions, sees the pending one ---
    lst = c.get(f"/api/v1/gateways/{gid}/sessions", headers=gh)
    assert lst.status_code == 200, lst.text
    assert any(x["id"] == sid and x["status"] == "authorized" for x in lst.json())
    # --- device verifies before opening tunnel ---
    v = c.post(f"/api/v1/connections/{sid}/verify", headers=gh,
               json={"gateway_id": gid, "session_token": stok})
    assert v.status_code == 200, v.text


def test_firmware_error_paths():
    u = c.post("/api/v1/auth/register",
               json={"email": "hw2@example.com", "password": "Password123!"}).json()
    uh = {"Authorization": f"Bearer {u['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={
        "device_type": "esp32", "public_key": PUBKEY + "zz",
        "algorithm": "ed25519", "firmware_version": "1.0.0"})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=uh).json()["gateway_token"]
    gh = {"Authorization": f"Bearer {gtok}"}
    # no token -> 401 (device before TOKEN paste)
    assert c.post("/api/v1/gateways/heartbeat", json={"nonce": "1"}).status_code == 401
    # wrong gateway id in path -> 403
    assert c.get("/api/v1/gateways/00000000-0000-0000-0000-000000000000/configuration",
                 headers=gh).status_code == 403
    assert c.get(f"/api/v1/gateways/00000000-0000-0000-0000-000000000000/sessions",
                 headers=gh).status_code == 403
    # tampered token -> 401
    bad = {"Authorization": f"Bearer {gtok}tampered"}
    assert c.post("/api/v1/gateways/heartbeat", headers=bad,
                  json={"nonce": "1"}).status_code == 401
    # true replay: same nonce twice in a row -> 409
    assert c.post("/api/v1/gateways/heartbeat", headers=gh,
                  json={"nonce": "50"}).status_code == 200
    assert c.post("/api/v1/gateways/heartbeat", headers=gh,
                  json={"nonce": "50"}).status_code == 409
