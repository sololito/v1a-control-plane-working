"""End-to-end: what the API does when the tunnel relay is unreachable.

This is the guarantee that a session is never advertised with an endpoint
nothing is listening on. `authorize-wg` must fail with 503 and leave no trace,
rather than commit a session whose ports were never bound — the old behaviour
made a relay outage look like a working tunnel until a phone timed out on a
handshake nobody could answer.

The relay URL is pinned on the cached Settings instance in a fixture rather
than via os.environ: get_settings() is lru_cache'd, so by the time this module
is imported an earlier test module has already built the Settings from .env —
and the repo .env points at a relay that may genuinely be running on localhost.
"""
import importlib.util
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = "sqlite:///./test_relay_api.db"

try:
    if os.path.exists("./test_relay_api.db"):
        os.remove("./test_relay_api.db")
except PermissionError:
    pass

import base64

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_relay_api.db",
                       connect_args={"check_same_thread": False})
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

from app import ratelimit  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.routers import auth as auth_router  # noqa: E402

_RELAY_PATH = Path(__file__).resolve().parents[1] / "firmware" / "relay" / "odivora_relay.py"
_spec = importlib.util.spec_from_file_location("odivora_relay_api_test", _RELAY_PATH)
relay_mod = importlib.util.module_from_spec(_spec)
sys.modules["odivora_relay_api_test"] = relay_mod
_spec.loader.exec_module(relay_mod)


class ControlServer:
    """The real relay control surface on a real port."""

    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), relay_mod.ControlHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


DEAD_RELAY_URL = "http://127.0.0.1:9"  # discard port, closed


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    # Default every test to a relay that cannot be reached, and make the
    # failure fast enough not to dominate the suite.
    monkeypatch.setattr(get_settings(), "relay_control_url", DEAD_RELAY_URL)
    monkeypatch.setattr(get_settings(), "relay_control_retries", 1)
    monkeypatch.setattr(get_settings(), "relay_control_timeout_seconds", 0.25)
    monkeypatch.setattr(get_settings(), "relay_control_backoff_seconds", 0.0)
    yield
    app.dependency_overrides[get_db] = override
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
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
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
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]},
               headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    return h, gtok, gid


def _session_row(session_id):
    from app import models
    db = TestingSession()
    try:
        return db.query(models.ConnectionSession).filter(
            models.ConnectionSession.id == session_id).first()
    finally:
        db.close()


def test_authorize_returns_503_when_the_relay_is_unreachable():
    h, _gtok, gid = make_gateway("relaydown@example.com")
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    baseline = _session_row(s["id"])
    assert baseline.relay_info is None and baseline.wg_assigned_ip is None

    r = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert r.status_code == 503, r.text
    assert "relay" in r.json()["detail"].lower()

    # The critical part: no endpoint is advertised and no peer was authorized.
    # POST /connections creates the row as "authorized", so status is not the
    # signal here — relay_info and the tunnel IP are.
    row = _session_row(s["id"])
    assert row is not None
    assert row.relay_info is None, "a dead relay endpoint was persisted"
    assert row.connection_path != "relay", f"left on {row.connection_path}"
    assert row.wg_assigned_ip is None, "tunnel IP was allocated for a failed relay"
    assert row.wg_peer_public_key is None, "peer was authorized despite the failure"

    # And the gateway was never told about a peer it cannot serve.
    peers = c.get(f"/api/v1/gateways/{gid}/peers", headers=h)
    assert peers.status_code in (401, 403)


def test_authorize_leaves_no_port_reservation_behind_after_a_relay_failure():
    """Repeated failures must not eat the port pool."""
    from app import relay as cloud_relay
    # A fresh user per round: the default entitlement allows one session each.
    for i in range(4):
        h, _gtok, gid = make_gateway(f"relaypool{i}@example.com")
        s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
        r = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
        assert r.status_code == 503, r.text
    assert cloud_relay._allocations == {}, cloud_relay._allocations


def test_authorize_succeeds_against_a_live_relay(monkeypatch):
    """The 503 must be a real failure signal, not a blanket refusal."""
    server = ControlServer()
    monkeypatch.setattr(get_settings(), "relay_control_url", server.url)
    try:
        h, _gtok, gid = make_gateway("relayup@example.com")
        s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
        r = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["connection_path"] == "relay"
        assert body["relay"]["phone_port"] and body["relay"]["gateway_port"]
        # And the relay really is holding those sockets, so the advertised
        # endpoint is one a phone can actually reach.
        live = relay_mod.snapshot()
        ids = {e["session_id"] for e in live}
        assert str(s["id"]) in ids
        row = _session_row(s["id"])
        assert row.status == "authorized"
        assert json.loads(row.relay_info)["phone_endpoint"]
    finally:
        server.close()


def test_revoking_an_unreachable_relay_still_succeeds(monkeypatch):
    """A revoke is a security action and must complete even if the relay is down."""
    server = ControlServer()
    monkeypatch.setattr(get_settings(), "relay_control_url", server.url)
    h, _gtok, gid = make_gateway("relayrevoke@example.com")
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    assert c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h).status_code == 200
    server.close()  # relay now unreachable

    r = c.post(f"/api/v1/sessions/{s['id']}/revoke-wg", headers=h)
    assert r.status_code == 200, r.text
    row = _session_row(s["id"])
    assert row.status == "revoked"

