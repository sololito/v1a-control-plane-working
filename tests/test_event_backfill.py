"""Store-and-forward, end to end: the outage nobody planned for.

The whole point of GATEWAY_EVENT_CACHE.md in one script: the gateway keeps
observing while the Cloud is unreachable, the rows wait in the local queue,
one healthy heartbeat drains them, a response lost in flight costs nothing,
and the audit report says plainly that these rows are the sensor's word.
"""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_event_backfill.db"
try:
    if os.path.exists("./test_event_backfill.db"):
        os.remove("./test_event_backfill.db")
except PermissionError:
    pass

import base64
import json
import sys
import time
import uuid
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_event_backfill.db",
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

from app import ratelimit
from app.gateway.events import EventSpool
from app.routers import auth as auth_router

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "firmware", "linux_gateway"))
import gateway_agent as agent  # noqa: E402


@pytest.fixture(autouse=True)
def _clear():
    app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()
    auth_router._fails.clear()


def headers(tok):
    return {"Authorization": f"Bearer {tok}"}


def setup_tunnel():
    """(admin_headers, gateway_id, gateway_headers, cfg) for one home box."""
    email = f"backfill{uuid.uuid4().hex[:8]}@example.com"
    admin = headers(c.post("/api/v1/auth/register",
                           json={"email": email, "password": "Password123!"}
                           ).json()["access_token"])
    db = TestingSession()
    try:
        from app import models
        db.query(models.User).filter(models.User.email == email).first().is_admin = True
        db.commit()
    finally:
        db.close()

    raw = base64.b64encode(os.urandom(32)).decode()
    r = c.post("/api/v1/gateways/register",
               json={"device_type": "linux", "public_key": raw})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=admin).json()["gateway_token"]
    cfg = {"ODIVORA_API_BASE": "http://testserver", "GATEWAY_ID": gid,
           "GATEWAY_TOKEN": gtok}
    return admin, gid, headers(gtok), cfg


@pytest.fixture
def cloud(monkeypatch):
    """The agent's `_post`, pointed at the test app, with an outage switch.

    `lose_response` reproduces the nastiest outage: the server stores the
    rows and the reply never arrives.
    """
    state = {"offline": False, "lose_response": False, "calls": []}

    def fake_post(url, payload=None, token=None, timeout=20):
        path = "/api/v1" + url.split("/api/v1", 1)[1]
        if state["offline"]:
            return 503, {"error": "cloud down"}
        state["calls"].append(path)
        r = c.post(path, json=payload, headers={"Authorization": f"Bearer {token}"})
        if state["lose_response"]:
            return 0, {"error": "read timed out"}
        body = r.json() if r.text else {}
        return r.status_code, body

    monkeypatch.setattr(agent, "_post", fake_post)
    return state


def test_events_survive_an_outage_and_land_as_one_backlog(tmp_path, cloud):
    admin, gid, _, cfg = setup_tunnel()
    spool = EventSpool(str(tmp_path / "events.jsonl"))

    # --- the Cloud goes down; the gateway keeps working and keeps notes ---
    cloud["offline"] = True
    spool.emit("peer_added", {"peer_public_key": "aaa", "allowed_ip": "10.8.0.2"})
    spool.emit("sync_error", {"error": "wg show: netlink unreachable"})
    spool.emit("wan_ip_changed", {"old": "196.201.1.5", "new": "196.201.9.9"})
    assert spool.depth() == 3

    res = agent.ship_events(cfg, spool, {}, min_events=1, min_age=0)
    assert res is None                     # nothing landed …
    assert spool.depth() == 3              # … and nothing was thrown away
    assert not cloud["calls"]              # the outage is detected up front

    # Still down: the queue grows rather than the agent giving up.
    spool.emit("peer_removed", {"peer_public_key": "bbb"})
    spool.emit("handshake_seen", {"peer_public_key": "aaa"})
    assert agent.ship_events(cfg, spool, {}, min_events=1, min_age=0) is None
    assert spool.depth() == 5

    # --- recovery: one batch drains the whole backlog ---
    cloud["offline"] = False
    res = agent.ship_events(cfg, spool, {}, min_events=1, min_age=0)

    assert res == {"ok": True, "stored": 5, "duplicates": 0}
    assert spool.depth() == 0
    # Second drain is a no-op: there is nothing left to say.
    assert agent.ship_events(cfg, spool, {}, min_events=1, min_age=0) is None

    report = c.get(f"/api/v1/admin/tunnels/{gid}/audit", headers=admin).json()
    assert report["summary"]["gateway_events"] == 5
    assert "unverified" in report["evidence_note"]
    events = report["gateway_events"]
    assert {e["type"] for e in events} == {
        "peer_added", "sync_error", "wan_ip_changed",
        "peer_removed", "handshake_seen"}
    times = [e["at"] for e in events]
    assert times == sorted(times, reverse=True)   # newest first, ties allowed
    assert all(e["unverified"] for e in events)
    assert all(e["received_at"] for e in events)


def test_a_response_lost_in_flight_costs_nothing_but_a_retry(tmp_path, cloud):
    admin, gid, _, cfg = setup_tunnel()
    spool = EventSpool(str(tmp_path / "events.jsonl"))
    for i in range(4):
        spool.emit("peer_added", {"n": i})

    # The server stores the rows; the reply never makes it back.
    cloud["lose_response"] = True
    assert agent.ship_events(cfg, spool, {}, min_events=1, min_age=0) is None
    assert spool.depth() == 4   # not acked, so it will be sent again

    cloud["lose_response"] = False
    res = agent.ship_events(cfg, spool, {}, min_events=1, min_age=0)

    assert res["stored"] == 0 and res["duplicates"] == 4
    assert spool.depth() == 0
    db = TestingSession()
    try:
        from app import models
        n = db.query(models.GatewayEvent).filter(
            models.GatewayEvent.gateway_id == gid,
            models.GatewayEvent.event_id.isnot(None)).count()
        assert n == 4   # four claims, not eight
    finally:
        db.close()


def test_a_quiet_gateway_does_not_spend_a_round_trip(tmp_path, cloud):
    _, _, _, cfg = setup_tunnel()
    spool = EventSpool(str(tmp_path / "events.jsonl"))
    spool.emit("agent_started", {"pid": 1})

    tracker = {"last_attempt": time.monotonic()}

    assert agent.ship_events(cfg, spool, tracker, min_events=20, min_age=30) is None
    assert not cloud["calls"]
    # …but it does not sit on them forever: once the window passes, they go.
    tracker["last_attempt"] = time.monotonic() - 31
    assert agent.ship_events(cfg, spool, tracker, min_events=20, min_age=30) is not None
    assert spool.depth() == 0


def test_the_report_trusts_the_clouds_clock_over_a_wrong_sensor_clock(tmp_path,
                                                                      cloud):
    """A freshly imaged gateway with no NTP stamps rows years away. The reader
    sees the time the Cloud learned it, and is told the sensor is suspect."""
    admin, gid, _, cfg = setup_tunnel()
    spool = EventSpool(str(tmp_path / "events.jsonl"))
    spool.emit("peer_added", {"peer_public_key": "aaa"})
    with open(spool.path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"event_id": str(uuid.uuid4()),
                            "recorded_at": "2020-01-01T00:00:00.000Z",
                            "type": "wan_ip_changed",
                            "payload": {"old": "10.0.0.1", "new": "10.0.0.2"}}) + "\n")

    assert agent.ship_events(cfg, spool, {}, min_events=1, min_age=0)["stored"] == 2

    report = c.get(f"/api/v1/admin/tunnels/{gid}/audit", headers=admin).json()
    by_type = {e["type"]: e for e in report["gateway_events"]}
    assert by_type["wan_ip_changed"]["clock_suspect"] is True
    assert by_type["wan_ip_changed"]["at"].startswith("2020-01-01")
    assert by_type["wan_ip_changed"]["shown_at"].startswith(
        str(datetime.utcnow().year))          # shown at the Cloud's time
    assert by_type["peer_added"]["clock_suspect"] is False

    page = c.get(f"/api/v1/admin/tunnels/{gid}/audit/print", headers=admin).text
    assert "Gateway-reported events" in page
    assert "unverified" in page
    assert "clock suspect" in page
