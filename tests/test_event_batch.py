"""`POST /gateways/{id}/events/batch` — the store-and-forward landing strip.

The gateway ships what it observed while the Cloud was unreachable; the
contract that makes that safe (GATEWAY_EVENT_CACHE.md §3–§5):

  * only the gateway whose id is in the path may write to it, and only with
    its own bearer token;
  * `event_id` (minted by the gateway) makes a resend a duplicate, never a
    second copy — inside one batch and across batches;
  * the endpoint is bounded (count, bytes, payload, type length) because an
    agent bug must not be able to grow the table without limit;
  * `received_at`/`remote_ip` are what the Cloud observed, and they are kept
    apart from the gateway's own clock;
  * rows are evidence, not history: the retention job prunes them on the
    server's clock.
"""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_event_batch.db"
try:
    if os.path.exists("./test_event_batch.db"):
        os.remove("./test_event_batch.db")
except PermissionError:
    pass

import base64
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_event_batch.db",
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
from app.config import get_settings
from app.jobs import prune_gateway_events
from app.routers import auth as auth_router

_seq = {"n": 0}


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


def make_admin(email="events-admin@example.com"):
    r = c.post("/api/v1/auth/register",
               json={"email": email, "password": "Password123!"})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    db = TestingSession()
    try:
        from app import models
        u = db.query(models.User).filter(models.User.email == email).first()
        u.is_admin = True
        db.commit()
    finally:
        db.close()
    return headers(tok)


def make_gateway(owner=None):
    """(owner_headers, gateway_id, gateway_headers) for a claimed gateway."""
    _seq["n"] += 1
    email = owner or f"owner{_seq['n']}@example.com"
    h = headers(c.post("/api/v1/auth/register",
                       json={"email": email, "password": "Password123!"}
                       ).json()["access_token"])
    raw = (base64.b64encode(os.urandom(32))).decode()
    r = c.post("/api/v1/gateways/register",
               json={"device_type": "linux", "public_key": raw})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    return h, gid, headers(gtok)


def event(**over):
    """One row as the agent writes it: gateway uuid, gateway clock."""
    row = {"event_id": str(uuid.uuid4()),
           "recorded_at": "2026-10-06T19:44:12.413Z",
           "type": "peer_added",
           "payload": {"peer_public_key": "abc123", "allowed_ip": "10.8.0.3"}}
    row.update(over)
    return row


def ship(gid, gh, events, query=""):
    return c.post(f"/api/v1/gateways/{gid}/events/batch{query}",
                  json={"events": events}, headers=gh)


# ------------------------------------------------------------------- auth ---

def test_only_the_gateway_itself_can_ship_to_its_own_path():
    _, gid, gh = make_gateway()
    other = make_gateway()[2]

    assert c.post(f"/api/v1/gateways/{gid}/events/batch",
                  json={"events": [event()]}).status_code == 401
    # A user token is not a gateway token.
    user = make_gateway()[0]
    assert ship(gid, user, [event()]).status_code == 401
    # And this gateway's token may not write to another gateway's table.
    assert ship(gid, other, [event()]).status_code == 403


def test_a_heartbeat_still_works_after_a_batch():
    """The batch route shares the gateway token; it must not consume or
    rotate anything the heartbeat path needs."""
    _, gid, gh = make_gateway()
    assert ship(gid, gh, [event()]).status_code == 200
    assert c.post("/api/v1/gateways/heartbeat", json={}, headers=gh).status_code == 200


# ------------------------------------------------------------------ dedupe ---

def test_a_duplicated_id_inside_one_batch_is_stored_once():
    _, gid, gh = make_gateway()
    row = event()

    res = ship(gid, gh, [row, dict(row)])

    assert res.status_code == 200
    assert res.json() == {"ok": True, "stored": 1, "duplicates": 1}
    db = TestingSession()
    try:
        from app import models
        n = db.query(models.GatewayEvent).filter(
            models.GatewayEvent.event_id == row["event_id"]).count()
        assert n == 1
    finally:
        db.close()


def test_a_resent_batch_after_a_lost_response_is_a_noop():
    """The agent only trims its queue on a 2xx, so a response lost in flight
    means the same rows arrive twice and must be counted, not copied."""
    _, gid, gh = make_gateway()
    rows = [event(type="peer_added"), event(type="peer_removed")]

    first = ship(gid, gh, rows).json()
    second = ship(gid, gh, rows).json()

    assert first == {"ok": True, "stored": 2, "duplicates": 0}
    assert second == {"ok": True, "stored": 0, "duplicates": 2}
    db = TestingSession()
    try:
        from app import models
        n = db.query(models.GatewayEvent).filter(
            models.GatewayEvent.event_id.in_([r["event_id"] for r in rows])).count()
        assert n == 2
    finally:
        db.close()


def test_an_audit_row_records_the_drain_not_every_event():
    _, gid, gh = make_gateway()
    admin = make_admin("batch-audit@example.com")
    ship(gid, gh, [event(), event()])

    audit = c.get(f"/api/v1/admin/audit?action=gateway.events_batch"
                  f"&resource_id={gid}",
                  headers=admin).json()
    assert audit["total"] == 1
    assert '"stored": 2' in audit["items"][0]["detail"]


# -------------------------------------------------------------------- caps ---

def test_a_batch_larger_than_the_event_cap_is_rejected():
    _, gid, gh = make_gateway()

    res = ship(gid, gh, [event() for _ in range(201)])

    assert res.status_code == 422
    assert "200 events" in res.json()["detail"]


def test_a_batch_larger_than_the_byte_cap_is_rejected():
    _, gid, gh = make_gateway()
    rows = [event(payload={"pad": "x" * 2000}) for _ in range(200)]

    res = ship(gid, gh, rows)

    assert res.status_code == 422
    assert "bytes" in res.json()["detail"]


def test_an_oversized_payload_is_rejected_on_its_own():
    _, gid, gh = make_gateway()

    res = ship(gid, gh, [event(payload={"pad": "x" * 9000})])

    assert res.status_code == 422
    assert "payload too large" in res.json()["detail"]


def test_malformed_rows_are_rejected_before_anything_is_stored():
    _, gid, gh = make_gateway()

    assert ship(gid, gh, [event(event_id="not-a-uuid")]).status_code == 422
    assert ship(gid, gh, [event(recorded_at="yesterday")]).status_code == 422
    assert ship(gid, gh, [event(type="x" * 61)]).status_code == 422
    assert ship(gid, gh, []).status_code == 422

    # Nothing was half-stored by the attempts above.
    res = ship(gid, gh, [event()])
    assert res.json() == {"ok": True, "stored": 1, "duplicates": 0}


# --------------------------------------------------------- clocks / provenance ---

def test_each_row_keeps_the_gateway_clock_and_the_clouds_observation():
    _, gid, gh = make_gateway()
    before = datetime.utcnow()
    row_in = event(recorded_at="2026-10-06T19:44:12.413Z")
    ship(gid, gh, [row_in])

    db = TestingSession()
    try:
        from app import models
        row = db.query(models.GatewayEvent).filter(
            models.GatewayEvent.event_id == row_in["event_id"]).first()
        # created_at is the *gateway's* claim about when it saw the event …
        assert row.created_at == datetime(2026, 10, 6, 19, 44, 12, 413000)
        # … received_at and the source IP are what the Cloud observed.
        assert before <= row.received_at <= datetime.utcnow() + timedelta(seconds=5)
        assert row.remote_ip
    finally:
        db.close()


def test_an_offset_is_normalised_to_utc():
    _, gid, gh = make_gateway()
    row_in = event(recorded_at="2026-10-06T22:44:12.413+03:00")
    ship(gid, gh, [row_in])

    db = TestingSession()
    try:
        from app import models
        row = db.query(models.GatewayEvent).filter(
            models.GatewayEvent.event_id == row_in["event_id"]).first()
        assert row.created_at == datetime(2026, 10, 6, 19, 44, 12, 413000)
    finally:
        db.close()


# ------------------------------------------------------------- rate limit ---

def test_the_batch_has_its_own_rate_limit_bucket(monkeypatch):
    _, gid, gh = make_gateway()
    monkeypatch.setattr(get_settings(), "gateway_rate_per_minute", 3)

    codes = [ship(gid, gh, [event()]).status_code for _ in range(4)]

    assert codes == [200, 200, 200, 429]


# --------------------------------------------------------------- admin API ---

def test_admin_events_query_orders_filters_and_labels_itself():
    _, gid, gh = make_gateway()
    admin = make_admin("events-admin2@example.com")
    ship(gid, gh, [
        event(recorded_at="2026-01-01T10:00:00.000Z", type="peer_added"),
        event(recorded_at="2026-06-01T10:00:00.000Z", type="wan_ip_changed"),
        event(recorded_at="2026-10-01T10:00:00.000Z", type="sync_error"),
    ])

    res = c.get(f"/api/v1/admin/gateways/{gid}/events", headers=admin)
    assert res.status_code == 200
    body = res.json()
    assert body["gateway_id"] == gid
    assert body["note"] == "gateway-reported (unverified)"
    assert [e["type"] for e in body["items"]] == [
        "sync_error", "wan_ip_changed", "peer_added"]  # newest first

    filtered = c.get(f"/api/v1/admin/gateways/{gid}/events"
                     f"?since=2026-03-01T00:00:00&type=wan_ip_changed",
                     headers=admin).json()
    assert [e["type"] for e in filtered["items"]] == ["wan_ip_changed"]
    assert filtered["total"] == 1
    assert filtered["items"][0]["unverified"] is True
    assert filtered["items"][0]["received_at"]

    # Admin-only, like every other /admin route.
    _, _, gh2 = make_gateway()
    assert c.get(f"/api/v1/admin/gateways/{gid}/events").status_code == 401


# -------------------------------------------------------------- retention ---

def test_retention_prunes_on_the_servers_clock_not_the_sensors():
    _, gid, gh = make_gateway()
    ship(gid, gh, [event()])
    db = TestingSession()
    try:
        from app import models
        now = datetime.utcnow()
        rows = [
            # Fresh, sensor-stamped: kept.
            models.GatewayEvent(gateway_id=gid, event_type="peer_added",
                                event_id=str(uuid.uuid4()), received_at=now),
            # Arrived 120 days ago: gone.
            models.GatewayEvent(gateway_id=gid, event_type="peer_removed",
                                event_id=str(uuid.uuid4()),
                                received_at=now - timedelta(days=120)),
            # Server-generated (no received_at): ages from created_at, gone.
            models.GatewayEvent(gateway_id=gid, event_type="heartbeat",
                                created_at=now - timedelta(days=120)),
            # A sensor stamping its own clock a year ahead cannot keep its
            # rows alive: age comes from when the Cloud received them.
            models.GatewayEvent(gateway_id=gid, event_type="sync_error",
                                event_id=str(uuid.uuid4()),
                                received_at=now,
                                created_at=now + timedelta(days=365)),
        ]
        db.add_all(rows)
        db.commit()
        mine = {r.event_id for r in rows if r.event_id}

        assert prune_gateway_events(db, 90) == 2
        surviving = {r.event_id for r in db.query(models.GatewayEvent).filter(
            models.GatewayEvent.gateway_id == gid,
            models.GatewayEvent.event_id.isnot(None))}
        assert surviving & mine == {rows[0].event_id, rows[3].event_id}
        assert prune_gateway_events(db, 0) == 0   # 0 disables the sweep
    finally:
        db.close()
