"""Cross-cutting plumbing nobody's feature depends on, until it breaks.

Three subsystems that only become visible under stress:

  * `app.middleware` — every response must carry a request id an operator can
    grep for, the browser-hardening headers must be on *every* reply, and an
    unhandled exception must come back as a body carrying that id rather than
    a stack trace. Leaking a traceback is an information disclosure; losing the
    id makes a 500 untraceable in the logs.
  * `app.ratelimit` — the sliding window that keeps auth endpoints from being
    brute-forced. What matters is not "it limits" but that scopes are isolated
    (a hammering gateway must not lock a user out of login), that the window
    really expires, and that a Redis outage degrades to the memory limiter
    instead of taking the API down with it.
  * `app.signalling` — best-effort fan-out over WebSockets. A socket that dies
    mid-broadcast must be dropped rather than retried forever, and must not be
    left in the room collecting the next round of messages.

None of it touches the database, so this module never claims the shared
`get_db` override from the files that do.
"""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.responses import Response


# ------------------------------------------------------------- middleware ----

class _Req:
    """Minimal stand-in for starlette Request: only what the middleware reads."""

    def __init__(self, headers=None):
        self.headers = headers or {}
        self.state = SimpleNamespace()
        self.method = "GET"
        self.url = SimpleNamespace(path="/api/v1/thing")


def _run_middleware(req, call_next):
    from app.middleware import request_id_middleware
    return asyncio.run(request_id_middleware(req, call_next))


async def _ok(_request):
    return Response(content=b'{"ok":true}', status_code=200)


def test_request_id_is_echoed_when_the_client_supplies_one():
    req = _Req({"x-request-id": "abc123def456"})
    resp = _run_middleware(req, _ok)
    assert resp.headers["X-Request-ID"] == "abc123def456"
    assert req.state.rid == "abc123def456"


def test_request_id_is_generated_when_the_client_supplies_none():
    req = _Req()
    resp = _run_middleware(req, _ok)
    rid = resp.headers["X-Request-ID"]
    assert len(rid) == 12 and rid == req.state.rid
    # Two independent requests must not share an id, or log correlation breaks.
    other = _run_middleware(_Req(), _ok)
    assert other.headers["X-Request-ID"] != rid


def test_security_headers_are_present_on_every_response():
    resp = _run_middleware(_Req(), _ok)
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]


def test_unhandled_exception_becomes_a_500_that_carries_the_id_not_a_traceback():
    req = _Req({"x-request-id": "deadbeef0000"})

    async def boom(_request):
        raise RuntimeError("database connection pool exploded")

    resp = _run_middleware(req, boom)
    assert resp.status_code == 500
    body = resp.body.decode()
    assert "deadbeef0000" in body
    # The failure detail stays in the log; the client gets no stack frame,
    # no module path, and no exception text to fingerprint the stack with.
    assert "Traceback" not in body
    assert "database connection pool exploded" not in body
    assert "RuntimeError" not in body


def test_the_real_app_sets_and_echoes_the_headers():
    """End-to-end through the mounted middleware, not just the function."""
    from fastapi.testclient import TestClient
    from app.main import app

    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.headers["X-Request-ID"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"

    echoed = c.get("/health", headers={"X-Request-ID": "trace-this-request"})
    assert echoed.headers["X-Request-ID"] == "trace-this-request"


# ------------------------------------------------------------- rate limit ----

@pytest.fixture(autouse=True)
def _clean_rate_state(monkeypatch):
    from app import ratelimit
    # Pin the memory limiter: a developer with a local Redis would otherwise
    # get different behaviour (and a different clock source) from these tests.
    monkeypatch.setattr(ratelimit, "_get_redis", lambda: None)
    ratelimit._mem.clear()
    yield
    ratelimit._mem.clear()


def test_limit_is_enforced_per_scope_and_per_key():
    from app import ratelimit

    for _ in range(3):
        ratelimit.check_rate("login", "10.0.0.1", limit=3, window_s=60)
    with pytest.raises(HTTPException) as e:
        ratelimit.check_rate("login", "10.0.0.1", limit=3, window_s=60)
    assert e.value.status_code == 429

    # Same scope, different client: untouched by the exhausted one.
    ratelimit.check_rate("login", "10.0.0.2", limit=3, window_s=60)
    # Same client, different scope: a hot heartbeat must not lock out a login.
    ratelimit.check_rate("heartbeat", "10.0.0.1", limit=3, window_s=60)


def test_the_window_slides_rather_than_reseting_on_a_calendar_boundary():
    import app.ratelimit as rl

    now = [1_000.0]
    fake_time = SimpleNamespace(time=lambda: now[0])
    original, rl.time = rl.time, fake_time
    try:
        rl.check_rate("k", "ip", limit=2, window_s=60)
        rl.check_rate("k", "ip", limit=2, window_s=60)
        with pytest.raises(HTTPException):
            rl.check_rate("k", "ip", limit=2, window_s=60)

        # Still inside the window: the limit holds.
        now[0] = 1_059.0
        with pytest.raises(HTTPException):
            rl.check_rate("k", "ip", limit=2, window_s=60)

        # Past the window: the oldest hits fall out and the client recovers.
        now[0] = 1_061.0
        rl.check_rate("k", "ip", limit=2, window_s=60)
    finally:
        rl.time = original


def test_a_broken_redis_falls_back_to_the_memory_limiter(monkeypatch, caplog):
    """Redis being down must not become the whole API being down."""
    from app import ratelimit

    class _Down:
        def pipeline(self):
            raise ConnectionError("redis went away")

    monkeypatch.setattr(ratelimit, "_get_redis", lambda: _Down())

    with caplog.at_level("WARNING", logger="odivora.ratelimit"):
        for _ in range(3):
            ratelimit.check_rate("login", "10.0.0.9", limit=3, window_s=60)
        # Degraded, but still protecting the endpoint from the memory limiter.
        with pytest.raises(HTTPException) as e:
            ratelimit.check_rate("login", "10.0.0.9", limit=3, window_s=60)

    assert e.value.status_code == 429
    assert "fail-open" in caplog.text


def test_an_authoritative_429_from_redis_is_not_swallowed(monkeypatch):
    """Failing open is for outages; a real 'too many' must still reject."""
    from app import ratelimit

    class _Pipe:
        def zremrangebyscore(self, *a):
            return self

        def zadd(self, *a):
            return self

        def zcard(self, *a):
            return self

        def expire(self, *a):
            return self

        def execute(self):
            return [0, 0, 99, 60]

    class _Up:
        def pipeline(self):
            return _Pipe()

    monkeypatch.setattr(ratelimit, "_get_redis", lambda: _Up())
    with pytest.raises(HTTPException) as e:
        ratelimit.check_rate("login", "10.0.0.1", limit=10, window_s=60)
    assert e.value.status_code == 429


def test_client_ip_never_raises_on_a_socket_without_a_peer():
    from app.ratelimit import client_ip

    assert client_ip(SimpleNamespace(client=SimpleNamespace(host="198.51.100.7"))) == "198.51.100.7"
    assert client_ip(SimpleNamespace(client=None)) == "anon"


# ------------------------------------------------------------- signalling ----

class _FakeWS:
    def __init__(self, dead=False):
        self.dead = dead
        self.accepted = False
        self.messages = []

    async def accept(self):
        self.accepted = True

    async def send_json(self, message):
        if self.dead:
            raise RuntimeError("socket is gone")
        self.messages.append(message)


@pytest.fixture(autouse=True)
def _clean_rooms():
    from app import signalling
    signalling._rooms.clear()
    yield
    signalling._rooms.clear()


def _run(coro):
    return asyncio.run(coro)


def test_broadcast_reaches_only_the_subscribers_of_that_room():
    from app import signalling

    in_room, out_of_room = _FakeWS(), _FakeWS()
    _run(signalling.join("gateway:aaa", in_room))
    _run(signalling.join("gateway:bbb", out_of_room))
    assert in_room.accepted and out_of_room.accepted

    _run(signalling.broadcast("gateway:aaa", {"type": "session", "event": "authorized"}))
    assert in_room.messages == [{"type": "session", "event": "authorized"}]
    assert out_of_room.messages == []


def test_a_dead_socket_is_pruned_and_stops_receiving():
    """A dropped phone must not be retried on every event, nor accumulate."""
    from app import signalling

    alive, dead = _FakeWS(), _FakeWS(dead=True)
    _run(signalling.join("user:1", alive))
    _run(signalling.join("user:1", dead))

    _run(signalling.broadcast("user:1", {"n": 1}))
    assert alive.messages == [{"n": 1}]
    assert len(signalling._rooms["user:1"]) == 1, "dead socket left in the room"

    # The next event must not even attempt the dead one.
    _run(signalling.broadcast("user:1", {"n": 2}))
    assert alive.messages == [{"n": 1}, {"n": 2}]


def test_broadcast_session_fans_out_to_both_the_gateway_and_the_user():
    from app import signalling

    gw_ws, user_ws, stranger = _FakeWS(), _FakeWS(), _FakeWS()
    _run(signalling.join("gateway:g1", gw_ws))
    _run(signalling.join("user:u1", user_ws))
    _run(signalling.join("user:u2", stranger))

    _run(signalling.broadcast_session("g1", "u1", "authorized", "s1", "authorized"))

    expected = {"type": "session", "event": "authorized", "session_id": "s1",
                "status": "authorized"}
    assert gw_ws.messages == [expected]
    assert user_ws.messages == [expected]
    assert stranger.messages == []


def test_leaving_twice_and_broadcasting_to_an_empty_room_are_noops():
    from app import signalling

    ws = _FakeWS()
    _run(signalling.join("gateway:gone", ws))
    signalling.leave("gateway:gone", ws)
    signalling.leave("gateway:gone", ws)          # double disconnect
    signalling.leave("never-joined", ws)          # unknown room
    assert "gateway:gone" not in signalling._rooms or not signalling._rooms["gateway:gone"]

    # No subscribers at all must not raise; polling is the source of truth.
    _run(signalling.broadcast("gateway:gone", {"n": 1}))
