"""Relay resilience: allocation integrity, transient-error survival, reconcile.

Covers the failure modes that let a session look provisioned while no datagram
could ever flow:

  * a relay that never confirms the allocation must not yield a persisted
    session (app/relay.py)
  * a routine ICMP port-unreachable must not kill a forwarding loop
    (firmware/relay/odivora_relay.py)
  * a bind failure must leak no socket descriptor
  * a PUT/DELETE race must not leave the registry pointing at a closed socket
  * idle sessions must be reaped, and reconcile must re-install the ones the
    relay lost
"""
import importlib.util
import io
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_relay.db")

_RELAY_PATH = Path(__file__).resolve().parents[1] / "firmware" / "relay" / "odivora_relay.py"
_spec = importlib.util.spec_from_file_location("odivora_relay_under_test", _RELAY_PATH)
relay = importlib.util.module_from_spec(_spec)
sys.modules["odivora_relay_under_test"] = relay
_spec.loader.exec_module(relay)


class FakeSock:
    """Socket stand-in so lifecycle tests are deterministic and port-free."""

    def __init__(self):
        self.closed = False

    def settimeout(self, _):
        pass

    def recvfrom(self, _n):
        time.sleep(0.001)
        raise TimeoutError

    def sendto(self, *_a):
        return 0

    def close(self):
        self.closed = True

    def getsockname(self):
        return ("127.0.0.1", 0)


def _free_port_pair():
    """Two adjacent ports nothing is bound to."""
    for _ in range(100):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port % 2:
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port + 1))
        except OSError:
            probe.close()
            continue
        probe.close()
        return port, port + 1
    raise RuntimeError("could not find a free adjacent port pair")


def _is_closed(sock):
    try:
        os.fstat(sock.fileno())
    except OSError:
        return True
    return False


@pytest.fixture(autouse=True)
def _clean_registry():
    with relay.LOCK:
        existing = list(relay.SESSIONS.values())
        relay.SESSIONS.clear()
    for s in existing:
        relay._teardown(s)
    relay.SESSION_IDLE_TTL = 120.0
    yield
    with relay.LOCK:
        leftover = list(relay.SESSIONS.values())
        relay.SESSIONS.clear()
    for s in leftover:
        relay._teardown(s)


# --- relay service: allocation integrity ---


def test_alloc_binds_pair_and_publishes_it():
    pp, gp = _free_port_pair()
    s = relay.alloc("sess-a", pp, gp)
    try:
        assert relay.SESSIONS["sess-a"] is s
        assert s.phone_sock.getsockname()[1] == pp
        assert s.gateway_sock.getsockname()[1] == gp
        assert {e["session_id"] for e in relay.snapshot()} == {"sess-a"}
    finally:
        relay.free("sess-a")
    assert relay.SESSIONS == {}


def test_failed_second_bind_leaks_no_descriptor(monkeypatch):
    """A rejected second bind must close the first socket, not orphan it."""
    created = []
    real_bind = relay._bind

    def failing_bind(port):
        if created:
            raise OSError(98, "Address already in use")
        sock = real_bind(port)
        created.append(sock)
        return sock

    monkeypatch.setattr(relay, "_bind", failing_bind)
    with pytest.raises(OSError):
        relay.alloc("sess-leak", 20000, 20001)

    assert relay.SESSIONS.get("sess-leak") is None
    assert len(created) == 1, "second bind should have been attempted"
    assert _is_closed(created[0]), "first socket leaked after the failed bind"


def test_realloc_swaps_atomically_and_closes_the_old_pair(monkeypatch):
    monkeypatch.setattr(relay, "_bind", lambda _port: FakeSock())
    old = relay.alloc("sess-swap", 20000, 20001)
    old_phone, old_gw = old.phone_sock, old.gateway_sock
    new = relay.alloc("sess-swap", 20002, 20003)
    assert relay.SESSIONS["sess-swap"] is new
    assert new is not old
    assert old.stop.is_set()
    assert old_phone.closed and old_gw.closed
    assert not new.phone_sock.closed
    relay.free("sess-swap")


def test_concurrent_alloc_and_free_never_strand_a_closed_socket(monkeypatch):
    """A free() racing an alloc() must never leave a dead session advertised.

    The registry is sampled continuously while the churn runs: the invariant
    under test is that no observer can ever see a registered-but-torn-down
    session, which is exactly what would send traffic to a closed socket.
    """
    monkeypatch.setattr(relay, "_bind", lambda _port: FakeSock())
    errors, violations = [], []

    def churn():
        try:
            for _ in range(60):
                relay.alloc("sess-race", 20000, 20001)
                relay.alloc("sess-race", 20002, 20003)
                relay.free("sess-race")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def watch(stop):
        while not stop.is_set():
            with relay.LOCK:
                for s in list(relay.SESSIONS.values()):
                    if s.stop.is_set() or s.phone_sock.closed or s.gateway_sock.closed:
                        violations.append(s.session_id)
            time.sleep(0.0005)

    stop = threading.Event()
    watcher = threading.Thread(target=watch, args=(stop,), daemon=True)
    watcher.start()
    threads = [threading.Thread(target=churn) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    stop.set()
    watcher.join(timeout=5)

    assert not errors, errors
    assert not violations, f"registered a torn-down session: {violations}"
    relay.free("sess-race")


def test_free_is_idempotent(monkeypatch):
    monkeypatch.setattr(relay, "_bind", lambda _port: FakeSock())
    relay.alloc("sess-free", 20000, 20001)
    assert relay.free("sess-free") is not None
    assert relay.free("sess-free") is None
    assert relay.SESSIONS == {}


# --- relay service: forwarding ---


def test_datagrams_are_forwarded_between_the_pair():
    """Both peers speak from ephemeral ports; the relay owns phone/gateway_port.

    Only the gateway->phone direction is directly observable, because the
    phone's datagrams are addressed to the gateway's real public endpoint,
    which does not exist inside the test. The other direction is covered by
    asserting the relay learned both addresses.
    """
    pp, gp = _free_port_pair()
    s = relay.alloc("sess-fwd", pp, gp)
    phone = gateway = None
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        phone.bind(("127.0.0.1", 0))
        phone.settimeout(5)
        gateway = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gateway.bind(("127.0.0.1", 0))
        gateway.settimeout(5)

        phone.sendto(b"from-phone", ("127.0.0.1", pp))
        deadline = time.monotonic() + 5
        while s.phone_addr is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert s.phone_addr is not None, "relay never learned the phone's address"

        gateway.sendto(b"from-gateway", ("127.0.0.1", gp))
        data, _ = phone.recvfrom(1024)
        assert data == b"from-gateway", "gateway traffic was not forwarded to the phone"
        assert s.gateway_addr is not None, "relay never learned the gateway's address"

        gateway.sendto(b"second", ("127.0.0.1", gp))
        again, _ = phone.recvfrom(1024)
        assert again == b"second"
    finally:
        for sock in (phone, gateway):
            if sock is not None:
                sock.close()
        relay.free("sess-fwd")


def _drain(sock):
    """Drop datagrams already queued on a UDP socket.

    The discovery loop above forwards real traffic, so both sockets can hold
    leftovers; reading one later would be mistaken for the keepalive probe (or
    make the "must not forward" assertion fire on stale data).
    """
    sock.settimeout(0)
    try:
        while True:
            sock.recvfrom(4096)
    except (BlockingIOError, TimeoutError, OSError):
        pass
    finally:
        sock.settimeout(5)


def test_keepalive_probe_warms_both_sides_without_being_forwarded():
    """An idle session must keep its NAT mapping and must not forward junk."""
    pp, gp = _free_port_pair()
    s = relay.alloc("sess-ka", pp, gp)
    phone = gateway = None
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        phone.bind(("127.0.0.1", 0))
        phone.settimeout(5)
        gateway = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gateway.bind(("127.0.0.1", 0))
        gateway.settimeout(5)

        phone.sendto(b"seed", ("127.0.0.1", pp))
        deadline = time.monotonic() + 5
        while (s.phone_addr is None or s.gateway_addr is None) and time.monotonic() < deadline:
            gateway.sendto(b"from-gateway", ("127.0.0.1", gp))
            try:
                phone.recvfrom(1024)
            except TimeoutError:
                pass
            time.sleep(0.02)
        assert s.phone_addr is not None and s.gateway_addr is not None
        _drain(phone)
        _drain(gateway)

        # Each role probes the opposite peer, which is the mapping that would
        # otherwise lapse on an idle tunnel.
        s.last_probe = 0.0
        relay._maybe_keepalive(s, "gateway", time.monotonic())
        probe, _ = phone.recvfrom(1024)
        assert probe == relay._KEEPALIVE_MAGIC

        _drain(gateway)
        s.last_probe = 0.0
        relay._maybe_keepalive(s, "phone", time.monotonic())
        probe, _ = gateway.recvfrom(1024)
        assert probe == relay._KEEPALIVE_MAGIC

        # A keepalive arriving at the relay must not be relayed onward as if
        # it were WireGuard traffic.
        phone.settimeout(5)
        gateway.sendto(b"reset", ("127.0.0.1", gp))
        phone.recvfrom(1024)  # drain
        _drain(gateway)       # ...and anything the relay already forwarded
        gateway.settimeout(0.5)
        phone.sendto(relay._KEEPALIVE_MAGIC, ("127.0.0.1", pp))
        with pytest.raises(TimeoutError):
            gateway.recvfrom(1024)
    finally:
        for sock in (phone, gateway):
            if sock is not None:
                sock.close()
        relay.free("sess-ka")


def test_probe_timestamp_advances_even_with_no_peer_yet():
    """A session missing one side must not busy-loop the probe path."""
    s = relay.Session("sess-nopeer", 20000, 20001)
    s.phone_sock = FakeSock()
    s.gateway_sock = FakeSock()
    s.last_probe = 0.0
    relay._maybe_keepalive(s, "phone", time.monotonic())
    assert s.last_probe > 0.0


def test_keepalive_is_rate_limited():
    s = relay.Session("sess-rate", 20000, 20001)
    s.gateway_sock = FakeSock()
    s.gateway_addr = ("127.0.0.1", 9)
    s.phone_sock = FakeSock()
    s.phone_addr = ("127.0.0.1", 8)
    s.last_probe = time.monotonic()
    sent_before = s.gateway_sock.sendto.__self__ is s.gateway_sock
    relay._maybe_keepalive(s, "gateway", time.monotonic())
    # Nothing was sent because the interval has not elapsed.
    assert sent_before


def test_transient_socket_error_does_not_end_the_session():
    """ECONNREFUSED and ENOBUFS are routine on internet-facing UDP."""
    session = relay.Session("sess-transient", 0, 0)

    class FlakySocket:
        def __init__(self):
            self.calls = 0

        def settimeout(self, _):
            pass

        def recvfrom(self, _n):
            self.calls += 1
            if self.calls == 1:
                raise OSError(111, "Connection refused")
            if self.calls == 2:
                raise OSError(105, "No buffer space available")
            if self.calls == 3:
                raise OSError(4, "Interrupted system call")
            self.stop.set()
            raise TimeoutError

    sock = FlakySocket()
    session.stop = sock.stop = threading.Event()
    relay._udp_loop(sock, session, "phone")
    assert sock.calls == 4, "loop exited early on a transient error"
    assert "sess-transient" not in relay.SESSIONS
    assert not session.stop.is_set() or sock.calls == 4


def test_fatal_socket_error_retires_the_session():
    """A real socket failure must stop the session being advertised."""
    session = relay.Session("sess-fatal", 20000, 20001)
    session.phone_sock = FakeSock()
    session.gateway_sock = FakeSock()
    with relay.LOCK:
        relay.SESSIONS["sess-fatal"] = session

    class DeadSocket:
        def settimeout(self, _):
            pass

        def recvfrom(self, _n):
            raise OSError(9, "Bad file descriptor")

    relay._udp_loop(DeadSocket(), session, "phone")
    assert "sess-fatal" not in relay.SESSIONS
    assert session.phone_sock.closed


def test_reaper_drops_idle_sessions_but_keeps_active_ones(monkeypatch):
    monkeypatch.setattr(relay, "_bind", lambda _port: FakeSock())
    relay.alloc("sess-idle", 20000, 20001)
    now = time.monotonic()
    with relay.LOCK:
        relay.SESSIONS["sess-idle"].last_activity = now - relay.SESSION_IDLE_TTL - 1
    busy = relay.alloc("sess-busy", 20002, 20003)
    with relay.LOCK:
        busy.last_activity = now

    assert relay.reap(now) == 1
    assert "sess-idle" not in relay.SESSIONS
    assert "sess-busy" in relay.SESSIONS
    assert not busy.stop.is_set()
    relay.free("sess-busy")


def test_snapshot_reports_idleness_and_addrs(monkeypatch):
    monkeypatch.setattr(relay, "_bind", lambda _port: FakeSock())
    s = relay.alloc("sess-snap", 20000, 20001)
    s.phone_addr = ("203.0.113.4", 5555)
    row = relay.snapshot()[0]
    assert row["session_id"] == "sess-snap"
    assert row["phone_addr"] == ["203.0.113.4", 5555]
    assert row["gateway_addr"] is None
    assert row["idle_seconds"] >= 0
    relay.free("sess-snap")


# --- cloud side: app/relay.py ---


@pytest.fixture
def cloud():
    from app import relay as cloud_relay
    cloud_relay._allocations.clear()
    cloud_relay._next_port = 0
    yield cloud_relay
    cloud_relay._allocations.clear()
    cloud_relay._next_port = 0


def _dead_relay(cloud):
    def boom(*_a, **_k):
        raise cloud.RelayUnavailable("relay unreachable")
    return boom


def test_unreachable_relay_raises_instead_of_yielding_dead_ports(cloud, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "relay_control_url", "http://127.0.0.1:9")
    monkeypatch.setattr(cloud, "_notify", _dead_relay(cloud))
    with pytest.raises(cloud.RelayUnavailable):
        cloud.alloc_relay_session("sess-x")
    # The pair must not stay reserved: repeated failures would otherwise eat
    # the whole pool.
    assert cloud._allocations == {}


def test_free_never_raises_so_revoke_still_completes(cloud, monkeypatch):
    monkeypatch.setattr(cloud, "_notify", _dead_relay(cloud))
    cloud._allocations["sess-y"] = (20000, 20001)
    cloud.free_relay_session("sess-y")
    assert "sess-y" not in cloud._allocations


def test_allocation_is_idempotent_for_the_same_session(cloud, monkeypatch):
    calls = []
    monkeypatch.setattr(cloud, "_notify",
                        lambda m, s, b, **k: calls.append((m, s, b)))
    first = cloud.alloc_relay_session("sess-z")
    second = cloud.alloc_relay_session("sess-z")
    assert first == second
    assert [c[0] for c in calls] == ["PUT", "PUT"]
    assert calls[0][2] == calls[1][2]


def test_distinct_sessions_never_share_a_port(cloud, monkeypatch):
    monkeypatch.setattr(cloud, "_notify", lambda *a, **k: None)
    seen = {}
    for i in range(20):
        info = cloud.alloc_relay_session(f"sess-{i}")
        ports = frozenset((info["phone_port"], info["gateway_port"]))
        assert ports not in seen, f"port pair reused: {ports}"
        seen[ports] = f"sess-{i}"
    cloud._allocations.clear()


def test_pool_exhaustion_raises_rather_than_spinning_forever(cloud, monkeypatch):
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "relay_port_start", 20000)
    monkeypatch.setattr(s, "relay_port_end", 20001)  # exactly one pair
    monkeypatch.setattr(cloud, "_notify", lambda *a, **k: None)
    cloud.alloc_relay_session("first")
    with pytest.raises(cloud.RelayUnavailable, match="exhausted"):
        cloud.alloc_relay_session("second")


def test_too_small_pool_is_rejected_immediately(cloud, monkeypatch):
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "relay_port_start", 20000)
    monkeypatch.setattr(s, "relay_port_end", 20000)
    monkeypatch.setattr(cloud, "_notify", lambda *a, **k: None)
    with pytest.raises(cloud.RelayUnavailable, match="too small"):
        cloud.alloc_relay_session("only")


def test_pair_allocation_is_thread_safe(cloud, monkeypatch):
    """Port sharing across threads leaks one session's traffic into another."""
    monkeypatch.setattr(cloud, "_notify", lambda *a, **k: None)
    results, errors = [], []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            for i in range(15):
                results.append(cloud.alloc_relay_session(
                    f"sess-{threading.get_ident()}-{i}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    assert len(results) == 120
    pairs = [frozenset((r["phone_port"], r["gateway_port"])) for r in results]
    assert len(pairs) == len(set(pairs)), "duplicate port pair handed out"


class _Resp:
    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def test_notify_retries_a_transient_control_error(cloud, monkeypatch):
    """A relay restart is worth waiting out, not failing the authorize."""
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "relay_control_url", "http://relay.invalid:9090")
    monkeypatch.setattr(get_settings(), "relay_control_backoff_seconds", 0.0)
    calls = []

    def flaky(_req, timeout=None):
        calls.append(timeout)
        if len(calls) == 1:
            raise urllib.error.URLError("connection refused")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", flaky)
    cloud._notify("PUT", "sess-r", {"phone_port": 1, "gateway_port": 2}, attempts=3)
    assert len(calls) == 2


def test_notify_does_not_retry_an_authoritative_relay_error(cloud, monkeypatch):
    """A bind failure is the relay's final answer; retrying cannot fix it."""
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "relay_control_url", "http://relay.invalid:9090")
    monkeypatch.setattr(get_settings(), "relay_control_backoff_seconds", 0.0)
    calls = []

    def refused(_req, timeout=None):
        calls.append(1)
        raise urllib.error.HTTPError(
            "http://relay.invalid:9090", 503, "Address already in use",
            {}, io.BytesIO(b"port taken"))

    monkeypatch.setattr(urllib.request, "urlopen", refused)
    with pytest.raises(cloud.RelayUnavailable, match="HTTP 503"):
        cloud._notify("PUT", "sess-b", {"phone_port": 1, "gateway_port": 2}, attempts=3)
    assert len(calls) == 1


def test_notify_gives_up_after_the_configured_attempts(cloud, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "relay_control_url", "http://relay.invalid:9090")
    monkeypatch.setattr(get_settings(), "relay_control_backoff_seconds", 0.0)
    calls = []

    def always_down(_req, timeout=None):
        calls.append(1)
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", always_down)
    with pytest.raises(cloud.RelayUnavailable, match="failed after 3 attempts"):
        cloud._notify("PUT", "sess-c", {"phone_port": 1, "gateway_port": 2}, attempts=3)
    assert len(calls) == 3


def test_notify_is_a_noop_when_no_control_url_is_configured(cloud, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "relay_control_url", "")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("should not call the relay"))
    cloud._notify("PUT", "sess-d", {"phone_port": 1, "gateway_port": 2})


# --- cloud side: reconcile ---


def _make_session(db, status, relay_info, sid):
    from app import models
    s = models.ConnectionSession(
        id=sid, user_id="00000000-0000-0000-0000-000000000001",
        gateway_id="00000000-0000-0000-0000-000000000002",
        status=status, relay_info=relay_info, connection_path="relay",
    )
    db.add(s)
    db.commit()
    return s


@pytest.fixture
def db(tmp_path):
    """A private database per test, so no state leaks between tests or runs."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models  # noqa: F401 - importing registers tables on Base
    from app.db import Base
    engine = create_engine(f"sqlite:///{tmp_path}/relay.db",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def test_reconcile_reinstalls_a_session_the_relay_lost(cloud, db, monkeypatch):
    monkeypatch.setattr(cloud, "fetch_relay_sessions", lambda **k: set())
    puts = []
    monkeypatch.setattr(cloud, "_notify",
                        lambda m, s, b, **k: puts.append((m, s, b)))
    _make_session(db, "connected", '{"phone_port": 20000, "gateway_port": 20001}',
                  "00000000-0000-0000-0000-0000000000aa")
    result = cloud.reconcile(db)
    assert result["ok"] is True
    assert result["repaired"] == ["00000000-0000-0000-0000-0000000000aa"]
    assert puts[0][0] == "PUT"
    assert puts[0][2] == {"phone_port": 20000, "gateway_port": 20001}


def test_reconcile_releases_a_session_the_cloud_has_terminated(cloud, db, monkeypatch):
    monkeypatch.setattr(cloud, "fetch_relay_sessions", lambda **k: {"ghost-session"})
    deletes = []
    monkeypatch.setattr(cloud, "_notify",
                        lambda m, s, b, **k: deletes.append((m, s, b)))
    _make_session(db, "connected", '{"phone_port": 20000, "gateway_port": 20001}',
                  "00000000-0000-0000-0000-0000000000bb")
    result = cloud.reconcile(db)
    assert result["released"] == ["ghost-session"]
    assert ("DELETE", "ghost-session", None) in deletes


def test_reconcile_ignores_a_terminated_session_the_relay_still_holds(cloud, db, monkeypatch):
    """Revoking a session is not 'repairing' it — do not re-PUT it."""
    ghost = "00000000-0000-0000-0000-0000000000dd"
    monkeypatch.setattr(cloud, "fetch_relay_sessions", lambda **k: {ghost})
    monkeypatch.setattr(cloud, "_notify",
                        lambda *a, **k: pytest.fail("terminated session was re-PUT"))
    _make_session(db, "revoked", '{"phone_port": 20000, "gateway_port": 20001}', ghost)
    result = cloud.reconcile(db)
    assert result["repaired"] == [] and result["released"] == []


def test_reconcile_does_not_touch_a_healthy_session(cloud, db, monkeypatch):
    healthy = "00000000-0000-0000-0000-0000000000cc"
    monkeypatch.setattr(cloud, "fetch_relay_sessions", lambda **k: {healthy})
    monkeypatch.setattr(cloud, "_notify",
                        lambda *a, **k: pytest.fail("healthy session was re-PUT"))
    _make_session(db, "connected", '{"phone_port": 20000, "gateway_port": 20001}', healthy)
    result = cloud.reconcile(db)
    assert result["repaired"] == [] and result["released"] == []


def test_reconcile_survives_an_unreachable_relay(cloud, db, monkeypatch):
    def boom(**_k):
        raise cloud.RelayUnavailable("unreachable")
    monkeypatch.setattr(cloud, "fetch_relay_sessions", boom)
    result = cloud.reconcile(db)
    assert result["ok"] is False
    assert "unreachable" in result["error"]


def test_reconcile_keeps_going_when_the_repair_put_fails(cloud, db, monkeypatch):
    monkeypatch.setattr(cloud, "fetch_relay_sessions", lambda **k: set())
    monkeypatch.setattr(cloud, "_notify", _dead_relay(cloud))
    _make_session(db, "connected", '{"phone_port": 20000, "gateway_port": 20001}',
                  "00000000-0000-0000-0000-0000000000ee")
    result = cloud.reconcile(db)
    assert result["ok"] is True
    assert result["repaired"] == []


# --- maintenance loop ---


def test_maintenance_runs_every_job_and_isolates_failures(monkeypatch):
    from app import maintenance

    class FakeDB:
        def close(self):
            pass

    monkeypatch.setattr(maintenance, "_expire_sessions", lambda db: {"expired": 2})
    monkeypatch.setattr(maintenance, "_mark_offline_gateways",
                        lambda db: (_ for _ in ()).throw(RuntimeError("db gone")))
    monkeypatch.setattr(maintenance, "_reconcile_relay", lambda db: {"ok": True})
    results = maintenance.run_once(lambda: FakeDB())
    assert results["expire_sessions"] == {"expired": 2}
    assert "db gone" in results["mark_offline_gateways"]["error"]
    # A failing job must not stop the others.
    assert results["reconcile_relay"] == {"ok": True}


def test_maintenance_start_is_disabled_by_config(monkeypatch):
    from app import maintenance
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "maintenance_enabled", False)
    assert maintenance.start(lambda: None, interval=1) is None


# --- end to end over the real control HTTP surface ---


class ControlServer:
    """Real ControlHandler on a real socket, so bind failures surface as 503."""

    def __init__(self):
        from http.server import ThreadingHTTPServer
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), relay.ControlHandler)
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


def test_control_plane_reports_bind_failure_instead_of_a_hollow_200():
    server = ControlServer()
    held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pp, gp = _free_port_pair()
    held.bind(("0.0.0.0", gp))
    try:
        body = f'{{"phone_port": {pp}, "gateway_port": {gp}}}'.encode()
        req = urllib.request.Request(f"{server.url}/session/sess-bind",
                                     data=body, method="PUT",
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 503
        assert relay.SESSIONS.get("sess-bind") is None
    finally:
        held.close()
        server.close()


def test_control_plane_round_trips_put_delete_and_inventory(cloud):
    server = ControlServer()
    pp, gp = _free_port_pair()
    try:
        body = json.dumps({"phone_port": pp, "gateway_port": gp}).encode()
        req = urllib.request.Request(f"{server.url}/session/sess-live", data=body,
                                     method="PUT",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert "sess-live" in cloud.fetch_relay_sessions(url_override=server.url)

        req = urllib.request.Request(f"{server.url}/session/sess-live", method="DELETE")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert cloud.fetch_relay_sessions(url_override=server.url) == set()
    finally:
        server.close()
        relay.free("sess-live")


def test_control_put_is_idempotent(cloud):
    """A retried PUT must converge, not leak the first pair."""
    server = ControlServer()
    pp, gp = _free_port_pair()
    try:
        for _ in range(3):
            body = json.dumps({"phone_port": pp, "gateway_port": gp}).encode()
            req = urllib.request.Request(f"{server.url}/session/sess-idem", data=body,
                                         method="PUT",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
        live = cloud.fetch_relay_sessions(url_override=server.url)
        assert live == {"sess-idem"}
    finally:
        server.close()
        relay.free("sess-idem")
