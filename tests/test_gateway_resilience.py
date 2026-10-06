"""Resilience of the paths that keep a gateway reachable after something breaks.

Three layers, in the order they fail:

  * `app.gateway.backoff.Backoff` — how a device paces its reconnects. The
    property that matters is not "it backs off" but *where the ceiling lands*:
    a cap at or above the Cloud's offline threshold turns a recoverable outage
    into a visible disconnection, and an offline gateway cannot be connected to
    at all. `test_the_cap_never_reaches_the_offline_threshold` pins that.
  * `app.jobs` — the sweeps that make persisted state honest: a gateway that
    vanished goes offline, a session past its expiry is closed.
  * `app.maintenance` — the loop that runs those sweeps, whose real duty is
    containment: one job raising, one tick running long, or a stop request must
    not take anything else down.

Jitter is asserted through an injected `rand`, never by observing randomness.
The tests that isolate the arithmetic disable the offline-threshold ceiling
(`no_ceiling`) so that clamping is not confused with the delay schedule; the
clamping itself has its own tests.
"""
import threading
import time

import pytest


# ---------------------------------------------------------------- backoff ----

@pytest.fixture
def no_ceiling(monkeypatch):
    """Disable the offline-threshold ceiling so delay arithmetic stands alone."""
    import app.gateway.backoff as backoff_mod
    monkeypatch.setattr(backoff_mod, "_offline_ceiling", lambda: None)


def test_backoff_rejects_a_configuration_that_cannot_back_off():
    from app.gateway.backoff import Backoff

    with pytest.raises(ValueError):
        Backoff(base=0)           # would never wait at all
    with pytest.raises(ValueError):
        Backoff(base=10, cap=5)   # success slower than failure
    with pytest.raises(ValueError):
        Backoff(factor=0.5)       # would shrink under the base on every failure


def test_backoff_without_jitter_is_exactly_the_nominal_schedule(no_ceiling):
    """jitter=0 is the deterministic mode: delays are exactly base*factor^n."""
    from app.gateway.backoff import Backoff

    b = Backoff(base=10.0, cap=100.0, factor=2.0, jitter=0, rand=lambda: 0.5)
    assert [b.delay(ok=False) for _ in range(5)] == [10.0, 20.0, 40.0, 80.0, 100.0]
    assert b.failures == 5   # 80 doubled to 160, pulled back to the cap


def test_backoff_grows_on_failure_and_resets_on_success(no_ceiling):
    from app.gateway.backoff import Backoff

    b = Backoff(base=1.0, cap=60.0, jitter=0, rand=lambda: 0.5)
    assert b.healthy is True

    b.delay(ok=False)
    assert b.failures == 1 and b.healthy is False
    b.delay(ok=False)
    assert b.failures == 2

    b.delay(ok=True)
    assert b.failures == 0 and b.healthy is True
    # Back to the healthy cadence, not straight back to the deep delay.
    assert b.delay(ok=True) == 1.0


def test_backoff_reset_clears_the_failure_count(no_ceiling):
    from app.gateway.backoff import Backoff

    b = Backoff(base=1.0, cap=60.0, jitter=0, rand=lambda: 0.0)
    for _ in range(4):
        b.delay(ok=False)
    assert b.failures == 4

    b.reset()
    assert b.failures == 0 and b.healthy is True
    assert b.delay(ok=False) == 1.0


def test_backoff_never_exceeds_its_cap(no_ceiling):
    from app.gateway.backoff import Backoff

    b = Backoff(base=1.0, cap=8.0, jitter=0, rand=lambda: 1.0)
    for _ in range(50):
        assert b.delay(ok=False) <= 8.0


def test_the_cap_never_reaches_the_offline_threshold():
    """The sharp edge: a cap past the threshold flaps the gateway 'offline'.

    The Cloud marks a gateway offline once last_seen is older than
    heartbeat_offline_after_seconds, and an offline gateway cannot be connected
    to at all. So however generous the caller, the effective cap is pulled down.
    """
    from app.config import get_settings
    from app.gateway.backoff import Backoff

    threshold = float(get_settings().heartbeat_offline_after_seconds)
    assert threshold > 0

    # Ask for something absurd; the ceiling must still hold.
    b = Backoff(base=1.0, cap=3600.0, jitter=0, rand=lambda: 1.0)
    assert b.cap < threshold
    for _ in range(200):
        assert b.delay(ok=False) < threshold


def test_an_oversized_cap_is_clamped_but_a_sensible_one_is_left_alone():
    from app.config import get_settings
    from app.gateway.backoff import Backoff

    ceiling = float(get_settings().heartbeat_offline_after_seconds) / 2.0
    assert Backoff(base=1.0, cap=3600.0).cap == ceiling
    assert Backoff(base=1.0, cap=ceiling / 2).cap == ceiling / 2


def test_the_ceiling_is_skipped_when_it_cannot_be_determined(monkeypatch):
    """An unknowable threshold has to mean 'no ceiling', not 'no waiting'.

    Clamping to zero would make every retry immediate — the opposite of a
    backoff — so a missing or non-positive threshold must leave the cap alone.
    """
    import app.gateway.backoff as backoff_mod

    monkeypatch.setattr(backoff_mod, "_offline_ceiling", lambda: None)
    assert backoff_mod.Backoff(base=2.0, cap=120.0).cap == 120.0

    monkeypatch.setattr(backoff_mod, "_offline_ceiling", lambda: 0.0)
    assert backoff_mod.Backoff(base=2.0, cap=120.0).cap == 120.0


def test_the_ceiling_comes_from_the_offline_threshold():
    """Half the threshold: a merely-slow gateway must still look alive."""
    import app.gateway.backoff as backoff_mod

    assert backoff_mod._offline_ceiling() == 60.0


def test_healthy_delay_is_never_shorter_than_the_base():
    """Jitter spreads retries but must not let the healthy cadence speed up.

    A delay below base would quietly increase polling load every heartbeat.
    """
    from app.gateway.backoff import Backoff

    b = Backoff(base=10.0, cap=60.0, jitter=0.5)
    for r in (0.0, 0.5, 1.0):
        b._rand = lambda r=r: r
        assert 10.0 <= b.delay(ok=True) <= 10.0 * 1.5
    b._rand = lambda: 1.0
    assert b.delay(ok=True) == 15.0


def test_failed_delay_keeps_a_half_floor_and_an_upper_bound(no_ceiling):
    """Equal jitter: raw/2 <= delay <= raw.

    The floor matters as much as the ceiling — without it a tight base never
    genuinely backs off and recovery stays unbounded.
    """
    from app.gateway.backoff import Backoff

    floor = Backoff(base=10.0, cap=1000.0, factor=2.0, jitter=0.25, rand=lambda: 0.0)
    assert floor.delay(ok=False) == 5.0     # raw 10  -> floor 5
    assert floor.delay(ok=False) == 10.0    # raw 20  -> floor 10

    top = Backoff(base=10.0, cap=1000.0, factor=2.0, jitter=0.25, rand=lambda: 1.0)
    assert top.delay(ok=False) == 10.0
    assert top.delay(ok=False) == 20.0

    spread = Backoff(base=10.0, cap=1000.0, jitter=0.25)
    for r in (0.0, 0.25, 0.75, 1.0):
        spread._rand = lambda r=r: r
        spread.reset()
        for _ in range(6):                 # enough failures to reach the cap
            # raw is keyed off the failure count *before* the call, since
            # delay() increments it.
            raw = min(1000.0, 10.0 * (2.0 ** spread.failures))
            assert raw / 2.0 <= spread.delay(ok=False) <= raw


def test_jitter_decorrelates_devices_that_failed_at_the_same_moment(no_ceiling):
    """Identical histories must not become identical retries.

    Two gateways on the same upstream that failed the same number of times
    would, with no jitter, pick the same delay to the microsecond and hammer
    the recovering server together. Same histories, different streams.
    """
    from app.gateway.backoff import Backoff

    def stream(values):
        it = iter(values)
        return lambda: next(it)

    a = Backoff(base=10.0, cap=60.0, jitter=0.25, rand=stream([0.10, 0.90, 0.30]))
    b = Backoff(base=10.0, cap=60.0, jitter=0.25, rand=stream([0.95, 0.05, 0.65]))

    seq_a = [a.delay(ok=False) for _ in range(3)]
    seq_b = [b.delay(ok=False) for _ in range(3)]
    assert seq_a != seq_b
    # Each still respects its own equal-jitter window.
    for i, d in enumerate(seq_a + seq_b):
        raw = min(60.0, 10.0 * (2.0 ** (i % 3)))
        assert raw / 2.0 <= d <= raw


def test_jitter_is_clamped_to_the_unit_interval(no_ceiling):
    from app.gateway.backoff import Backoff

    assert Backoff(base=1.0, jitter=5.0).jitter == 1.0
    assert Backoff(base=1.0, jitter=-1.0).jitter == 0.0


def test_describe_reports_the_live_state(no_ceiling):
    from app.gateway.backoff import Backoff, describe

    b = Backoff(base=12.5, cap=45.0, jitter=0, rand=lambda: 0.0)
    b.delay(ok=False)
    text = describe(b)
    assert "base=12.5s" in text and "cap=45s" in text and "failures=1" in text


# ------------------------------------------------------------------- jobs ----

@pytest.fixture
def db(tmp_path):
    """A private database per test, so no state leaks between tests or runs."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models  # noqa: F401 - importing registers tables on Base
    from app.db import Base
    engine = create_engine(f"sqlite:///{tmp_path}/resilience.db",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _status(db, row):
    db.refresh(row)
    return row.status


def _gateway(db, status="online", age_seconds="keep"):
    from datetime import datetime, timedelta
    from app import models
    gw = models.Gateway(device_type="esp32", status=status,
                         public_key="esp32-pubkey-test")
    if age_seconds != "keep":
        gw.last_seen = datetime.utcnow() - timedelta(seconds=age_seconds)
    db.add(gw)
    db.commit()
    return gw


def test_mark_offline_gateways_flaps_only_the_silent_online_ones(db):
    from app.jobs import mark_offline_gateways

    silent = _gateway(db, "online", age_seconds=600)     # silent for 10 min
    chatty = _gateway(db, "online", age_seconds=5)       # just checked in
    was_offline = _gateway(db, "offline", age_seconds=600)
    revoked = _gateway(db, "revoked", age_seconds=600)

    assert mark_offline_gateways(db, offline_after_seconds=120) == 1
    assert _status(db, silent) == "offline"
    assert _status(db, chatty) == "online"
    assert _status(db, was_offline) == "offline"   # already terminal, unchanged
    assert _status(db, revoked) == "revoked"       # never resurrected


def test_mark_offline_gateways_honours_the_threshold(db):
    from app.jobs import mark_offline_gateways

    just_inside = _gateway(db, "online", age_seconds=30)
    just_outside = _gateway(db, "online", age_seconds=300)

    assert mark_offline_gateways(db, offline_after_seconds=120) == 1
    assert _status(db, just_inside) == "online"
    assert _status(db, just_outside) == "offline"


def test_mark_offline_gateways_leaves_never_seen_gateways_alone(db):
    """No heartbeat yet is 'pairing', not 'offline' — it must not be swept."""
    from app.jobs import mark_offline_gateways

    pairing = _gateway(db, "pairing")
    assert pairing.last_seen is None
    assert mark_offline_gateways(db, offline_after_seconds=120) == 0
    assert _status(db, pairing) == "pairing"


def _session(db, status, expires_in_seconds):
    from datetime import datetime, timedelta
    from app import models
    n = abs(expires_in_seconds)
    u = models.User(email=f"s{status}{n}@example.com", password_hash="x")
    db.add(u)
    db.flush()
    gw = models.Gateway(device_type="esp32", status="online",
                        public_key="esp32-pubkey-test")
    db.add(gw)
    db.flush()
    s = models.ConnectionSession(
        user_id=u.id, gateway_id=gw.id, status=status,
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in_seconds))
    db.add(s)
    db.commit()
    return s


def test_expire_sessions_closes_only_overdue_live_sessions(db):
    from app import models
    from app.jobs import expire_sessions

    live = {st: _session(db, st, expires_in_seconds=-60)
            for st in ("requested", "authorized", "connecting")}
    future = _session(db, "authorized", expires_in_seconds=600)
    already = _session(db, "expired", expires_in_seconds=-600)
    disconnected = _session(db, "disconnected", expires_in_seconds=-600)
    connected = _session(db, "connected", expires_in_seconds=-600)
    revoked = _session(db, "revoked", expires_in_seconds=-600)

    assert expire_sessions(db) == 3
    for s in live.values():
        db.refresh(s)
        assert s.status == "expired"
        assert s.ended_at is not None
    # Everything already terminal, or not yet due, is left exactly as it was.
    for s, expected in ((future, "authorized"), (already, "expired"),
                        (disconnected, "disconnected"), (connected, "connected"),
                        (revoked, "revoked")):
        assert _status(db, s) == expected
    # Every closure leaves an audit event.
    assert (db.query(models.SessionEvent)
            .filter(models.SessionEvent.event == "expired").count()) == 3


def test_expire_sessions_is_idempotent(db):
    from app.jobs import expire_sessions

    _session(db, "requested", expires_in_seconds=-60)
    assert expire_sessions(db) == 1
    # A second sweep must not re-expire, or re-event, an already-closed session.
    assert expire_sessions(db) == 0


def test_expire_sessions_ignores_a_session_with_no_expiry(db):
    from app.jobs import expire_sessions

    s = _session(db, "requested", expires_in_seconds=0)
    s.expires_at = None
    db.commit()
    assert expire_sessions(db) == 0
    assert _status(db, s) == "requested"


# ------------------------------------------------------------- maintenance ---

@pytest.fixture
def maintenance(monkeypatch):
    """Maintenance holds thread state in module globals; start from clean.

    stop() deliberately leaves _shutdown set — that is how it wakes the loop —
    so the fixture clears it afterwards. A test that does not call start()
    would otherwise inherit a module already flagged for shutdown.
    """
    import app.maintenance as maintenance_mod
    from app.config import get_settings

    def reset():
        maintenance_mod.stop()
        maintenance_mod._shutdown = False

    reset()
    monkeypatch.setattr(get_settings(), "maintenance_enabled", True)
    yield maintenance_mod
    reset()


class FakeDB:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_maintenance_gives_every_job_its_own_session_and_closes_it(maintenance,
                                                                   monkeypatch):
    """A session left open leaks a pooled connection on every single tick."""
    made = []
    monkeypatch.setattr(maintenance, "_expire_sessions",
                        lambda db: {"expired": 0})
    monkeypatch.setattr(maintenance, "_mark_offline_gateways",
                        lambda db: {"offline": 0})
    monkeypatch.setattr(maintenance, "_reconcile_relay", lambda db: {"ok": True})

    def factory():
        db = FakeDB()
        made.append(db)
        return db

    maintenance.run_once(factory)
    # Three jobs, three distinct sessions, all closed.
    assert len(made) == 3 and len({id(d) for d in made}) == 3
    assert all(d.closed for d in made)


def test_maintenance_closes_the_session_of_a_job_that_raises(maintenance,
                                                             monkeypatch):
    """Containment includes cleanup: the failure path must still close."""
    made = []

    def boom(db):
        raise RuntimeError("db gone")

    monkeypatch.setattr(maintenance, "_expire_sessions", boom)
    monkeypatch.setattr(maintenance, "_mark_offline_gateways", lambda db: {"offline": 0})
    monkeypatch.setattr(maintenance, "_reconcile_relay", lambda db: {"ok": True})

    def factory():
        db = FakeDB()
        made.append(db)
        return db

    results = maintenance.run_once(factory)
    assert "db gone" in results["expire_sessions"]["error"]
    # A failing job must not stop the others.
    assert results["mark_offline_gateways"] == {"offline": 0}
    assert results["reconcile_relay"] == {"ok": True}
    assert all(d.closed for d in made)


def test_maintenance_start_is_disabled_by_config(maintenance, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "maintenance_enabled", False)
    assert maintenance.start(lambda: None, interval=3600) is None


def test_maintenance_start_is_a_noop_for_a_non_positive_interval(maintenance):
    assert maintenance.start(lambda: None, interval=0) is None
    assert maintenance.start(lambda: None, interval=-5) is None


def test_maintenance_start_is_idempotent(maintenance, monkeypatch):
    monkeypatch.setattr(maintenance, "run_once", lambda f: {"ok": True})
    first = maintenance.start(lambda: None, interval=3600)
    second = maintenance.start(lambda: None, interval=3600)
    assert first is not None and second is first


def test_maintenance_stop_returns_before_the_interval_is_up(maintenance, monkeypatch):
    """stop() must interrupt the wait, not block on it.

    The Condition backs both 'wait for the next tick' and 'wake/stop now'; if
    it regressed to sleeping out the interval, shutdown would take the period.
    """
    monkeypatch.setattr(maintenance, "run_once", lambda f: {"ok": True})
    t = maintenance.start(lambda: None, interval=3600)
    assert t is not None
    time.sleep(0.05)                    # let the first tick settle

    t0 = time.monotonic()
    maintenance.stop()
    assert time.monotonic() - t0 < 5.0
    assert not t.is_alive()


def test_trigger_wakes_a_parked_loop_without_stopping_it(maintenance, monkeypatch):
    """trigger() must wake a waiter, and must not look like a stop.

    Tested by parking a waiter on the same Condition the loop uses, rather than
    by racing the real thread: notify_all is edge-triggered, so a trigger that
    lands in the window between a tick finishing and the loop re-parking is
    legitimately dropped. The contract is about a *parked* waiter.
    """
    monkeypatch.setattr(maintenance, "run_once", lambda f: {"ok": True})
    parked_at = threading.Event()
    outcome = []

    def park():
        with maintenance._cond:
            parked_at.set()
            outcome.append(maintenance._wait_next(3600))

    waiter = threading.Thread(target=park, daemon=True)
    waiter.start()
    assert parked_at.wait(5)
    time.sleep(0.05)                  # let it settle into _cond.wait
    maintenance.trigger()
    waiter.join(timeout=5)
    assert not waiter.is_alive(), "trigger() did not wake the parked loop"
    # Woken, and told to keep going (_shutdown untouched).
    assert outcome == [True]


def test_maintenance_ticks_do_not_overlap(maintenance, monkeypatch):
    """A slow tick must not be joined by a second one.

    Two concurrent reconciles would fight over relay state. The tick lock is
    what prevents that, so the assertion is that a tick requested mid-flight is
    skipped rather than queued behind it.
    """
    inside = threading.Event()
    release = threading.Event()
    tick_count = []

    def slow_tick(factory):
        tick_count.append(1)
        inside.set()
        release.wait(5)
        return {"ok": True}

    monkeypatch.setattr(maintenance, "run_once", slow_tick)
    maintenance.start(lambda: None, interval=3600)
    assert inside.wait(5), "the first tick never started"

    maintenance.trigger()      # ask for another tick while one is in flight
    time.sleep(0.2)
    assert tick_count == [1], "a second tick ran concurrently"
    release.set()
    maintenance.stop()


def test_maintenance_lifespan_starts_and_stops_the_thread(maintenance, monkeypatch):
    """Wired into the ASGI lifespan, so only a context-managed client sees it.

    TestClient enters lifespan only as a context manager — a bare get()/post()
    never starts this thread, which is why background maintenance cannot be
    assumed to be running anywhere else in the suite.
    """
    from fastapi.testclient import TestClient
    import app.main as main_mod

    monkeypatch.setattr(maintenance, "run_once", lambda f: {"ok": True})

    with TestClient(main_mod.app):
        thread = maintenance._thread
        assert thread is not None and thread.is_alive()
    assert not thread.is_alive()
    assert maintenance._thread is None