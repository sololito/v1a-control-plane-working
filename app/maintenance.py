"""Periodic maintenance: keep persisted state aligned with reality.

These jobs existed but nothing ever ran them. `mark_offline_gateways` was only
reachable from a manual admin call, so a gateway that vanished stayed "online"
indefinitely, and a session the relay had lost stayed "authorized" until a
user reported it dead.

One daemon thread runs every job. Each job gets its own DB session and its own
error boundary, so one failing job cannot stop the others from running on the
next tick, and a DB error in one cannot poison the next.

A single Condition serves both "wait for the next tick" and "wake/stop now",
because Event.wait can only watch one event and would make `trigger()` a lie.

Tests do not start this: it is wired into the ASGI lifespan, which TestClient
only enters when used as a context manager.
"""
import logging
import threading

log = logging.getLogger(__name__)

_cond = threading.Condition()
_tick_lock = threading.Lock()
_shutdown = False
_thread = None


def _expire_sessions(db):
    from app.jobs import expire_sessions
    return {"expired": expire_sessions(db)}


def _mark_offline_gateways(db):
    from app.config import get_settings
    from app.jobs import mark_offline_gateways
    s = get_settings()
    return {"offline": mark_offline_gateways(db, s.heartbeat_offline_after_seconds)}


def _reconcile_relay(db):
    from app.relay import reconcile
    result = reconcile(db)
    if result.get("repaired") or result.get("released"):
        log.warning("relay reconcile repaired=%s released=%s",
                    result.get("repaired"), result.get("released"))
    return result


def run_once(session_factory) -> dict:
    """Run every maintenance job once. Returns per-job results or error text.

    Exposed separately from the loop so it can be driven directly by a
    scheduler, an admin endpoint, or a test.
    """
    results = {}
    jobs = (
        ("expire_sessions", _expire_sessions),
        ("mark_offline_gateways", _mark_offline_gateways),
        ("reconcile_relay", _reconcile_relay),
    )
    for name, fn in jobs:
        db = session_factory()
        try:
            results[name] = fn(db)
        except Exception as exc:
            # Logged and contained: a job that raises must not stop the loop.
            log.warning("maintenance job %s failed: %s", name, exc, exc_info=True)
            results[name] = {"error": str(exc)}
        finally:
            try:
                db.close()
            except Exception:
                pass
    return results


def _wait_next(interval):
    """Sleep up to `interval`, returning False as soon as shutdown is asked."""
    with _cond:
        if _shutdown:
            return False
        _cond.wait(interval)
        return not _shutdown


def _loop(session_factory, interval):
    while not _shutdown:
        # Guard against a slow tick overlapping the next one, which would put
        # two reconciles on the relay at once.
        if _tick_lock.acquire(blocking=False):
            try:
                run_once(session_factory)
            except Exception as exc:
                log.warning("maintenance tick failed: %s", exc, exc_info=True)
            finally:
                _tick_lock.release()
        if not _wait_next(interval):
            break


def start(session_factory, interval=None) -> threading.Thread | None:
    """Start the maintenance thread. Idempotent; a no-op when disabled."""
    global _thread, _shutdown
    from app.config import get_settings
    s = get_settings()
    if not s.maintenance_enabled:
        log.info("maintenance disabled")
        return None
    if interval is None:
        interval = s.maintenance_interval_seconds
    if interval <= 0:
        log.info("maintenance disabled (interval %s)", interval)
        return None
    with _cond:
        if _thread is not None and _thread.is_alive():
            return _thread
        _shutdown = False
        t = threading.Thread(target=_loop, args=(session_factory, interval),
                             daemon=True, name="odivora-maintenance")
        _thread = t
        t.start()
    log.info("maintenance started (interval %ss)", interval)
    return t


def stop():
    # Both globals, not just _thread: without declaring _shutdown this creates a
    # function-local that is discarded on return, the loop never sees the flag,
    # and join() blocks for the full timeout every time — leaving the thread
    # alive and letting the next start() spawn a second one beside it.
    global _thread, _shutdown
    with _cond:
        _shutdown = True
        _cond.notify_all()
        t = _thread
    if t is not None and t.is_alive():
        t.join(timeout=5)
    _thread = None


def trigger():
    """Make the loop run now instead of waiting out the interval."""
    with _cond:
        _cond.notify_all()
