"""Relay allocation for V1B NAT traversal.

The relay is a plain UDP pair-forwarder that never terminates WireGuard —
it only shuttles ciphertext between the phone and the gateway. The Cloud
stays control-plane-only; relay sessions are signaled from here and
enforced on the relay service.

Port-pair model (per session):
    phone_port    <- phone sends WireGuard packets to relay:phone_port
    gateway_port  <- gateway sends WireGuard packets to relay:gateway_port
    relay forwards raw UDP datagrams between the two <-> both peers see
    "relay_public:port" as the peer endpoint.

No decryption, no logging of payload, no TLS termination at the relay.

Allocation is NOT fire-and-forget. A relay that silently fails to bind is
indistinguishable from a working one until a phone times out on a handshake
nobody is listening for, so a control call that cannot be confirmed raises
`RelayUnavailable` and the caller must not persist the session.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

from app.config import get_settings

# In-process allocation table: session_id -> port pair.
# A single API worker process is the assumption in V1; horizontal scaling
# would move this to Redis (or deterministic hash of session id) later.
_allocations: dict[str, tuple[int, int]] = {}
_next_port: int = 0
# Two concurrent authorizes must never be handed the same port pair.
_alloc_lock = threading.Lock()

# Sessions in these states are expected to exist on the relay; a relay that
# has lost one of them is missing a live tunnel, so reconcile re-installs it.
_ACTIVE = ("requested", "authorized", "connecting", "connected")


class RelayUnavailable(RuntimeError):
    """The relay could not be told about a session.

    Callers MUST NOT persist a session that caused this: the ports would be
    advertised to the phone and gateway while nothing is bound to them.
    """


def _pool_bounds():
    s = get_settings()
    return s.relay_port_start, s.relay_port_end


def _allocate_pair_locked() -> tuple[int, int]:
    """Reserve the next free (phone, gateway) port pair.

    Caller must hold _alloc_lock. Port reuse across threads is a security bug,
    not a cosmetic one: two sessions sharing a port means one phone's
    WireGuard traffic is delivered to the other's gateway socket.
    """
    global _next_port
    start, end = _pool_bounds()
    used = set()
    for pp, gp in _allocations.values():
        used.add(pp)
        used.add(gp)
    if (end - start + 1) < 2:
        raise RelayUnavailable(f"relay port pool {start}-{end} is too small for a pair")
    i = start if _next_port == 0 else _next_port
    for _ in range((end - start) // 2 + 2):
        a, b = i, i + 1
        if b > end:
            i = start
            continue
        if a not in used and b not in used:
            _next_port = b + 1
            return a, b
        i += 2
        if i > end:
            i = start
    raise RelayUnavailable(f"relay port pool {start}-{end} exhausted ({len(_allocations)} sessions held)")


def _allocate_pair() -> tuple[int, int]:
    with _alloc_lock:
        return _allocate_pair_locked()


def _reserve(session_id: str) -> tuple[int, int]:
    """Return this session's pair, allocating one on first use."""
    with _alloc_lock:
        existing = _allocations.get(session_id)
        if existing is not None:
            return existing
        pp, gp = _allocate_pair_locked()
        _allocations[session_id] = (pp, gp)
        return pp, gp


def _release(session_id: str) -> None:
    with _alloc_lock:
        _allocations.pop(session_id, None)


def alloc_relay_session(session_id: str) -> dict:
    """Reserve a (phone_port, gateway_port) pair and install it on the relay.

    Raises RelayUnavailable — leaving the reservation released — if the relay
    does not confirm the allocation.
    """
    pp, gp = _reserve(session_id)
    try:
        _notify("PUT", session_id, {"phone_port": pp, "gateway_port": gp})
    except RelayUnavailable:
        # Release before re-raising: a pair the relay never bound must not
        # stay reserved, or repeated failures quietly eat the whole pool.
        _release(session_id)
        raise
    host = _relay_host()
    return {
        "relay_host": host,
        "phone_port": pp,
        "gateway_port": gp,
        "phone_endpoint": f"{host}:{pp}",
        "gateway_endpoint": f"{host}:{gp}",
    }


def free_relay_session(session_id: str) -> None:
    """Release a session's pair and tell the relay to drop it.

    Never raises. Revoking a session is a security action; it must complete in
    the database even when the relay is unreachable, and the relay's idle
    reaper is the backstop for the sockets it could not be told about.
    """
    _release(session_id)
    try:
        _notify("DELETE", session_id, None)
    except RelayUnavailable:
        pass


def _relay_host() -> str:
    return get_settings().relay_public_host or "127.0.0.1"


def _control_url() -> str:
    return get_settings().relay_control_url.rstrip("/")


def _notify(method: str, session_id: str, body: Optional[dict], *,
            attempts: Optional[int] = None, timeout: Optional[float] = None) -> None:
    """Call the relay control API, retrying transient failures.

    An empty RELAY_CONTROL_URL is dev mode: allocation is local-only and the
    relay is assumed to be listening with a matching convention.

    Retries use linear backoff, not the timeout itself — the timeout is what
    we are trying not to spend. Raises RelayUnavailable once attempts run out
    so the caller can refuse to hand out an unprovisioned port pair.
    """
    url = _control_url()
    if not url:
        return
    s = get_settings()
    attempts = attempts if attempts is not None else max(1, s.relay_control_retries)
    timeout = timeout if timeout is not None else s.relay_control_timeout_seconds
    data = json.dumps(body).encode() if body is not None else None
    last_error = "unknown"
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            f"{url}/session/{session_id}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp.read()
            return
        except urllib.error.HTTPError as exc:
            # The relay answered, and its answer is authoritative: a bind
            # failure will not fix itself, so stop instead of retrying.
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                detail = ""
            raise RelayUnavailable(f"relay {method} {session_id} -> HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        if attempt < attempts:
            time.sleep(s.relay_control_backoff_seconds * attempt)
    raise RelayUnavailable(
        f"relay {method} {session_id} failed after {attempts} attempts: {last_error}")


def fetch_relay_sessions(*, attempts: int = 2, timeout: float = 5.0,
                         url_override: Optional[str] = None) -> set:
    """Session ids the relay currently holds sockets for.

    Used by reconcile to spot a session the relay has lost (restart, or a
    socket that died) before the user notices a dead tunnel.
    """
    url = (url_override if url_override is not None else _control_url())
    if not url:
        return set()
    last_error = "unknown"
    for attempt in range(1, max(1, attempts) + 1):
        try:
            with urllib.request.urlopen(f"{url}/sessions", timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return {str(s["session_id"]) for s in payload.get("sessions", []) if s.get("session_id")}
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, OSError, ValueError) as exc:
            last_error = str(exc)
        if attempt < attempts:
            time.sleep(get_settings().relay_control_backoff_seconds * attempt)
    raise RelayUnavailable(f"relay inventory unavailable: {last_error}")


def reconcile(db) -> dict:
    """Re-align the relay with the sessions the Cloud believes are live.

    Two directions, both needed after a relay restart:
      * a session the Cloud says is active but the relay has lost gets its
        port pair re-installed, restoring the tunnel without user action;
      * a session the relay still holds that the Cloud has terminated is
        dropped, so a revoke that could not reach the relay still takes
        effect.

    An unreachable relay is not an error here — there is nothing to align
    against, and the next sweep tries again.
    """
    from app import models

    try:
        live = fetch_relay_sessions()
    except RelayUnavailable as exc:
        return {"ok": False, "error": str(exc), "repaired": [], "released": []}

    repaired, released = [], []
    known = set()
    rows = (
        db.query(models.ConnectionSession)
        .filter(models.ConnectionSession.relay_info.isnot(None))
        .all()
    )
    for row in rows:
        sid = str(row.id)
        known.add(sid)
        try:
            info = json.loads(row.relay_info or "{}")
        except (TypeError, ValueError):
            info = {}
        if not info.get("phone_port") or not info.get("gateway_port"):
            continue
        if sid in live or row.status not in _ACTIVE:
            continue
        try:
            _notify("PUT", sid, {"phone_port": info["phone_port"],
                                 "gateway_port": info["gateway_port"]})
            repaired.append(sid)
        except RelayUnavailable:
            pass  # relay still unhappy; retried on the next sweep

    for sid in sorted(live - known):
        free_relay_session(sid)
        released.append(sid)

    if repaired or released:
        db.commit()
    return {"ok": True, "repaired": repaired, "released": released}
