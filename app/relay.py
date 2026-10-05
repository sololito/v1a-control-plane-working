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
"""
import json
import urllib.request
from typing import Optional

from app.config import get_settings

# In-process allocation table: session_id -> port pair.
# A single API worker process is the assumption in V1; horizontal scaling
# would move this to Redis (or deterministic hash of session id) later.
_allocations: dict[str, tuple[int, int]] = {}
_next_port: int = 0


def _pool_bounds():
    s = get_settings()
    return s.relay_port_start, s.relay_port_end


def _allocate_pair() -> tuple[int, int]:
    global _next_port
    start, end = _pool_bounds()
    used = set()
    for pp, gp in _allocations.values():
        used.add(pp)
        used.add(gp)
    i = start if _next_port == 0 else _next_port
    while True:
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


def alloc_relay_session(session_id: str) -> dict:
    """Reserve a (phone_port, gateway_port) pair and tell the relay."""
    if session_id in _allocations:
        pp, gp = _allocations[session_id]
    else:
        pp, gp = _allocate_pair()
        _allocations[session_id] = (pp, gp)
    _notify("PUT", session_id, {"phone_port": pp, "gateway_port": gp})
    return {
        "relay_host": _relay_host(),
        "phone_port": pp,
        "gateway_port": gp,
        "phone_endpoint": f"{_relay_host()}:{pp}",
        "gateway_endpoint": f"{_relay_host()}:{gp}",
    }


def free_relay_session(session_id: str) -> None:
    if session_id in _allocations:
        del _allocations[session_id]
    _notify("DELETE", session_id, None)


def _relay_host() -> str:
    return get_settings().relay_public_host or "127.0.0.1"


def _notify(method: str, session_id: str, body: Optional[dict]) -> None:
    """Best-effort control call to the relay service. Empty
    RELAY_CONTROL_URL = dev mode: allocation is local-only and the relay
    is assumed to be listening with a matching convention."""
    url = get_settings().relay_control_url.rstrip("/")
    if not url:
        return
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{url}/session/{session_id}", data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        # Relay will TTL-expire stale pairs; the Cloud must not die because
        # the relay is momentarily unreachable.
        pass
