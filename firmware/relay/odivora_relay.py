#!/usr/bin/env python3
"""ODIVORA relay service (V1B) — a UDP pair-forwarder.

Keeps WireGuard traffic END-TO-END ENCRYPTED: the relay never sees
keys or plaintext. It pairs two UDP sockets per Cloud-allocated session
and copies datagrams between them.

Control plane (local HTTP, bound to control host/port):
    PUT    /session/{session_id}   {"phone_port": N, "gateway_port": M}
    DELETE /session/{session_id}
    GET    /sessions                live inventory, so the Cloud can detect
                                    a session the relay has lost

Rendezvous (STUN-lite): a UDP echo socket that replies with the
sender's observed public IP:port, so peers can discover their own
public endpoint for future DIRECT connections.

Durability contract — what the Cloud is allowed to assume about this
process. Every one of these used to be violated, which let a session
look provisioned while no datagram could ever flow:

  * A session survives routine UDP errors. An ICMP port-unreachable, a
    full receive buffer, and an interrupted syscall are all normal on
    internet-facing UDP and none of them mean the socket is gone.
  * A session dies only on DELETE, on idle TTL, or on real socket death.
  * While a session is live the relay re-probes BOTH peers, so an idle
    NAT mapping on either side stays warm instead of expiring.
  * Sockets are built outside LOCK and swapped inside it, so a
    concurrent PUT/DELETE can never leave the registry pointing at a
    closed descriptor, and a failed bind leaks nothing.

Usage:
    python odivora_relay.py --control 0.0.0.0:9090 --rendezvous-port 3478
"""
import argparse
import errno
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A session with no forwarded traffic for this long is reaped. Generous
# enough to cover a phone on a metered link that only bursts occasionally.
SESSION_IDLE_TTL = 120.0
# Re-probe both peers at this cadence so NAT mappings stay warm and a
# genuinely dead peer ages out into the reaper.
KEEPALIVE_INTERVAL = 15.0
_REAP_INTERVAL = 5.0
_RECV_TIMEOUT = 1.0
_KEEPALIVE_MAGIC = b"odivora-ka"

# Errors that must NOT tear down a live session: none of them invalidate
# the socket, and all of them are routine on internet-facing UDP.
_TRANSIENT_ERRNOS = frozenset({
    errno.ECONNREFUSED,   # ICMP port-unreachable from a peer whose mapping aged out
    errno.ENOBUFS,        # kernel receive buffer full
    errno.EAGAIN,         # would block
    errno.EINTR,          # interrupted syscall
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.ETIMEDOUT,
    errno.ECONNRESET,
})


class Session:
    def __init__(self, session_id, phone_port, gateway_port):
        self.session_id = session_id
        self.phone_port = phone_port
        self.gateway_port = gateway_port
        self.phone_addr = None
        self.gateway_addr = None
        self.phone_sock = None
        self.gateway_sock = None
        self.stop = threading.Event()
        self.last_activity = time.monotonic()
        self.last_probe = 0.0


SESSIONS: dict[str, Session] = {}
LOCK = threading.Lock()


def _touch(session):
    session.last_activity = time.monotonic()


def _bind(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
    except OSError:
        sock.close()
        raise
    return sock


def _teardown(session):
    """Close a session's sockets and stop its loops. Safe to call twice."""
    session.stop.set()
    for sock in (session.phone_sock, session.gateway_sock):
        if sock is None:
            continue
        try:
            sock.close()
        except OSError:
            pass


def _build_session(session_id, phone_port, gateway_port):
    """Bind a complete socket pair, or bind nothing at all.

    Building outside the lock keeps a slow/failing bind from stalling every
    other session. If the second bind fails the first socket is closed here,
    so a rejected allocation never leaks a descriptor.
    """
    s = Session(session_id, phone_port, gateway_port)
    phone_sock = gateway_sock = None
    try:
        phone_sock = _bind(phone_port)
        gateway_sock = _bind(gateway_port)
    except OSError:
        for sock in (phone_sock, gateway_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        raise
    s.phone_sock = phone_sock
    s.gateway_sock = gateway_sock
    return s


def _maybe_keepalive(session, role, now):
    """Re-probe the opposite peer so neither side's NAT mapping ages out.

    The relay sits on a public address, so it is not the side whose mapping
    matters — it is the peer's. Sending it anything refreshes the mapping the
    peer will use to reach us, which is exactly what a fully idle session
    would otherwise lose.
    """
    if now - session.last_probe < KEEPALIVE_INTERVAL:
        return
    if role == "phone":
        peer_addr, peer_sock = session.gateway_addr, session.gateway_sock
    else:
        peer_addr, peer_sock = session.phone_addr, session.phone_sock
    session.last_probe = now
    if not peer_addr or peer_sock is None:
        return
    try:
        peer_sock.sendto(_KEEPALIVE_MAGIC, peer_addr)
    except OSError:
        pass


def _udp_loop(sock, session, role):
    sock.settimeout(_RECV_TIMEOUT)
    while not session.stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            _maybe_keepalive(session, role, time.monotonic())
            continue
        except OSError as exc:
            # A transient error is not a dead session. Retrying is the whole
            # point: the peer is very likely still there behind a mapping we
            # just refreshed.
            if exc.errno in _TRANSIENT_ERRNOS:
                continue
            if session.stop.is_set():
                break
            # Genuinely fatal (EBADF and friends): the pair is useless with
            # one socket gone, so drop the session and let the Cloud's
            # reconcile notice it is missing and re-PUT it.
            _fault_session(session, f"{role} socket failed: {exc}")
            break
        _touch(session)
        if data == _KEEPALIVE_MAGIC:
            continue  # our own probe echoed back; never forward it
        if role == "phone":
            session.phone_addr = addr
            if session.gateway_addr and session.gateway_sock is not None:
                try:
                    session.gateway_sock.sendto(data, session.gateway_addr)
                except OSError as exc:
                    if exc.errno not in _TRANSIENT_ERRNOS:
                        session.gateway_addr = None
        else:
            session.gateway_addr = addr
            if session.phone_addr and session.phone_sock is not None:
                try:
                    session.phone_sock.sendto(data, session.phone_addr)
                except OSError as exc:
                    if exc.errno not in _TRANSIENT_ERRNOS:
                        session.phone_addr = None


def _fault_session(session, reason):
    """Retire a session whose socket died so it stops being advertised."""
    with LOCK:
        if SESSIONS.get(session.session_id) is session:
            del SESSIONS[session.session_id]
    _teardown(session)
    print(f"[relay] session {session.session_id} retired: {reason}", flush=True)


def alloc(session_id, phone_port, gateway_port):
    """Install a socket pair for the session, replacing any previous one.

    The pair is built first, then swapped into the registry under LOCK, and
    the old pair is torn down only after the swap. A concurrent alloc or free
    can therefore never observe a half-installed session.
    """
    s = _build_session(session_id, phone_port, gateway_port)
    with LOCK:
        old = SESSIONS.get(session_id)
        SESSIONS[session_id] = s
    if old is not None:
        _teardown(old)
    threading.Thread(target=_udp_loop, args=(s.phone_sock, s, "phone"),
                     daemon=True, name=f"relay-phone-{session_id[:8]}").start()
    threading.Thread(target=_udp_loop, args=(s.gateway_sock, s, "gateway"),
                     daemon=True, name=f"relay-gw-{session_id[:8]}").start()
    return s


def free(session_id):
    with LOCK:
        s = SESSIONS.pop(session_id, None)
    if s:
        _teardown(s)
    return s


def snapshot():
    """Live session inventory for the Cloud's reconcile pass."""
    now = time.monotonic()
    with LOCK:
        sessions = list(SESSIONS.values())
    out = []
    for s in sessions:
        out.append({
            "session_id": s.session_id,
            "phone_port": s.phone_port,
            "gateway_port": s.gateway_port,
            "phone_addr": list(s.phone_addr) if s.phone_addr else None,
            "gateway_addr": list(s.gateway_addr) if s.gateway_addr else None,
            "idle_seconds": round(now - s.last_activity, 3),
        })
    return out


def reap(now=None, ttl=None):
    """Drop sessions that have gone idle past the TTL.

    Without this the relay accumulates sockets for sessions the Cloud has
    already revoked, which is how a port pool silently exhausts itself.
    """
    now = time.monotonic() if now is None else now
    ttl = SESSION_IDLE_TTL if ttl is None else ttl
    expired = []
    with LOCK:
        for sid, s in list(SESSIONS.items()):
            if now - s.last_activity > ttl:
                del SESSIONS[sid]
                expired.append(s)
    for s in expired:
        _teardown(s)
        print(f"[relay] session {s.session_id} reaped after "
              f"{now - s.last_activity:.0f}s idle", flush=True)
    return len(expired)


def reaper_loop(ttl=None):
    ttl = SESSION_IDLE_TTL if ttl is None else ttl
    # Tick faster than the TTL, so the configured --session-ttl is the thing
    # that actually decides when a session dies. A fixed 5s cadence silently
    # overrode a shorter TTL.
    interval = max(0.5, min(_REAP_INTERVAL, ttl / 4))
    while True:
        time.sleep(interval)
        try:
            reap(ttl=ttl)
        except Exception as exc:  # a bad reap must not kill the relay
            print(f"[relay] reaper error: {exc}", flush=True)


class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        if not self.path.startswith("/session/"):
            self._send(404, {"error": "not found"})
            return
        session_id = self.path.split("/", 2)[2]
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            phone_port, gateway_port = int(body["phone_port"]), int(body["gateway_port"])
            alloc(session_id, phone_port, gateway_port)
        except Exception as exc:
            # Report the failure rather than a hollow 200: the Cloud must be
            # able to refuse to hand these ports to a phone.
            self._send(503, {"error": str(exc), "session_id": session_id})
            return
        self._send(200, {"ok": True, "session_id": session_id,
                         "phone_port": phone_port, "gateway_port": gateway_port})

    def do_DELETE(self):
        if not self.path.startswith("/session/"):
            self._send(404, {"error": "not found"})
            return
        free(self.path.split("/", 2)[2])
        self._send(200, {"ok": True})

    def do_GET(self):
        if self.path.rstrip("/") not in ("", "/sessions"):
            self._send(404, {"error": "not found"})
            return
        self._send(200, {"sessions": snapshot()})

    def log_message(self, fmt, *args):
        pass


def rendezvous_server(port, stop=None):
    """STUN-lite: echo observed source back to the sender."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(_RECV_TIMEOUT)
    while stop is None or not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
            sock.sendto(f"{addr[0]}:{addr[1]}".encode(), addr)
        except TimeoutError:
            continue
        except OSError as exc:
            if exc.errno in _TRANSIENT_ERRNOS:
                continue
            break
    sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", default="127.0.0.1:9090", help="control HTTP bind")
    ap.add_argument("--rendezvous-port", type=int, default=3478)
    ap.add_argument("--session-ttl", type=float, default=SESSION_IDLE_TTL,
                    help="idle seconds before a session is reaped")
    ap.add_argument("--no-reaper", action="store_true", help="disable the idle reaper")
    args = ap.parse_args()

    host, _, port = args.control.partition(":")
    threading.Thread(target=rendezvous_server, args=(args.rendezvous_port,),
                     daemon=True, name="relay-rendezvous").start()
    if not args.no_reaper:
        threading.Thread(target=reaper_loop, args=(args.session_ttl,),
                         daemon=True, name="relay-reaper").start()
    print(f"relay control on {args.control}, rendezvous UDP on {args.rendezvous_port}, "
          f"idle TTL {args.session_ttl:.0f}s", flush=True)
    # Threading, not plain HTTPServer: one hung control client must not be
    # able to block every other session's PUT/DELETE.
    ThreadingHTTPServer((host, int(port)), ControlHandler).serve_forever()


if __name__ == "__main__":
    main()
