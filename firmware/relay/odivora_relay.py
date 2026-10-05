#!/usr/bin/env python3
"""ODIVORA relay service (V1B) — a UDP pair-forwarder.

Keeps WireGuard traffic END-TO-END ENCRYPTED: the relay never sees
keys or plaintext. It pairs two UDP sockets per Cloud-allocated session
and copies datagrams between them.

Control plane (local HTTP, bound to control host/port):
    PUT    /session/{session_id}   {"phone_port": N, "gateway_port": M}
    DELETE /session/{session_id}

Rendezvous (STUN-lite): a UDP echo socket that replies with the
sender's observed public IP:port, so peers can discover their own
public endpoint for future DIRECT connections.

Usage:
    python odivora_relay.py --control 0.0.0.0:9090 --rendezvous-port 3478
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


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


SESSIONS: dict[str, Session] = {}
LOCK = threading.Lock()


def _udp_loop(sock, session, role):
    sock.settimeout(1.0)
    while not session.stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except TimeoutError:
            continue
        except OSError:
            break
        if role == "phone":
            session.phone_addr = addr
            if session.gateway_addr:
                try:
                    session.gateway_sock.sendto(data, session.gateway_addr)
                except OSError:
                    pass
        else:
            session.gateway_addr = addr
            if session.phone_addr:
                try:
                    session.phone_sock.sendto(data, session.phone_addr)
                except OSError:
                    pass


def alloc(session_id, phone_port, gateway_port):
    free(session_id)
    with LOCK:
        s = Session(session_id, phone_port, gateway_port)
        import socket
        s.phone_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.phone_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.phone_sock.bind(("0.0.0.0", phone_port))
        s.gateway_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.gateway_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.gateway_sock.bind(("0.0.0.0", gateway_port))
        SESSIONS[session_id] = s
    threading.Thread(target=_udp_loop, args=(s.phone_sock, s, "phone"), daemon=True).start()
    threading.Thread(target=_udp_loop, args=(s.gateway_sock, s, "gateway"), daemon=True).start()


def free(session_id):
    with LOCK:
        s = SESSIONS.pop(session_id, None)
    if s:
        s.stop.set()
        try:
            s.phone_sock.close()
        except Exception:
            pass
        try:
            s.gateway_sock.close()
        except Exception:
            pass


class ControlHandler(BaseHTTPRequestHandler):
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
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            alloc(self.path.split("/", 2)[2], int(body["phone_port"]), int(body["gateway_port"]))
            self._send(200, {"ok": True})
        except Exception as e:
            self._send(400, {"error": str(e)})

    def do_DELETE(self):
        if not self.path.startswith("/session/"):
            self._send(404, {"error": "not found"})
            return
        free(self.path.split("/", 2)[2])
        self._send(200, {"ok": True})

    def log_message(self, fmt, *args):
        pass


def rendezvous_server(port):
    """STUN-lite: echo observed source back to the sender."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            sock.sendto(f"{addr[0]}:{addr[1]}".encode(), addr)
        except OSError:
            break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", default="127.0.0.1:9090", help="control HTTP bind")
    ap.add_argument("--rendezvous-port", type=int, default=3478)
    args = ap.parse_args()
    host, _, port = args.control.partition(":")
    threading.Thread(target=rendezvous_server, args=(args.rendezvous_port,), daemon=True).start()
    print(f"relay control on {args.control}, rendezvous UDP on {args.rendezvous_port}")
    HTTPServer((host, int(port)), ControlHandler).serve_forever()


if __name__ == "__main__":
    main()
