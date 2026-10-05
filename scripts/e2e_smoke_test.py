#!/usr/bin/env python3
"""ODIVORA V1B end-to-end API smoke test.

Drives the full control-plane flow against a running ODIVORA server:

  1. register a user
  2. register + claim a gateway (with a fresh Ed25519 identity)
  3. generate-keys (WireGuard keypair for the gateway)
  4. heartbeat (gateway comes online)
  5. create a connection session
  6. authorize-wg (peer provisioned, tunnel IP allocated)
  7. fetch wg-config
  8. handshake (session -> connected)
  9. revoke-wg (peer removed, IP freed)

This validates the Cloud coordination plane only. To prove real traffic
also flows, run it WHILE a WireGuard client (phone app or laptop) uses
the wg-config from step 7, and check `curl ifconfig.me` egress.

Usage:
    python scripts/e2e_smoke_test.py --api-base http://127.0.0.1:8000
"""
import argparse
import base64
import json
import sys
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def req(method, url, payload=None, token=None):
    r = urllib.request.Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def step(name, ok, extra=""):
    print(f"[{'OK' if ok else 'FAIL'}] {name} {extra}")
    if not ok:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    base = args.api_base.rstrip("/")
    email = f"e2e-{int(time.time())}@example.com"

    # identity for the gateway
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw).decode()

    code, me = req("POST", f"{base}/api/v1/auth/register",
                   {"email": email, "password": "Password123!"})
    step("register user", code == 200, f"({email})")
    user_token = me["access_token"]

    code, gw = req("POST", f"{base}/api/v1/gateways/register",
                   {"device_type": "linux", "public_key": pub_b64, "algorithm": "ed25519"})
    step("register gateway", code == 200)
    gid, pairing = gw["gateway_id"], gw["pairing_code"]

    code, claim = req("POST", f"{base}/api/v1/me/gateways/{gid}/claim",
                      {"pairing_code": pairing}, token=user_token)
    step("claim gateway", code == 200)
    gtok = claim["gateway_token"]

    code, hb = req("POST", f"{base}/api/v1/gateways/heartbeat",
                   {"firmware_version": "e2e-smoke", "nonce": "0000000001"}, token=gtok)
    step("heartbeat", code == 200)

    code, keys = req("POST", f"{base}/api/v1/gateways/{gid}/generate-keys", {}, token=user_token)
    step("generate-keys", code == 200, f"(pub {keys.get('public_key', '')[:8]}…)")

    code, sess = req("POST", f"{base}/api/v1/connections", {"gateway_id": gid}, token=user_token)
    step("create session", code == 200)
    sid = sess["id"]

    code, auth = req("POST", f"{base}/api/v1/sessions/{sid}/authorize-wg", {}, token=user_token)
    step("authorize-wg", code == 200, f"(ip {auth.get('assigned_ip')})")

    code, cfg = req("GET", f"{base}/api/v1/sessions/{sid}/wg-config", token=user_token)
    ok = code == 200 and "[Interface]" in cfg.get("config", "")
    step("wg-config", ok)

    code, hs = req("POST", f"{base}/api/v1/sessions/{sid}/handshake", token=user_token)
    step("handshake -> connected", code == 200 and hs.get("status") == "connected")

    code, peers = req("GET", f"{base}/api/v1/gateways/{gid}/peers", token=gtok)
    step("gateway peers visible", code == 200 and len(peers.get("peers", [])) == 1)

    code, rv = req("POST", f"{base}/api/v1/sessions/{sid}/revoke-wg", {}, token=user_token)
    step("revoke-wg", code == 200 and rv.get("status") == "revoked")

    print("\nSMOKE TEST PASSED — Cloud coordination plane works end-to-end.")
    print("For real traffic: keep the session alive, import the wg-config on")
    print("a phone/laptop, then curl ifconfig.me must return the home public IP.")


if __name__ == "__main__":
    main()
