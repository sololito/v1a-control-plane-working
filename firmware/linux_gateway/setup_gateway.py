#!/usr/bin/env python3
"""ODIVORA Linux gateway — one-time setup.

Run on the gateway machine (Ubuntu/Debian/OpenWrt) as root:

    sudo ./venv/bin/python firmware/linux_gateway/setup_gateway.py \
        --api-base https://api.example.com

What it does:
  1. Generates/loads an Ed25519 identity and registers the gateway
     (POST /api/v1/gateways/register) -> prints the PAIRING CODE.
  2. Waits for you to claim the gateway from your ODIVORA account
     (POST /me/gateways/{id}/claim), then stores the gateway_token.
  3. Generates the WireGuard keypair via the owner's access token
     (POST /gateways/{id}/generate-keys) and writes the PRIVATE key to
     /etc/odivora/wg_private_key (chmod 600). The public key is stored
     server-side for peer coordination.
  4. Writes /etc/odivora/gateway.env consumed by gateway_agent.py.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.request

STATE_DIR = "/etc/odivora"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
ENV_FILE = os.path.join(STATE_DIR, "gateway.env")
WG_PRIVATE_KEY_FILE = os.path.join(STATE_DIR, "wg_private_key")


def _post(url, payload, token=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")
    except urllib.error.URLError as e:
        sys.exit(
            f"\n[SETUP ERROR] Cannot reach the ODIVORA API at {url}\n"
            f"  {e.reason}\n"
            "  Checklist:\n"
            "   1. Remove '<' '>' characters from --api-base; use the real IP.\n"
            "   2. Use the API host's real LAN IP, not a broadcast/subnet address.\n"
            "   3. Verify it works here first:  curl http://<API_IP>:8000/health\n"
            "   4. Make sure both machines can route to each other.\n"
        )


def _ensure_dirs():
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o700)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default=os.environ.get("ODIVORA_API_BASE", "http://127.0.0.1:8000"))
    ap.add_argument("--device-type", default="linux")
    args = ap.parse_args()
    # Strip copy-paste artifacts like "<IP>" or a trailing ">"
    args.api_base = args.api_base.strip().strip("<>")
    if not args.api_base.startswith(("http://", "https://")):
        sys.exit(f"Invalid --api-base: {args.api_base}  (must start with http:// or https://)")
    _ensure_dirs()

    # 1. identity + register
    state = {}
    if os.path.exists(STATE_FILE):
        state = json.load(open(STATE_FILE))
    if not state.get("gateway_id"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.generate()
        raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pub_b64 = base64.b64encode(raw).decode()
        key_b64 = base64.b64encode(priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())).decode()
        code, res = _post(f"{args.api_base}/api/v1/gateways/register", {
            "device_type": args.device_type, "public_key": pub_b64,
            "algorithm": "ed25519", "firmware_version": "linux-gw-1.0",
        })
        if code != 200:
            sys.exit(f"register failed {code}: {res}")
        state = {"gateway_id": res["gateway_id"], "ed25519_private_key": key_b64,
                 "public_key": pub_b64}
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
        print(f"REGISTERED gateway_id={res['gateway_id']}")
        print(f">>> PAIRING CODE: {res['pairing_code']}  (expires {res['expires_at']})")
    else:
        print(f"gateway_id already set: {state['gateway_id']}")

    # 2. gateway token (after claim)
    if not state.get("gateway_token"):
        print("\nClaim the gateway from your account first, e.g.:")
        print(f"  curl -X POST {args.api_base}/api/v1/me/gateways/{state['gateway_id']}/claim \\")
        print(f"    -H 'Authorization: Bearer <your_user_access_token>' \\")
        print(f"    -H 'Content-Type: application/json' \\")
        print(f"    -d '{{\"pairing_code\": \"<code>\"}}'")
        tok = input("Paste the gateway_token from the claim response: ").strip()
        if not tok:
            sys.exit("No token provided.")
        state["gateway_token"] = tok
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)

    # 3. generate WG keypair (owner token required by the API)
    if not os.path.exists(WG_PRIVATE_KEY_FILE):
        user_token = input("Paste your ODIVORA user access token (owner) to generate WG keys: ").strip()
        code, res = _post(
            f"{args.api_base}/api/v1/gateways/{state['gateway_id']}/generate-keys", {}, token=user_token)
        if code != 200:
            sys.exit(f"generate-keys failed {code}: {res}")
        with open(WG_PRIVATE_KEY_FILE, "w") as f:
            f.write(res["private_key"] + "\n")
        os.chmod(WG_PRIVATE_KEY_FILE, 0o600)
        print("WireGuard PRIVATE key written to", WG_PRIVATE_KEY_FILE, "(public key is on the server).")
        if res.get("public_key"):
            print("public_key:", res["public_key"])
        # persist generated keys? server keeps public; we keep private only.
    else:
        print("WG private key already present.")

    # 4. env file
    with open(ENV_FILE, "w") as f:
        f.write(f"ODIVORA_API_BASE={args.api_base}\n")
        f.write(f"GATEWAY_ID={state['gateway_id']}\n")
        f.write(f"GATEWAY_TOKEN={state['gateway_token']}\n")
        f.write("WG_INTERFACE=wg0\nWAN_INTERFACE=eth0\nDEVICE_KIND=linux\nSYNC_INTERVAL=10\n")
    os.chmod(ENV_FILE, 0o600)
    print(f"\nWrote {ENV_FILE}. Next:")
    print("  sudo cp firmware/linux_gateway/odivora-gateway.service /etc/systemd/system/")
    print("  sudo systemctl daemon-reload && sudo systemctl enable --now odivora-gateway")


if __name__ == "__main__":
    main()
