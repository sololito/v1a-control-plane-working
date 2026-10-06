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
  3. Generates the WireGuard keypair LOCALLY (never transmitted), writes the
     private key to /etc/odivora/wg_private_key (chmod 600), and uploads only
     the public key (POST /gateways/{id}/wg-public-key) for peer coordination.
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


def _detect_wan_interface() -> str:
    """Uplink interface holding the default route (eth0/enp0s31f6/ens18/...).

    Writing a hardcoded "eth0" here yields NAT rules that never match, so the
    tunnel comes up with no internet behind it.
    """
    import subprocess
    try:
        out = subprocess.run(["ip", "-o", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        out = ""
    best, best_metric = "", None
    for line in out.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        iface = parts[parts.index("dev") + 1]
        metric = 0
        if "metric" in parts:
            try:
                metric = int(parts[parts.index("metric") + 1])
            except (IndexError, ValueError):
                metric = 0
        if best_metric is None or metric < best_metric:
            best, best_metric = iface, metric
    if best:
        return best
    print("[warn] no default route found; defaulting WAN_INTERFACE to eth0")
    return "eth0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default=os.environ.get("ODIVORA_API_BASE", "http://127.0.0.1:8000"))
    ap.add_argument("--device-type", default="linux")
    ap.add_argument("--reset", action="store_true", help="wipe local state and re-register")
    args = ap.parse_args()
    # Strip copy-paste artifacts like "<IP>" or a trailing ">"
    args.api_base = args.api_base.strip().strip("<>")
    if not args.api_base.startswith(("http://", "https://")):
        sys.exit(f"Invalid --api-base: {args.api_base}  (must start with http:// or https://)")
    if args.reset:
        for p in (STATE_FILE, ENV_FILE, WG_PRIVATE_KEY_FILE):
            try: os.remove(p)
            except FileNotFoundError: pass
        print("Local state wiped.")
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
        pairing = input("Enter the pairing code printed above (or from the API): ").strip()
        user_token = input("Paste your ODIVORA user access token (owner): ").strip()
        if not pairing or not user_token:
            sys.exit("Pairing code and user access token are both required.")
        code, res = _post(
            f"{args.api_base}/api/v1/me/gateways/{state['gateway_id']}/claim",
            {"pairing_code": pairing}, token=user_token)
        if code != 200:
            sys.exit(f"claim failed {code}: {res}\n(If the code expired, rerun with --reset.)")
        state["gateway_token"] = res["gateway_token"]
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
        print("Claimed. gateway_token stored.")
    else:
        print("gateway_token already present.")

    # 3. WireGuard keypair: generated HERE, on the gateway. The private half is
    #    written to local storage and never transmitted; only the public half is
    #    uploaded (POST /gateways/{id}/wg-public-key, authenticated with the
    #    gateway token) so the cloud can hand it to phones as a peer.
    if not os.path.exists(WG_PRIVATE_KEY_FILE):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))))
        from app.gateway.keypair import generate_wg_keypair, store_wg_private_key_locally
        keys = generate_wg_keypair()
        if not store_wg_private_key_locally(keys["private_key"], WG_PRIVATE_KEY_FILE):
            sys.exit(f"could not write private key to {WG_PRIVATE_KEY_FILE}")
        os.chmod(WG_PRIVATE_KEY_FILE, 0o600)
        code, res = _post(
            f"{args.api_base}/api/v1/gateways/{state['gateway_id']}/wg-public-key",
            {"wg_public_key": keys["public_key"]}, token=state["gateway_token"])
        if code != 200:
            sys.exit(f"wg-public-key upload failed {code}: {res}\n"
                     "The private key is on disk and was NOT sent anywhere; "
                     "re-run to retry the upload.")
        print(f"WireGuard keypair generated on this device.")
        print(f"  private key -> {WG_PRIVATE_KEY_FILE} (mode 600, never transmitted)")
        print(f"  public key  -> {keys['public_key']} (uploaded: {res.get('status')})")
    else:
        print("WG private key already present.")
        # Re-upload the public key when the server doesn't know it yet (e.g. the
        # DB was reset, or this device is being re-keyed).
        from_wg = None
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))))
            from app.gateway.keypair import get_wg_public_key_from_private
            with open(WG_PRIVATE_KEY_FILE) as f:
                from_wg = get_wg_public_key_from_private(f.read().strip())
        except Exception as e:
            print(f"[warn] could not derive public key locally: {e}")
        if from_wg:
            code, res = _post(
                f"{args.api_base}/api/v1/gateways/{state['gateway_id']}/wg-public-key",
                {"wg_public_key": from_wg}, token=state["gateway_token"])
            print(f"public key registration: {code} {res.get('status', res)}")

    # 4. env file
    wan = _detect_wan_interface()
    # Preserve settings the operator added by hand (e.g. WG_ENDPOINT) instead of
    # silently dropping them on every re-run.
    previous = {}
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            if "=" in line and not line.startswith("#"):
                k, _, v = line.strip().partition("=")
                previous[k] = v
    with open(ENV_FILE, "w") as f:
        f.write(f"ODIVORA_API_BASE={args.api_base}\n")
        f.write(f"GATEWAY_ID={state['gateway_id']}\n")
        f.write(f"GATEWAY_TOKEN={state['gateway_token']}\n")
        f.write("WG_INTERFACE=wg0\n")
        f.write(f"WAN_INTERFACE={wan}\n")
        f.write("DEVICE_KIND=linux\nSYNC_INTERVAL=10\n")
        for k, v in previous.items():
            if k not in ("ODIVORA_API_BASE", "GATEWAY_ID", "GATEWAY_TOKEN",
                         "WG_INTERFACE", "WAN_INTERFACE", "DEVICE_KIND",
                         "SYNC_INTERVAL") and v:
                f.write(f"{k}={v}\n")
                print(f"preserved {k}={v}")
    os.chmod(ENV_FILE, 0o600)
    print(f"\nWrote {ENV_FILE} (WAN_INTERFACE={wan}). Next:")
    print("  sudo cp firmware/linux_gateway/odivora-gateway.service /etc/systemd/system/")
    print("  sudo systemctl daemon-reload && sudo systemctl enable --now odivora-gateway")


if __name__ == "__main__":
    main()
