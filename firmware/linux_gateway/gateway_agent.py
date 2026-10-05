#!/usr/bin/env python3
"""ODIVORA Linux gateway daemon (V1B).

Outbound-only connection to the ODIVORA Cloud (no inbound port
forwarding on the home router needed):

  * register/claim/pair handled once by setup_gateway.py
  * this daemon every --interval s:
      1. POST /gateways/heartbeat (Bearer token + monotonic nonce)
      2. ensure /etc/wireguard/wg0.conf exists with the gateway's
         deterministic tunnel IP + private key
      3. GET /gateways/{id}/peers and reconcile `wg0` (sync_peers)
      4. ensure IP forwarding + NAT (idempotent)

Runs under systemd (see odivora-gateway.service).
"""
import argparse
import json
import os
import sys
import time
import urllib.request

# Make the repo's `app` package importable (firmware/ lives inside the repo).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.gateway.dataplane import PeerSpec, get_dataplane  # noqa: E402

STATE_FILE = "/etc/odivora/state.json"
ENV_FILE = "/etc/odivora/gateway.env"
WG_CONF_DIR = "/etc/wireguard"
WG_CONF_FILE = os.path.join(WG_CONF_DIR, "wg0.conf")
WG_PRIVATE_KEY_FILE = "/etc/odivora/wg_private_key"


def _env():
    cfg = {}
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                cfg[k] = v
    cfg.setdefault("ODIVORA_API_BASE", os.environ.get("ODIVORA_API_BASE", "http://127.0.0.1:8000"))
    cfg.setdefault("GATEWAY_ID", os.environ.get("GATEWAY_ID", ""))
    cfg.setdefault("GATEWAY_TOKEN", os.environ.get("GATEWAY_TOKEN", ""))
    cfg.setdefault("WG_INTERFACE", "wg0")
    cfg.setdefault("WAN_INTERFACE", "eth0")
    cfg.setdefault("DEVICE_KIND", "linux")
    return cfg


def _load_state():
    if os.path.exists(STATE_FILE):
        return json.load(open(STATE_FILE))
    return {}


def _save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    try:
        os.chmod(STATE_FILE, 0o600)
    except Exception:
        pass


def _post(url, payload, token=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def heartbeat(cfg, state):
    state["nonce_ctr"] = int(state.get("nonce_ctr", 0)) + 1
    nonce = str(state["nonce_ctr"]).zfill(10)
    code, res = _post(f"{cfg['ODIVORA_API_BASE']}/api/v1/gateways/heartbeat",
                      {"firmware_version": "linux-gw-1.0", "nonce": nonce},
                      token=cfg["GATEWAY_TOKEN"])
    if code == 200:
        _save_state(state)
        return True
    if code == 409:  # stale nonce: resync by accepting a server-side reset hint
        state["nonce_ctr"] = 1
        _save_state(state)
        print("[hb] stale nonce — resynced counter")
        return True
    print(f"[hb] HTTP {code}: {res}")
    return False


def ensure_wg_conf(cfg, gateway_id):
    """Write /etc/wireguard/wg0.conf with the gateway's deterministic
    tunnel IP if it does not exist yet."""
    if os.path.exists(WG_CONF_FILE):
        return
    try:
        from app.gateway.ip_alloc import gateway_tunnel_ip, gateway_tunnel_network
        ip = gateway_tunnel_ip(gateway_id)
        net = gateway_tunnel_network(gateway_id)
    except Exception:
        ip, net = "10.70.0.1", None
    if not os.path.exists(WG_PRIVATE_KEY_FILE):
        print("[wg] private key missing; run setup_gateway.py first")
        return
    private_key = open(WG_PRIVATE_KEY_FILE).read().strip()
    try:
        os.makedirs(WG_CONF_DIR, exist_ok=True)
        with open(WG_CONF_FILE, "w") as f:
            f.write(
                "[Interface]\n"
                f"Address = {ip}/24\n"
                f"ListenPort = 51820\n"
                f"PrivateKey = {private_key}\n"
            )
        os.chmod(WG_CONF_FILE, 0o600)
        print(f"[wg] wrote {WG_CONF_FILE} (Address {ip}/24, subnet {net})")
        os.system("wg-quick up " + WG_CONF_FILE.replace(".conf", ""))
    except Exception as exc:
        print(f"[wg] conf write failed: {exc}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=None)
    ap.add_argument("--once", action="store_true", help="single iteration (testing)")
    args = ap.parse_args()

    cfg = _env()
    if not cfg["GATEWAY_ID"] or not cfg["GATEWAY_TOKEN"]:
        sys.exit("Missing GATEWAY_ID/GATEWAY_TOKEN — run setup_gateway.py first.")

    state = _load_state()
    dp = get_dataplane(cfg["DEVICE_KIND"])
    dp.interface = cfg["WG_INTERFACE"]
    dp.wan_interface = cfg["WAN_INTERFACE"]
    try:
        from app.gateway.ip_alloc import gateway_tunnel_network
        dp.tunnel_subnet = str(gateway_tunnel_network(cfg["GATEWAY_ID"]))
    except Exception:
        pass
    interval = args.interval if args.interval is not None else float(cfg.get("SYNC_INTERVAL", "10"))

    while True:
        try:
            if heartbeat(cfg, state):
                ensure_wg_conf(cfg, cfg["GATEWAY_ID"])
                try:
                    from app.gateway.daemon import fetch_desired_peers, sync_once
                    res = sync_once(cfg["ODIVORA_API_BASE"], cfg["GATEWAY_ID"],
                                    cfg["GATEWAY_TOKEN"], dp)
                    if res["added"] or res["removed"]:
                        print(f"[sync] +{len(res['added'])} -{len(res['removed'])} ={len(res['kept'])}")
                except Exception as exc:
                    print(f"[sync] error: {exc}")
        except Exception as exc:
            print(f"[agent] error: {exc}")
        if args.once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
