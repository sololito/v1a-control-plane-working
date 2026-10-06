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
import random
import shutil
import signal
import sys
import time
import urllib.error
import urllib.request

# Make the repo's `app` package importable (firmware/ lives inside the repo).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.gateway.backoff import Backoff, describe  # noqa: E402
from app.gateway.dataplane import PeerSpec, get_dataplane  # noqa: E402

STATE_FILE = "/etc/odivora/state.json"
ENV_FILE = "/etc/odivora/gateway.env"
WG_CONF_DIR = "/etc/wireguard"
WG_CONF_FILE = os.path.join(WG_CONF_DIR, "wg0.conf")
WG_PRIVATE_KEY_FILE = "/etc/odivora/wg_private_key"
# Keep the gateway's own NAT mapping warm. Must be <= the relay's keepalive
# cadence so neither side's mapping can lapse while the tunnel is idle.
WG_KEEPALIVE_SECONDS = 15
# ip_forward and the NAT rules are idempotent, so re-verifying them on every
# peer sync is pure overhead (a handful of subprocesses each poll). Re-check
# occasionally instead; anything that changes them out-of-band is still
# self-healing, just within this window.
NAT_REVERIFY_SECONDS = 300.0
# Set by SIGTERM/SIGINT so a systemd stop does not have to wait out the current
# backoff sleep.
_STOPPING = False


def _handle_stop(_signum, _frame):
    global _STOPPING
    _STOPPING = True


def stop_wait(seconds):
    """Sleep in short slices, returning early when asked to stop."""
    deadline = time.monotonic() + max(0.0, seconds)
    while not _STOPPING:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.5, remaining))


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
    # Optional public endpoint (host:port) for direct connections, e.g. when
    # UDP 51820 is port-forwarded from the home router. Unset => relay path.
    cfg.setdefault("WG_ENDPOINT", os.environ.get("WG_ENDPOINT", ""))
    return cfg


def _load_state():
    """Read state, tolerating a missing or corrupt file.

    The previous version called json.load() on the file unguarded, so a single
    truncated write (power cut mid-`json.dump`) raised at startup and the agent
    never came back — the one file whose corruption is unrecoverable was also
    the one file written most often. Fall back to the previous good copy and
    only then start clean.
    """
    for path in (STATE_FILE, STATE_FILE + ".bak"):
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            print(f"[state] {path} is not an object; ignoring")
        except (ValueError, OSError) as exc:
            print(f"[state] cannot read {path}: {exc}")
    return {}


def _save_state(state):
    """Write state atomically, keeping the previous good copy.

    Write-to-temp + fsync + rename: a crash leaves either the old file or the
    new one, never a half-written one that no longer parses. The chmod happens
    before the rename so the file is never briefly world-readable, which
    matters because it holds the gateway bearer token and the Ed25519 key.
    """
    directory = os.path.dirname(STATE_FILE) or "."
    tmp = f"{STATE_FILE}.tmp"
    try:
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(STATE_FILE):
            shutil.copyfile(STATE_FILE, f"{STATE_FILE}.bak")
        with open(tmp, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)
    except OSError as exc:
        print(f"[state] save failed: {exc}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise


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
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # Cloud unreachable (boot ordering, Wi-Fi still associating). Report a
        # synthetic status so the loop keeps running instead of dying.
        return 0, {"error": str(e)}


def refresh_token(cfg, state, attempts=2):
    """Re-mint the gateway bearer token via the Ed25519 challenge/verify flow.

    Gateway tokens expire (GATEWAY_TOKEN_EXPIRE_MINUTES). Without this the
    gateway would go permanently offline an hour after provisioning. The
    Ed25519 private key never leaves the device — only the signature does.

    The nonce/verify pair is two sequential round trips, so a single dropped
    connection here used to strand the gateway for a whole poll interval even
    though nothing was actually wrong. Retry immediately, with jitter, before
    giving up and letting the loop back off.
    """
    priv_b64 = state.get("ed25519_private_key")
    if not priv_b64:
        print("[auth] no Ed25519 identity in state; cannot refresh token")
        return False
    gid = state.get("gateway_id") or cfg.get("GATEWAY_ID")
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    except Exception as exc:
        print(f"[auth] cannot load Ed25519 identity: {exc}")
        return False

    last = "not attempted"
    for attempt in range(1, max(1, attempts) + 1):
        code, res = _post(f"{cfg['ODIVORA_API_BASE']}/api/v1/gateways/{gid}/nonce", {})
        if code == 0:
            last = f"cloud unreachable: {res.get('error') if isinstance(res, dict) else res}"
        elif code != 200 or not res.get("nonce"):
            # An HTTP answer here is authoritative; repeating it will not help.
            print(f"[auth] nonce request failed HTTP {code}: {res}")
            return False
        else:
            try:
                sig = base64.b64encode(key.sign(res["nonce"].encode())).decode()
            except Exception as exc:
                print(f"[auth] signing failed: {exc}")
                return False
            code, res = _post(
                f"{cfg['ODIVORA_API_BASE']}/api/v1/gateways/{gid}/auth/verify",
                {"nonce": res["nonce"], "signature": sig})
            if code == 200 and res.get("gateway_token"):
                state["gateway_token"] = res["gateway_token"]
                _save_state(state)
                cfg["GATEWAY_TOKEN"] = res["gateway_token"]
                print("[auth] token refreshed")
                return True
            if code != 0:
                print(f"[auth] verify failed HTTP {code}: {res}")
                return False
            last = f"verify unreachable: {res.get('error') if isinstance(res, dict) else res}"
        if attempt < attempts:
            # Small jittered pause: enough to clear a transient blip, short
            # enough that a token refresh never delays the heartbeat much.
            time.sleep(0.4 + random.random() * 0.6)
    print(f"[auth] token refresh failed after {attempts} attempts: {last}")
    return False


def heartbeat(cfg, state, max_refresh=1):
    """Prove liveness to the Cloud and prove our token is still valid.

    Returns True when the gateway is confirmed healthy, False when the caller
    should back off. An expired token is recoverable, so a successful refresh
    is followed by an immediate retry in the same call — returning False here
    used to park the gateway for a full poll interval with a valid token
    already in hand.
    """
    for _ in range(max(1, max_refresh) + 1):
        state["nonce_ctr"] = int(state.get("nonce_ctr", 0)) + 1
        nonce = str(state["nonce_ctr"]).zfill(10)
        payload = {"firmware_version": "linux-gw-1.0", "nonce": nonce}
        if cfg.get("WG_ENDPOINT"):
            payload["wg_endpoint"] = cfg["WG_ENDPOINT"]
        code, res = _post(f"{cfg['ODIVORA_API_BASE']}/api/v1/gateways/heartbeat",
                          payload, token=cfg["GATEWAY_TOKEN"])
        if code == 200:
            _save_state(state)
            return True
        if code == 409:  # stale nonce: resume from the server's counter
            detail = res.get("detail") if isinstance(res, dict) else None
            server_nonce = detail.get("last_nonce") if isinstance(detail, dict) else None
            try:
                state["nonce_ctr"] = int(server_nonce) + 1
            except (TypeError, ValueError):
                state["nonce_ctr"] = int(state.get("nonce_ctr", 0)) + 1
            _save_state(state)
            print(f"[hb] stale nonce — resumed counter at {state['nonce_ctr']}")
            return True
        if code == 0:
            print(f"[hb] cloud unreachable: {res.get('error') if isinstance(res, dict) else res}")
            return False
        if code in (401, 403):
            print(f"[auth] token rejected ({code}) — refreshing via Ed25519 challenge")
            if not refresh_token(cfg, state):
                print("[auth] token refresh failed; backing off")
                return False
            cfg["GATEWAY_TOKEN"] = state.get("gateway_token", cfg["GATEWAY_TOKEN"])
            # Loop straight back around: the new token is already in hand, so
            # there is no reason to make the caller wait another interval.
            continue
        print(f"[hb] HTTP {code}: {res}")
        return False
    return False
        print("[auth] token refresh failed; retrying next poll")
        return False
    print(f"[hb] HTTP {code}: {res}")
    return False


def ensure_wg_conf(cfg, gateway_id, dp):
    """Ensure /etc/wireguard/wg0.conf exists AND the interface is up.

    Writing the config is not enough: after a reboot (or a `wg-quick down`)
    the file is still there but wg0 is gone, and every `wg set` then fails
    with "Unable to access interface". So verify the link each iteration and
    bring it up when missing.
    """
    if not os.path.exists(WG_CONF_FILE):
        _write_wg_conf(cfg, gateway_id)
    if dp.interface_up():
        return
    if not os.path.exists(WG_CONF_FILE):
        print("[wg] no config and no private key; skipping interface bring-up")
        return
    rc, out = dp.runner.run(["wg-quick", "up", cfg["WG_INTERFACE"]])
    if rc != 0:
        print(f"[wg-quick] up failed rc={rc}: {out}")
    else:
        print(f"[wg] brought {cfg['WG_INTERFACE']} up")


def _write_wg_conf(cfg, gateway_id):
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
                "ListenPort = 51820\n"
                f"PrivateKey = {private_key}\n"
                # Without this the gateway's outbound NAT mapping is torn down
                # by the router after a few minutes of silence, and the next
                # inbound handshake from a phone never arrives. The phone gets
                # the same setting from the Cloud, but the gateway was missing
                # it entirely, so a tunnel that idled for a while came back
                # dead on both the direct and relay paths.
                f"PersistentKeepalive = {WG_KEEPALIVE_SECONDS}\n"
            )
        os.chmod(WG_CONF_FILE, 0o600)
        print(f"[wg] wrote {WG_CONF_FILE} (Address {ip}/24, subnet {net})")
    except Exception as exc:
        print(f"[wg] conf write failed: {exc}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=None)
    ap.add_argument("--once", action="store_true", help="single iteration (testing)")
    ap.add_argument("--max-backoff", type=float, default=None,
                    help="ceiling for the reconnect backoff")
    args = ap.parse_args()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle_stop)
        except (ValueError, OSError):
            pass  # not on the main thread, or unsupported platform

    cfg = _env()
    if not cfg["GATEWAY_ID"] or not cfg["GATEWAY_TOKEN"]:
        sys.exit("Missing GATEWAY_ID/GATEWAY_TOKEN — run setup_gateway.py first.")

    state = _load_state()
    # state.json holds the freshly-minted token; gateway.env is written once at
    # provisioning time and goes stale, so prefer the state file.
    if state.get("gateway_token"):
        cfg["GATEWAY_TOKEN"] = state["gateway_token"]
    if state.get("gateway_id"):
        cfg["GATEWAY_ID"] = state["gateway_id"]

    dp = get_dataplane(cfg["DEVICE_KIND"])
    dp.interface = cfg["WG_INTERFACE"]
    dp.wan_interface = cfg["WAN_INTERFACE"]
    try:
        from app.gateway.ip_alloc import gateway_tunnel_network
        dp.tunnel_subnet = str(gateway_tunnel_network(cfg["GATEWAY_ID"]))
    except Exception:
        pass
    interval = args.interval if args.interval is not None else float(cfg.get("SYNC_INTERVAL", "10"))
    max_backoff = args.max_backoff if args.max_backoff is not None else float(
    cfg.get("MAX_BACKOFF", "60"))

    # Resolve the uplink once: a wrong name means MASQUERADE never matches
    # and peers get a tunnel with no internet behind it.
    configured_wan = cfg["WAN_INTERFACE"]
    resolved_wan = dp.resolve_wan_interface()
    if resolved_wan != configured_wan:
        print(f"[net] WAN_INTERFACE={configured_wan} not present; using default-route iface {resolved_wan}")
    dp.wan_interface = resolved_wan
    print(f"[net] wg={dp.interface} wan={dp.wan_interface} tunnel={dp.tunnel_subnet}")
    print(f"[loop] heartbeat {interval}s, backoff cap {max_backoff}s")

    # Liveness and peer reconciliation have different urgency. The heartbeat is
    # cheap and must keep flowing; the sync shells out to wg/iptables several
    # times, so it runs on its own cadence instead of once per heartbeat. The
    # first sync is immediate because that is when peers are most likely to be
    # wrong (post-reboot, post-cloud-restart).
    backoff = Backoff(base=interval, cap=max_backoff)
    peer_sync_interval = float(cfg.get("PEER_SYNC_INTERVAL", str(interval)))
    last_sync = None
    last_nat_check = 0.0
    while True:
        ok = False
        try:
            if heartbeat(cfg, state):
                ok = True
                ensure_wg_conf(cfg, cfg["GATEWAY_ID"], dp)
                now = time.monotonic()
                if not dp.interface_up():
                    print("[sync] wg interface still down; skipping peer sync")
                elif last_sync is None or (now - last_sync) >= peer_sync_interval:
                    last_sync = now
                    try:
                        from app.gateway.daemon import sync_once
                        res = sync_once(cfg["ODIVORA_API_BASE"], cfg["GATEWAY_ID"],
                                        cfg["GATEWAY_TOKEN"], dp,
                                        check_forwarding=(now - last_nat_check) >= NAT_REVERIFY_SECONDS)
                        last_nat_check = now
                        if res["added"] or res["removed"]:
                            print(f"[sync] +{len(res['added'])} -{len(res['removed'])} ={len(res['kept'])}")
                        for err in res.get("errors", []):
                            print(f"[sync] ERROR {err}")
                    except Exception as exc:
                        print(f"[sync] error: {exc}")
                        ok = False
        except Exception as exc:
            print(f"[agent] error: {exc}")
            ok = False
        if args.once:
            break
        delay = backoff.delay(ok)
        if not ok:
            print(f"[loop] unhealthy, retrying in {delay:.1f}s ({describe(backoff)})")
        # Wait, but wake early if the process is asked to stop.
        stop_wait(delay)


if __name__ == "__main__":
    main()
