"""Gateway peer-sync daemon (V1B Stage 4).

Runs on the gateway (Linux/OpenWrt). Polls the Cloud for the gateway's
authorized WireGuard peers and reconciles the local `wg0` peer set.
Forwarding/NAT are ensured once per loop (idempotent).

    python -m app.gateway.daemon \
        --api-base http://cloud:8000 --gateway-id <uuid> \
        --token <gateway_token> --kind linux --interval 10

RELAY/CGNAT and WebSocket push are future enhancements; polling keeps
the first version simple and dependable. No private keys are handled.

The loop backs off exponentially with jitter rather than sleeping a flat
interval, so a fleet of gateways does not reconnect in lockstep after an
outage and a long outage does not pin the Cloud at full poll rate. The cap is
held below the Cloud's offline threshold — see app/gateway/backoff.py.
"""
import argparse
import json
import time
import urllib.request

from app.gateway.backoff import Backoff, describe
from app.gateway.dataplane import PeerSpec, get_dataplane

# Re-verifying ip_forward and the NAT rules costs several subprocesses per
# check and both are idempotent, so pace them independently of peer sync.
NAT_REVERIFY_SECONDS = 300.0


def fetch_desired_peers(api_base: str, gateway_id: str, token: str,
                        timeout: float = 10.0) -> list[PeerSpec]:
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/v1/gateways/{gateway_id}/peers",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return [
        PeerSpec(peer_public_key=p["peer_public_key"], allowed_ip=p["allowed_ip"],
                 session_id=p.get("session_id", ""), endpoint=p.get("endpoint"))
        for p in payload.get("peers", [])
        if p.get("peer_public_key") and p.get("allowed_ip")
    ]


def sync_once(api_base: str, gateway_id: str, token: str, dataplane,
              check_forwarding: bool = True) -> dict:
    """Reconcile local peers with the Cloud's desired state.

    `check_forwarding` re-verifies ip_forward/NAT; both are idempotent, so
    callers on a hot loop can skip the subprocesses and re-check occasionally.
    """
    desired = fetch_desired_peers(api_base, gateway_id, token)
    if check_forwarding:
        errors = list(dataplane.ensure_forwarding() or [])
        errors += list(dataplane.ensure_nat() or [])
    else:
        errors = []
    result = dataplane.sync_peers(desired)
    result.setdefault("errors", [])
    result["errors"] = list(result["errors"]) + errors
    return result


def main():  # pragma: no cover - operational entrypoint
    ap = argparse.ArgumentParser(description="ODIVORA gateway peer-sync daemon")
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--gateway-id", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--kind", default="linux", choices=["linux", "openwrt", "mt7981", "mt7986"])
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--max-backoff", type=float, default=60.0)
    ap.add_argument("--nat-reverify", type=float, default=NAT_REVERIFY_SECONDS)
    ap.add_argument("--once", action="store_true", help="single iteration (testing)")
    args = ap.parse_args()

    dp = get_dataplane(args.kind)
    backoff = Backoff(base=args.interval, cap=args.max_backoff)
    last_nat_check = 0.0
    print(f"[sync] base={args.interval:g}s cap={args.max_backoff:g}s", flush=True)
    while True:
        ok = False
        try:
            now = time.monotonic()
            due_nat = (now - last_nat_check) >= args.nat_reverify
            result = sync_once(args.api_base, args.gateway_id, args.token, dp,
                               check_forwarding=due_nat)
            if due_nat:
                last_nat_check = now
            ok = not result.get("errors")
            if result["added"] or result["removed"]:
                print(f"[sync] +{len(result['added'])} -{len(result['removed'])} ={len(result['kept'])} peers")
            for err in result.get("errors", []):
                print(f"[sync] ERROR {err}")
        except Exception as exc:  # keep the daemon alive
            print(f"[sync] error: {exc}")
        if args.once:
            break
        delay = backoff.delay(ok)
        if not ok:
            print(f"[sync] unhealthy, retrying in {delay:.1f}s ({describe(backoff)})", flush=True)
        time.sleep(delay)


if __name__ == "__main__":  # pragma: no cover
    main()