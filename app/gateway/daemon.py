"""Gateway peer-sync daemon (V1B Stage 4).

Runs on the gateway (Linux/OpenWrt). Polls the Cloud for the gateway's
authorized WireGuard peers and reconciles the local `wg0` peer set.
Forwarding/NAT are ensured once per loop (idempotent).

    python -m app.gateway.daemon \
        --api-base http://cloud:8000 --gateway-id <uuid> \
        --token <gateway_token> --kind linux --interval 10

RELAY/CGNAT and WebSocket push are future enhancements; polling keeps
the first version simple and dependable. No private keys are handled.
"""
import argparse
import json
import time
import urllib.request

from app.gateway.dataplane import PeerSpec, get_dataplane


def fetch_desired_peers(api_base: str, gateway_id: str, token: str) -> list[PeerSpec]:
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/v1/gateways/{gateway_id}/peers",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return [
        PeerSpec(peer_public_key=p["peer_public_key"], allowed_ip=p["allowed_ip"],
                 session_id=p.get("session_id", ""), endpoint=p.get("endpoint"))
        for p in payload.get("peers", [])
        if p.get("peer_public_key") and p.get("allowed_ip")
    ]


def sync_once(api_base: str, gateway_id: str, token: str, dataplane) -> dict:
    desired = fetch_desired_peers(api_base, gateway_id, token)
    dataplane.ensure_forwarding()
    dataplane.ensure_nat()
    return dataplane.sync_peers(desired)


def main():  # pragma: no cover - operational entrypoint
    ap = argparse.ArgumentParser(description="ODIVORA gateway peer-sync daemon")
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--gateway-id", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--kind", default="linux", choices=["linux", "openwrt", "mt7981", "mt7986"])
    ap.add_argument("--interval", type=float, default=10.0)
    args = ap.parse_args()

    dp = get_dataplane(args.kind)
    while True:
        try:
            result = sync_once(args.api_base, args.gateway_id, args.token, dp)
            if result["added"] or result["removed"]:
                print(f"[sync] +{len(result['added'])} -{len(result['removed'])} ={len(result['kept'])} peers")
        except Exception as exc:  # keep the daemon alive
            print(f"[sync] error: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":  # pragma: no cover
    main()
