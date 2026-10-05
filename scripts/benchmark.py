"""V1B benchmark runner (§16) — repeatable operational procedure.

Runs the *measurement plan* on the phone/host: baseline ping to a
reference IP, ping through the tunnel, establishment timing hints, and
an optional iperf3 run pointing at a server on the far side.

Usage:
    python scripts/benchmark.py --tunnel-ip 10.70.3.5 --ref-ip 1.1.1.1 \
        --gateway-ip 10.70.3.1 --iperf-server <home-lan-host>

All results are printed as a Markdown table you can paste into the
benchmark report. DO NOT hard-code expected numbers — record what you
observe; the doc template is docs/BENCHMARK_TEMPLATE.md.
"""
import argparse
import re
import statistics
import subprocess
import time


def ping_avg(target: str, count: int = 20) -> dict:
    try:
        out = subprocess.run(
            ["ping", "-n", str(count), target],
            capture_output=True, text=True, timeout=60,
        ).stdout
    except FileNotFoundError:
        # POSIX style
        out = subprocess.run(
            ["ping", "-c", str(count), target],
            capture_output=True, text=True, timeout=60,
        ).stdout
    lats = [float(m) for m in re.findall(r"time[=<]\s*([\d.]+)\s*ms", out)]
    loss = 0.0
    m = re.search(r"\((\d+)% loss\)", out) or re.search(r"(\d+)% packet loss", out)
    if m:
        loss = float(m.group(1))
    return {
        "target": target,
        "sent": count,
        "avg_ms": round(statistics.mean(lats), 2) if lats else None,
        "jitter_ms": round(statistics.pstdev(lats), 2) if len(lats) > 1 else None,
        "loss_pct": loss,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tunnel-ip", help="phone's tunnel IP (or gateway peer IP)")
    ap.add_argument("--gateway-ip", help="gateway's tunnel interface IP")
    ap.add_argument("--ref-ip", default="1.1.1.1")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--iperf-server", default=None)
    ap.add_argument("--iperf-seconds", type=int, default=15)
    args = ap.parse_args()

    rows = []
    rows.append(ping_avg(args.ref_ip, args.count))
    if args.gateway_ip:
        rows.append(ping_avg(args.gateway_ip, args.count))  # through tunnel
    if args.iperf_server:
        cmd = ["iperf3", "-c", args.iperf_server, "-t", str(args.iperf_seconds), "-J"]
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True)
        print(f"# iperf3 to {args.iperf_server} took {time.time()-t0:.1f}s")
        print(r.stdout[-2000:] if r.stdout else r.stderr[-2000:])

    print("\n| target | sent | avg ms | jitter ms | loss % |")
    print("|--------|------|--------|-----------|--------|")
    for r in rows:
        print(f"| {r['target']} | {r['sent']} | {r['avg_ms']} | {r['jitter_ms']} | {r['loss_pct']} |")


if __name__ == "__main__":
    main()
