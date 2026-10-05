"""Gateway data-plane abstraction (V1B Stage 4).

The Cloud coordinates *which* peers exist; the gateway daemon applies
that desired state to the local WireGuard interface. Everything that
touches the kernel goes through a CommandRunner so the same reconcile
logic runs on Linux, OpenWrt, and in tests.

Implementations:
- LinuxDataPlane   : ip_forward sysctl + iptables NAT (home prototype)
- OpenWrtDataPlane : same reconcile, sysctl/uci-flavoured NAT hook

Nothing here logs or transmits private keys.
"""
import subprocess
from typing import Iterable, List, Optional, Protocol

# --- desired-state model (mirrors GET /gateways/{id}/peers rows) ---


class PeerSpec:
    def __init__(self, peer_public_key: str, allowed_ip: str, session_id: str = "",
                 endpoint: str | None = None):
        self.peer_public_key = peer_public_key
        self.allowed_ip = allowed_ip  # e.g. "10.70.3.14/32"
        self.session_id = session_id
        # Where to reach this peer's WireGuard endpoint. For DIRECT paths
        # with the gateway public, the gateway leaves this unset (the phone
        # initiates and WireGuard learns the source from the handshake).
        # For RELAY paths both peers use the relay's per-session UDP pair.
        self.endpoint = endpoint

    def __repr__(self):  # pragma: no cover
        return f"PeerSpec({self.peer_public_key[:8]}…, {self.allowed_ip})"


class CommandRunner(Protocol):
    def run(self, args: List[str]) -> tuple[int, str]:
        ...


class SubprocessRunner:
    """Default runner on the gateway itself."""

    def run(self, args: List[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return p.returncode, (p.stdout + p.stderr).strip()
        except FileNotFoundError:
            return 127, f"command not found: {args[0]}"


class InMemoryRunner:
    """Test runner: records commands, fakes `wg show wg0 peers`."""

    def __init__(self, existing_peers: Optional[Iterable[str]] = None):
        self.commands: List[List[str]] = []
        self._peers = list(existing_peers or [])

    def run(self, args: List[str]) -> tuple[int, str]:
        self.commands.append(args)
        joined = " ".join(args)
        if joined.startswith("wg show") and "peers" in args:
            return 0, "\n".join(self._peers)
        if " peer " in joined and joined.endswith(" remove"):
            try:
                self._peers.remove(args[args.index("peer") + 1])
            except ValueError:
                pass
        elif " peer " in joined and "allowed-ips" in args:
            pub = args[args.index("peer") + 1]
            if pub not in self._peers:
                self._peers.append(pub)
        return 0, ""


class BaseDataPlane:
    interface = "wg0"
    wan_interface = "eth0"
    tunnel_subnet = "10.0.0.0/24"  # overridden per gateway in production

    def __init__(self, runner: Optional[CommandRunner] = None):
        self.runner: CommandRunner = runner or SubprocessRunner()

    # --- peer reconcile ---

    def list_peers(self) -> List[str]:
        rc, out = self.runner.run(["wg", "show", self.interface, "peers"])
        if rc != 0:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    def add_peer(self, spec: PeerSpec) -> None:
        args = ["wg", "set", self.interface, "peer", spec.peer_public_key,
                "allowed-ips", spec.allowed_ip]
        if spec.endpoint:
            args += ["endpoint", spec.endpoint]
        self.runner.run(args)

    def remove_peer(self, peer_public_key: str) -> None:
        self.runner.run(["wg", "set", self.interface, "peer", peer_public_key, "remove"])

    def sync_peers(self, desired: Iterable[PeerSpec]) -> dict:
        """Make the local peer set match the Cloud's desired state."""
        desired = {p.peer_public_key: p for p in desired}
        current = set(self.list_peers())
        added = sorted(set(desired) - current)
        removed = sorted(current - set(desired))
        for pub in added:
            self.add_peer(desired[pub])
        for pub in removed:
            self.remove_peer(pub)
        return {"added": added, "removed": removed, "kept": sorted(current & set(desired))}

    # --- forwarding / NAT (platform-specific hooks) ---

    def ensure_forwarding(self) -> None:
        raise NotImplementedError

    def ensure_nat(self) -> None:
        raise NotImplementedError


class LinuxDataPlane(BaseDataPlane):
    def ensure_forwarding(self) -> None:
        self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    def ensure_nat(self) -> None:
        # idempotent: check before add
        rc, _ = self.runner.run([
            "iptables", "-t", "nat", "-C",
            "POSTROUTING", "-s", self.tunnel_subnet,
            "-o", self.wan_interface, "-j", "MASQUERADE",
        ])
        if rc != 0:
            self.runner.run([
                "iptables", "-t", "nat", "-A",
                "POSTROUTING", "-s", self.tunnel_subnet,
                "-o", self.wan_interface, "-j", "MASQUERADE",
            ])
        self.runner.run(["iptables", "-A", "FORWARD", "-i", self.interface, "-o", self.wan_interface, "-j", "ACCEPT"])
        self.runner.run(["iptables", "-A", "FORWARD", "-i", self.wan_interface, "-o", self.interface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


class OpenWrtDataPlane(BaseDataPlane):
    def ensure_forwarding(self) -> None:
        self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    def ensure_nat(self) -> None:
        # OpenWrt: masquerade is normally declared on the WAN firewall zone.
        # Ensure wg zone forwards to wan; equivalent to
        #   uci set firewall.@zone[1].masq='1' && uci commit firewall && /etc/init.d/firewall restart
        self.runner.run(["uci", "get", "firewall.@zone[1].masq"])
        self.runner.run(["/etc/init.d/firewall", "reload"])


def get_dataplane(kind: str, runner: Optional[CommandRunner] = None) -> BaseDataPlane:
    k = (kind or "linux").lower()
    if k in ("openwrt", "mt7981", "mt7986"):
        return OpenWrtDataPlane(runner=runner)
    return LinuxDataPlane(runner=runner)
