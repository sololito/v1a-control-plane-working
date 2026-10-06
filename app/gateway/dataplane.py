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


def detect_wan_interface(runner: Optional["CommandRunner"] = None) -> Optional[str]:
    """Name of the interface holding the default route (the WAN/uplink).

    Distributions name the uplink differently (eth0, enp0s31f6, ens18, ...).
    Hardcoding one means NAT silently never matches, so probe instead.
    """
    runner = runner or SubprocessRunner()
    rc, out = runner.run(["ip", "-o", "route", "show", "default"])
    if rc != 0:
        return None
    best, best_metric = None, None
    for line in out.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        iface = parts[parts.index("dev") + 1]
        metric = None
        if "metric" in parts:
            try:
                metric = int(parts[parts.index("metric") + 1])
            except (IndexError, ValueError):
                metric = None
        # Prefer the lowest metric; untagged routes sort first (None -> 0).
        rank = 0 if metric is None else metric
        if best_metric is None or rank < best_metric:
            best, best_metric = iface, rank
    return best


class InMemoryRunner:
    """Test runner: records commands, fakes `wg show wg0 peers` + iptables state."""

    def __init__(self, existing_peers: Optional[Iterable[str]] = None,
                 existing_rules: Optional[Iterable[str]] = None):
        self.commands: List[List[str]] = []
        self._peers = list(existing_peers or [])
        self._rules = set(existing_rules or [])

    @staticmethod
    def _rule_key(args: List[str]) -> str:
        # Drop the iptables binary, every action verb, and any insert-position
        # argument so -C/-A/-I of one logical rule map to the same key.
        verbs = ("-A", "-I", "-D", "-C", "-S")
        out, positional_done = [], False
        for i, a in enumerate(args):
            if i == 0 and a == "iptables":
                continue
            if a in verbs:
                continue
            if a.isdigit() and not positional_done:
                positional_done = True  # insert position, e.g. `-I FORWARD 1`
                continue
            out.append(a)
        return " ".join(out)

    def run(self, args: List[str]) -> tuple[int, str]:
        self.commands.append(list(args))
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
        elif " peer " in joined and args[-1] == "remove":
            try:
                self._peers.remove(args[args.index("peer") + 1])
            except ValueError:
                pass
        if args and args[0] == "iptables":
            key = self._rule_key(args)
            if "-C" in args:
                return (0, "") if key in self._rules else (1, "")
            if "-D" in args:
                self._rules.discard(key)
                return 0, ""
            if ("-A" in args or "-I" in args) and key not in self._rules:
                self._rules.add(key)
            return 0, ""
        return 0, ""


class DataPlaneReadError(RuntimeError):
    """The current peer set could not be read, so it is unknown.

    Distinct from "there are no peers". Conflating the two makes an
    unreadable interface look empty, which makes sync_peers re-add every
    desired peer on every poll and reports success while the real fault is
    invisible in the logs.
    """


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
            raise DataPlaneReadError(f"wg show peers failed rc={rc}: {out}")
        return [line.strip() for line in out.splitlines() if line.strip()]

    def add_peer(self, spec: PeerSpec) -> tuple[int, str]:
        args = ["wg", "set", self.interface, "peer", spec.peer_public_key,
                "allowed-ips", spec.allowed_ip]
        if spec.endpoint:
            args += ["endpoint", spec.endpoint]
        return self.runner.run(args)

    def remove_peer(self, peer_public_key: str) -> tuple[int, str]:
        return self.runner.run(["wg", "set", self.interface, "peer", peer_public_key, "remove"])

    def interface_up(self) -> bool:
        rc, _ = self.runner.run(["ip", "link", "show", self.interface])
        return rc == 0

    def handshakes(self) -> dict[str, float]:
        """Peer public key -> unix time of that peer's last WireGuard handshake.

        Read-only evidence for the event cache. An unreadable interface is
        reported as "no data" rather than raising: this feeds a log, it does
        not gate reconciliation.
        """
        rc, out = self.runner.run(["wg", "show", self.interface, "latest-handshakes"])
        if rc != 0:
            return {}
        result: dict[str, float] = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    result[parts[0].strip()] = float(parts[1].strip())
                except ValueError:
                    continue
        return result

    def wan_ip(self) -> Optional[str]:
        """Address on the WAN interface, i.e. the IP the tunnel egresses from.

        Changes here (DHCP lease, failover, mobile APN) are worth an event:
        the phone's direct-connection hint goes stale the moment it moves.
        """
        rc, out = self.runner.run(["ip", "-4", "-o", "addr", "show", "dev", self.wan_interface])
        if rc != 0:
            return None
        tokens = out.split()
        for i, token in enumerate(tokens):
            if token == "inet" and i + 1 < len(tokens):
                return tokens[i + 1].split("/")[0]
        return None

    def sync_peers(self, desired: Iterable[PeerSpec]) -> dict:
        """Make the local peer set match the Cloud's desired state.

        Reconciliation needs to know what is already there. If that read
        fails the diff is unknowable, so nothing is applied: acting on a
        guess would rewrite every peer on a transient `wg` error. The failure
        is reported instead of being papered over.
        """
        desired = {p.peer_public_key: p for p in desired}
        try:
            current = set(self.list_peers())
        except DataPlaneReadError as exc:
            return {"added": [], "removed": [], "kept": [],
                    "errors": [f"peer state unreadable, reconcile skipped: {exc}"],
                    "readable": False}
        added = sorted(set(desired) - current)
        removed = sorted(current - set(desired))
        errors = []
        for pub in added:
            rc, out = self.add_peer(desired[pub])
            if rc != 0:
                errors.append(f"add {pub[:8]}…: {out}")
        for pub in removed:
            rc, out = self.remove_peer(pub)
            if rc != 0:
                errors.append(f"remove {pub[:8]}…: {out}")
        return {"added": added, "removed": removed,
                "kept": sorted(current & set(desired)), "errors": errors,
                "readable": True}

    # --- forwarding / NAT (platform-specific hooks) ---

    def ensure_forwarding(self) -> List[str]:
        raise NotImplementedError

    def ensure_nat(self) -> List[str]:
        """Idempotently install the NAT + forwarding rules.

        Returns a list of error strings (empty when everything applied).
        The daemon logs these; silently ignoring them hides a broken tunnel.
        """
        raise NotImplementedError

    # --- shared helpers ---

    def forwarding_enabled(self) -> bool:
        rc, out = self.runner.run(["sysctl", "-n", "net.ipv4.ip_forward"])
        return rc == 0 and out.strip().splitlines()[0].strip() == "1" if out.strip() else False

    def resolve_wan_interface(self) -> str:
        """Return a usable WAN interface name.

        If the configured name does not exist on this host, fall back to the
        interface owning the default route so NAT actually applies.
        """
        rc, _ = self.runner.run(["ip", "link", "show", self.wan_interface])
        if rc == 0:
            return self.wan_interface
        detected = detect_wan_interface(self.runner)
        if detected:
            return detected
        return self.wan_interface

    def _ensure_rule(self, args: List[str], insert: bool = False) -> tuple[bool, str]:
        """Add an iptables rule only if an identical rule is absent.

        `args` is a full command whose action verb (-A/-I/-C/-D) is swapped in
        place, because iptables requires global options such as `-t nat` to
        come *before* the verb.
        Returns (added, error_message).
        The daemon calls this every poll interval, so an unguarded `-A` would
        grow the chain without bound (thousands of duplicate rules per day).
        """
        verbs = ("-A", "-I", "-D", "-C", "-S")
        try:
            vi = next(i for i, a in enumerate(args) if a in verbs)
        except StopIteration:
            return False, f"no action verb in {args!r}"
        check = list(args)
        check[vi] = "-C"
        rc, out = self.runner.run(check)
        if rc == 0:
            return False, ""
        add = list(args)
        add[vi] = "-I" if insert else "-A"
        rc, out = self.runner.run(add)
        if rc != 0:
            return False, f"{' '.join(add)}: rc={rc} {out}".strip()
        return True, ""


class LinuxDataPlane(BaseDataPlane):
    def ensure_forwarding(self) -> List[str]:
        errors = []
        if not self.forwarding_enabled():
            rc, out = self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            if rc != 0:
                errors.append(f"enable ip_forward: rc={rc} {out}".strip())
        return errors

    def ensure_nat(self) -> List[str]:
        wan = self.resolve_wan_interface()
        errors = []
        # NAT: check before add. FORWARD rules are inserted at the head of the
        # chain so they win over a default DROP policy (ufw ships
        # DEFAULT_FORWARD_POLICY=DROP) without disabling the firewall.
        for args, insert in (
            (["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", self.tunnel_subnet,
              "-o", wan, "-j", "MASQUERADE"], False),
            (["iptables", "-A", "FORWARD", "-i", self.interface, "-o", wan,
              "-j", "ACCEPT"], True),
            (["iptables", "-A", "FORWARD", "-i", wan, "-o", self.interface,
              "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
              "-j", "ACCEPT"], True),
        ):
            _, err = self._ensure_rule(args, insert=insert)
            if err:
                errors.append(err)
        return errors


class OpenWrtDataPlane(BaseDataPlane):
    def ensure_forwarding(self) -> List[str]:
        if not self.forwarding_enabled():
            rc, out = self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            if rc != 0:
                return [f"enable ip_forward: rc={rc} {out}".strip()]
        return []

    def ensure_nat(self) -> List[str]:
        # OpenWrt: masquerade is normally declared on the WAN firewall zone.
        # Ensure wg zone forwards to wan; equivalent to
        #   uci set firewall.@zone[1].masq='1' && uci commit firewall && /etc/init.d/firewall restart
        errors = []
        for cmd in (["uci", "get", "firewall.@zone[1].masq"],
                    ["/etc/init.d/firewall", "reload"]):
            rc, out = self.runner.run(cmd)
            if rc != 0:
                errors.append(f"{' '.join(cmd)}: rc={rc} {out}".strip())
        return errors


def get_dataplane(kind: str, runner: Optional[CommandRunner] = None) -> BaseDataPlane:
    k = (kind or "linux").lower()
    if k in ("openwrt", "mt7981", "mt7986"):
        return OpenWrtDataPlane(runner=runner)
    return LinuxDataPlane(runner=runner)
