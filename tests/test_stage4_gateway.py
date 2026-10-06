"""V1B Stage 4: gateway peer-sync daemon, data-plane abstraction, path planner."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_stage4.db"
try:
    if os.path.exists("./test_stage4.db"):
        os.remove("./test_stage4.db")
except PermissionError:
    pass

import base64
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_stage4.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override
c = TestClient(app)

from app import ratelimit
from app.routers import auth as auth_router


@pytest.fixture(autouse=True)
def _clear():
    app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()
    auth_router._fails.clear()


def reg(email):
    r = c.post("/api/v1/auth/register", json={"email": email, "password": "Password123!"})
    assert r.status_code == 200, r.text
    return r.json()


def ed_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def make_gateway(email):
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register", json={"device_type": "linux", "public_key": ed_keys()})
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    c.post("/api/v1/gateways/heartbeat", json={},
           headers={"Authorization": f"Bearer {gtok}"})
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]},
               headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    return h, gtok, gid


def test_gateway_peers_endpoint_scoped_and_token_authed():
    h, gtok, gid = make_gateway("s4owner@example.com")
    t = reg("s4user@example.com")
    uh = {"Authorization": f"Bearer {t['access_token']}"}
    # non-gateway token rejected
    bad = c.get(f"/api/v1/gateways/{gid}/peers", headers=uh)
    assert bad.status_code == 401
    # gateway token, no peers yet
    r = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"})
    assert r.status_code == 200, r.text
    assert r.json()["peers"] == []
    # authorize one session on same gateway (owner creates connection)
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    a = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert a.status_code == 200, a.text
    r2 = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"}).json()
    assert len(r2["peers"]) == 1
    p = r2["peers"][0]
    assert p["allowed_ip"].endswith("/32") and len(p["peer_public_key"]) > 20
    assert "private" not in str(p).lower()
    # revoke clears it from active peer list
    c.post(f"/api/v1/sessions/{s['id']}/revoke-wg", headers=h)
    r3 = c.get(f"/api/v1/gateways/{gid}/peers", headers={"Authorization": f"Bearer {gtok}"}).json()
    assert r3["peers"] == []


def test_dataplane_sync_adds_missing_and_removes_stale():
    from app.gateway.dataplane import InMemoryRunner, LinuxDataPlane, PeerSpec

    runner = InMemoryRunner(existing_peers=["OLDPEERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="])
    dp = LinuxDataPlane(runner=runner)
    desired = [PeerSpec("NEWPEERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "10.70.3.5/32", "s1")]
    result = dp.sync_peers(desired)
    assert result["added"] == ["NEWPEERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]
    assert result["removed"] and result["removed"][0].startswith("OLDPEER")
    # idempotent second run
    result2 = dp.sync_peers(desired)
    assert result2["added"] == [] and result2["removed"] == []


def test_linux_nat_idempotent():
    from app.gateway.dataplane import InMemoryRunner, LinuxDataPlane

    runner = InMemoryRunner()
    dp = LinuxDataPlane(runner=runner)
    dp.wan_interface = "enp0s31f6"
    dp.interface_up = lambda: True
    dp.forwarding_enabled = lambda: False
    runner.run(["ip", "link", "show", "enp0s31f6"])  # iface exists
    dp.ensure_forwarding()
    dp.ensure_nat()
    cmds = [" ".join(a) for a in runner.commands]
    assert any("ip_forward=1" in c for c in cmds)
    assert any("POSTROUTING" in c and "MASQUERADE" in c for c in cmds)

    # Regression: every poll interval calls ensure_nat() again. Rules must not
    # be appended again, or the FORWARD chain grows without bound.
    before = len(runner.commands)
    dp.ensure_forwarding()
    dp.ensure_nat()
    added_again = [" ".join(a) for a in runner.commands[before:]
                   if " -A " in " ".join(a) or " -I " in " ".join(a)]
    assert added_again == [], f"rules re-added on second pass: {added_again}"


def test_linux_nat_uses_detected_wan_interface():
    """A wrong WAN name means MASQUERADE never matches -> tunnel has no internet."""
    from app.gateway.dataplane import InMemoryRunner, LinuxDataPlane

    runner = InMemoryRunner()
    dp = LinuxDataPlane(runner=runner)
    dp.wan_interface = "eth0"  # does not exist on this host
    dp.forwarding_enabled = lambda: True

    def fake_run(args):
        runner.commands.append(list(args))
        joined = " ".join(args)
        if joined.startswith("ip -o route show default"):
            return 0, "default via 192.168.10.1 dev enp0s31f6 proto dhcp metric 100"
        if joined == "ip link show eth0":
            return 1, "Device \"eth0\" does not exist."
        if joined.startswith("ip link show enp0s31f6"):
            return 0, "3: enp0s31f6: <BROADCAST> state UP"
        if "-C" in args:
            return 1, ""
        return 0, ""

    dp.runner = type("R", (), {"run": staticmethod(fake_run)})()
    assert dp.resolve_wan_interface() == "enp0s31f6"
    dp.ensure_nat()
    cmds = [" ".join(a) for a in runner.commands]
    assert any("enp0s31f6" in c and "MASQUERADE" in c for c in cmds), cmds
    # eth0 may only appear in the existence probe, never in an applied rule.
    applied = [c for c in cmds if c.startswith("iptables")]
    assert not any("eth0" in c for c in applied), applied


def test_sync_peers_reports_errors():
    """`wg set` failures must surface, not look like a successful sync."""
    from app.gateway.dataplane import LinuxDataPlane, PeerSpec

    class FailingRunner:
        def run(self, args):
            if args[0] == "wg" and args[1] == "show":
                return 0, ""
            if len(args) > 1 and args[1] == "set":
                return 1, "Unable to access interface: No such device"
            return 0, ""

    dp = LinuxDataPlane(runner=FailingRunner())
    res = dp.sync_peers([PeerSpec("PUB" + "A" * 43, "10.70.0.2/32", "s1")])
    assert res["added"], res
    assert res["errors"], f"failure not surfaced: {res}"
    assert "No such device" in res["errors"][0]


def test_detect_wan_interface_helper():
    from app.gateway.dataplane import detect_wan_interface

    class R:
        def run(self, args):
            return 0, ("default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.5 metric 600\n"
                       "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100")

    assert detect_wan_interface(R()) == "enp3s0"

    class Down:
        def run(self, args):
            return 1, "ip: command not found"

    assert detect_wan_interface(Down()) is None


def test_wg_keys_are_wireguard_valid():
    """Regression: stripping base64 padding produced keys `wg` rejects.

    A 32-byte WireGuard key must be standard base64 WITH padding: exactly 44
    characters ending in '='. Unpadded output made every gateway keypair
    unusable ("Key is not the correct length or format").
    """
    import base64
    from app.gateway.keypair import generate_wg_keypair, get_wg_public_key_from_private

    for _ in range(5):
        k = generate_wg_keypair()
        for field in ("private_key", "public_key"):
            val = k[field]
            assert len(val) == 44, f"{field} must be 44 chars, got {len(val)}: {val}"
            assert val.endswith("="), f"{field} must keep base64 padding: {val}"
            assert len(base64.b64decode(val, validate=True)) == 32
        assert get_wg_public_key_from_private(k["private_key"]) == k["public_key"]


def test_get_wg_public_key_rejects_junk():
    import pytest
    from app.gateway.keypair import get_wg_public_key_from_private

    with pytest.raises(ValueError):
        get_wg_public_key_from_private("not-a-real-key")
    with pytest.raises(ValueError):
        get_wg_public_key_from_private(base64.b64encode(b"short").decode())


def test_ensure_rule_preserves_table_before_verb():
    """Regression: `iptables -C -t nat ...` is invalid.

    iptables requires global options (`-t nat`) BEFORE the action verb.
    Emitting the verb first made every NAT check/add fail with
    "Bad argument `nat'", so MASQUERADE was silently never installed.
    """
    from app.gateway.dataplane import LinuxDataPlane

    seen = []

    class Recording:
        def run(self, args):
            seen.append(list(args))
            if "-C" in args:
                return 1, ""
            return 0, ""

    dp = LinuxDataPlane(runner=Recording())
    dp.tunnel_subnet = "10.70.0.0/24"
    dp.wan_interface = "enp0s31f6"
    dp.forwarding_enabled = lambda: True
    dp.resolve_wan_interface = lambda: "enp0s31f6"
    errors = dp.ensure_nat()

    nat_cmds = [a for a in seen if "nat" in a]
    assert nat_cmds, seen
    for cmd in nat_cmds:
        assert cmd.index("-t") < min(cmd.index(v) for v in ("-A", "-C", "-I") if v in cmd), cmd
    assert any("-t" in c and c.index("-t") < c.index("-C") for c in nat_cmds), nat_cmds
    assert errors == [], errors


def test_ensure_nat_surfaces_failures():
    from app.gateway.dataplane import LinuxDataPlane

    class Denying:
        def run(self, args):
            return 1, "Permission denied (you must be root)"

    dp = LinuxDataPlane(runner=Denying())
    dp.wan_interface = "eth0"
    dp.forwarding_enabled = lambda: True
    dp.resolve_wan_interface = lambda: "eth0"
    errors = dp.ensure_nat()
    assert errors, "a failing iptables must not look like success"
    assert any("MASQUERADE" in e for e in errors), errors


def test_path_planner():
    from app.paths import plan_connection_path

    assert plan_connection_path(True, True)["path"] == "direct"
    assert plan_connection_path(False, True)["path"] == "unknown"
    assert plan_connection_path(True, False, relay_available=True)["path"] == "relay"
    assert plan_connection_path(True, False)["path"] == "unknown"
