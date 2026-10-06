"""Mobile-foundation audit trail: device identifiers, visited sites,
per-tunnel audit report (JSON + printable HTML)."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_audit_trail.db"
try:
    if os.path.exists("./test_audit_trail.db"):
        os.remove("./test_audit_trail.db")
except PermissionError:
    pass

import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_audit_trail.db",
                       connect_args={"check_same_thread": False})
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


def reg(email, extra=None):
    body = {"email": email, "password": "Password123!"}
    body.update(extra or {})
    r = c.post("/api/v1/auth/register", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def headers(tok):
    return {"Authorization": f"Bearer {tok}"}


def make_admin(email="rootadmin@example.com"):
    tok = reg(email)["access_token"]
    db = TestingSession()
    try:
        from app import models
        u = db.query(models.User).filter(models.User.email == email).first()
        u.is_admin = True
        db.commit()
    finally:
        db.close()
    return headers(tok)


def ed_b64(seed: str = "a") -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = (Ed25519PrivateKey.generate().public_key()
           .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return base64.b64encode(raw).decode()


def setup_tunnel(email="owner@example.com"):
    """user -> gateway online with WG key -> live session. Returns (h, gid, sid)."""
    h = headers(reg(email)["access_token"])
    r = c.post("/api/v1/gateways/register",
               json={"device_type": "linux", "public_key": ed_b64()})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    gtok = c.post(f"/api/v1/me/gateways/{gid}/claim",
                  json={"pairing_code": code}, headers=h).json()["gateway_token"]
    assert c.post("/api/v1/gateways/heartbeat", json={},
                  headers=headers(gtok)).status_code == 200
    from app.gateway.keypair import generate_wg_keypair
    keys = generate_wg_keypair()
    r = c.post(f"/api/v1/gateways/{gid}/wg-public-key",
               json={"wg_public_key": keys["public_key"]}, headers=headers(gtok))
    assert r.status_code == 200, r.text
    s = c.post("/api/v1/connections", json={"gateway_id": gid}, headers=h).json()
    a = c.post(f"/api/v1/sessions/{s['id']}/authorize-wg", headers=h)
    assert a.status_code == 200, a.text
    return h, gid, s["id"]


def test_device_identity_records_ip_imei_mac():
    tok = reg("fp@example.com", {"imei": "356938035643809",
                                 "mac_address": "aa-bb-cc-dd-ee-ff"})["access_token"]
    h = headers(tok)
    # IMEI/MAC supplied at registration are normalised and stored
    devs = c.get("/api/v1/me/devices", headers=h).json()
    assert devs[0]["imei"] == "356938035643809"
    assert devs[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert devs[0]["ip_address"]  # server-observed

    # bad values are rejected without failing the call; good ones applied
    r = c.post("/api/v1/me/device-identity",
               json={"imei": "not-a-number", "mac_address": "zz:zz",
                     "device_name": "Pixel 8", "user_agent": "ODIVORA/1.0"},
               headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rejected"] == ["imei", "mac_address"]
    assert body["applied"]["device_name"] == "Pixel 8"
    assert body["applied"]["ip_address"]

    r = c.post("/api/v1/me/device-identity",
               json={"imei": "123456789012345", "mac_address": "AA:BB:CC:DD:EE:FF"},
               headers=h)
    assert r.json()["imei"] == "123456789012345"
    assert r.json()["rejected"] == []

    # IMEI rotation is itself audited
    r = c.post("/api/v1/me/device-identity", json={"imei": "999999999999999"}, headers=h)
    assert r.json()["imei"] == "999999999999999"
    audit = c.get("/api/v1/admin/audit?action=device.*", headers=make_admin()).json()
    actions = {i["action"] for i in audit["items"]}
    assert "device.identity_reported" in actions
    assert "device.imei_changed" in actions
    assert all(i["ip"] for i in audit["items"] if i["action"].startswith("device."))


def test_client_ip_taken_from_last_forwarded_hop():
    h = headers(reg("xff@example.com")["access_token"])
    c.post("/api/v1/me/device-identity", json={"device_name": "n1"},
           headers={**h, "X-Forwarded-For": "203.0.113.9, 198.51.100.7"})
    db = TestingSession()
    try:
        from app import models
        dev = db.query(models.UserDevice).join(models.User).filter(
            models.User.email == "xff@example.com").first()
        # last hop = the one appended by our trusted proxy
        assert dev.ip_address == "198.51.100.7"
    finally:
        db.close()


def test_visits_keep_first_ten_only():
    h, gid, sid = setup_tunnel("visitor@example.com")
    sites = [f"site{i}.example.com" for i in range(1, 13)]  # 12 distinct
    sites += ["HTTPS://Site1.example.com/path", "not a host!!", "site1.example.com"]
    r = c.post("/api/v1/me/visits", json={"session_id": sid, "sites": sites}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limit"] == 10
    assert body["total"] == 10
    assert body["stored"] == 10
    assert body["sites"][0] == "site1.example.com"
    reasons = {i["reason"] for i in body["ignored"]}
    assert "limit_reached" in reasons and "duplicate" in reasons and "unusable" in reasons

    # a later report cannot exceed the cap
    r = c.post("/api/v1/me/visits",
               json={"session_id": sid, "sites": ["late.example.com"]}, headers=h)
    assert r.json()["stored"] == 0
    assert r.json()["ignored"][0]["reason"] == "limit_reached"
    assert r.json()["total"] == 10

    # only the owner may report for a session
    other = headers(reg("nosy@example.com")["access_token"])
    assert c.post("/api/v1/me/visits",
                  json={"session_id": sid, "sites": ["x.example.com"]},
                  headers=other).status_code == 403


def test_admin_devices_and_tunnels_listing():
    admin = make_admin("admin2@example.com")
    h, gid, sid = setup_tunnel("owner2@example.com")
    c.post("/api/v1/me/device-identity",
           json={"imei": "356938035643809", "mac_address": "aa:bb:cc:dd:ee:ff"}, headers=h)
    c.post("/api/v1/me/visits", json={"session_id": sid, "sites": ["a.example.com"]},
           headers=h)

    devs = c.get("/api/v1/admin/devices?limit=50", headers=admin).json()
    row = next(d for d in devs["items"] if d["imei"] == "356938035643809")
    assert row["mac_address"] == "AA:BB:CC:DD:EE:FF" and row["ip_address"]
    assert row["email"] == "owner2@example.com"
    # search by identifier
    assert c.get("/api/v1/admin/devices?q=356938035643809",
                 headers=admin).json()["total"] >= 1

    tuns = c.get("/api/v1/admin/tunnels", headers=admin).json()
    t = next(x for x in tuns if x["gateway_id"] == gid)
    assert t["sessions_total"] == 1 and t["devices_total"] == 1
    assert t["sites_recorded"] == 1 and t["owner_email"] == "owner2@example.com"
    assert t["remote_ip"]  # server-observed gateway address


def test_tunnel_audit_json_and_printable_report():
    admin = make_admin("admin3@example.com")
    h, gid, sid = setup_tunnel("owner3@example.com")
    c.post("/api/v1/me/device-identity",
           json={"imei": "123456789012345", "mac_address": "de:ad:be:ef:00:01"},
           headers=h)
    c.post("/api/v1/me/visits",
           json={"session_id": sid,
                 "sites": ["news.example.com", "mail.example.org", "bank.co.ke"]},
           headers=h)

    rep = c.get(f"/api/v1/admin/tunnels/{gid}/audit", headers=admin).json()
    assert rep["report"] == "odivora-tunnel-audit"
    assert rep["tunnel"]["gateway_id"] == gid
    assert rep["tunnel"]["owner"]["email"] == "owner3@example.com"
    # the gateway's own address is server-observed on every heartbeat
    assert rep["tunnel"]["remote_ip"]
    assert rep["summary"]["sessions_total"] == 1
    sess = rep["sessions"][0]
    assert sess["id"] == sid
    assert sess["device"]["ip"] and sess["device"]["imei"] == "123456789012345"
    assert sess["device"]["mac"] == "DE:AD:BE:EF:00:01"
    assert [v["host"] for v in sess["visits"]] == ["news.example.com",
                                                   "mail.example.org", "bank.co.ke"]
    assert any(a["action"] == "tunnel.visits_reported" and a["ip"] for a in rep["audit"])
    assert any(a["action"] == "tunnel_authorized" for a in rep["audit"])

    # printable document
    r = c.get(f"/api/v1/admin/tunnels/{gid}/audit/print", headers=admin)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    page = r.text
    assert "Print this report" in page and "@media print" in page
    assert "123456789012345" in page and "DE:AD:BE:EF:00:01" in page
    assert "news.example.com" in page and "bank.co.ke" in page
    assert "self-reported by the mobile client" in page

    # per-session (single peer) report
    r = c.get(f"/api/v1/admin/sessions/{sid}/audit/print", headers=admin)
    assert r.status_code == 200
    assert "Tunnel session audit" in r.text and "news.example.com" in r.text

    # narrow the tunnel report to one session
    one = c.get(f"/api/v1/admin/tunnels/{gid}/audit?session_id={sid}",
                headers=admin).json()
    assert len(one["sessions"]) == 1
    assert c.get(f"/api/v1/admin/tunnels/{gid}/audit?session_id=00000000-0000-0000-0000-"
                 f"000000000000", headers=admin).status_code == 404

    # admin only
    plain = headers(reg("plain3@example.com")["access_token"])
    assert c.get(f"/api/v1/admin/tunnels/{gid}/audit", headers=plain).status_code == 403
    assert c.get(f"/api/v1/admin/tunnels/{gid}/audit/print",
                 headers=plain).status_code == 403
    assert c.get("/api/v1/admin/devices", headers=plain).status_code == 403


def test_audit_endpoint_filters():
    admin = make_admin("admin4@example.com")
    h, gid, sid = setup_tunnel("owner4@example.com")
    c.post("/api/v1/me/visits", json={"session_id": sid, "sites": ["z.example.com"]},
           headers=h)

    by_action = c.get("/api/v1/admin/audit?action=tunnel.*", headers=admin).json()
    assert by_action["total"] >= 1
    assert all(i["action"].startswith("tunnel.") for i in by_action["items"])

    by_resource = c.get(f"/api/v1/admin/audit?resource_id={sid}", headers=admin).json()
    assert by_resource["total"] >= 1
    assert all(i["resource"] == sid for i in by_resource["items"])

    ip = by_action["items"][0]["ip"]
    assert ip
    by_ip = c.get(f"/api/v1/admin/audit?ip={ip}", headers=admin).json()
    assert by_ip["total"] >= 1
    assert all(i["ip"] == ip for i in by_ip["items"])

    assert c.get("/api/v1/admin/audit?action=does.not.exist",
                 headers=admin).json()["total"] == 0


def test_admin_ui_exposes_audit_tabs():
    page = c.get("/admin")
    assert page.status_code == 200
    html = page.text
    for tab in ("data-t=\"tunnels\"", "data-t=\"devices\"", "data-t=\"audit\""):
        assert tab in html
    assert "printTunnel" in html and "/audit/print" in html
    # filters the UI sends to /admin/audit
    assert "au-action" in html and "au-ip" in html
