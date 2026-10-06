"""Auth plumbing and on-device key handling.

Two halves, joined by "payment can only be taken where the identity holds up":

  * `app.deps` + `app.authz` — the boundary that decides who is allowed to do
    what. The happy paths are covered elsewhere; these tests pin the *refusal*
    paths that otherwise only fire when something is already going wrong: a
    gateway token presented to a user endpoint, a malformed subject that used
    to explode into a 500, an inactive user, a revoked gateway, a revoked
    grant, and a subscription the user should not have.
  * `app.gateway.keypair` + `app.gateway_crypto` — the device-side half of key
    management. The private key must be written owner-only, read back exactly,
    fail loudly-but-softly when the directory is unwritable, and never be
    derived identically for two devices (reuse/crossover). The Ed25519 checks
    must reject every wrong thing a tampering gateway can present.

Because the module borrows the shared `get_db` override the same way the other
HTTP suites do, it restores whatever override was in place before each test so
later files are not accidentally pointed at this module's database.
"""
import base64
import os
from datetime import datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite:///./test_authz.db"
try:
    if os.path.exists("./test_authz.db"):
        os.remove("./test_authz.db")
except PermissionError:
    pass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_authz.db", connect_args={"check_same_thread": False})
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
def _claim_get_db_and_clear_limits():
    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()
    auth_router._fails.clear()
    if previous is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = previous


def reg(email="access@example.com", pw="Password123!"):
    r = c.post("/api/v1/auth/register", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()


def registered_gateway(email="gw@example.com"):
    """Register + claim a gateway, return (user_token, gateway_token, gateway_id)."""
    t = reg(email)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    r = c.post("/api/v1/gateways/register",
               json={"device_type": "linux", "public_key": "dev-key-000000000000001"})
    assert r.status_code == 200, r.text
    gid, code = r.json()["gateway_id"], r.json()["pairing_code"]
    claimed = c.post(f"/api/v1/me/gateways/{gid}/claim", json={"pairing_code": code}, headers=h)
    assert claimed.status_code == 200, claimed.text
    return h, {"Authorization": f"Bearer {claimed.json()['gateway_token']}"}, gid


# ------------------------------------------------------------------- deps ----

def test_missing_or_wrong_bearer_scheme_is_a_clean_401():
    assert c.get("/api/v1/me").status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Basic dXNlcjpwYXNz"}).status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Bearer "}).status_code == 401


def test_a_gateway_token_cannot_act_as_a_user():
    _, gh, _ = registered_gateway("wrongkind1@example.com")
    r = c.get("/api/v1/me", headers=gh)
    assert r.status_code == 401
    assert "wrong token kind" in r.json()["detail"]


def test_a_user_token_cannot_drive_the_gateway_api():
    h, _, _ = registered_gateway("wrongkind2@example.com")
    r = c.post("/api/v1/gateways/heartbeat", headers=h, json={"nonce": "1"})
    assert r.status_code == 401
    assert "wrong token kind" in r.json()["detail"]


def test_a_malformed_token_subject_is_401_not_500():
    """Regression: a token minted against a torn-down user used to 500 in UUID().."""
    from app.security import _encode

    junk = _encode({"sub": "not-a-uuid", "device_id": "not-a-uuid"},
                   timedelta(minutes=5), "access")
    r = c.get("/api/v1/me", headers={"Authorization": f"Bearer {junk}"})
    assert r.status_code == 401
    assert "malformed token" in r.json()["detail"]


def test_an_expired_token_gets_its_own_401():
    from app.security import _encode

    stale = _encode({"sub": "00000000-0000-0000-0000-000000000000",
                     "device_id": "00000000-0000-0000-0000-000000000001"},
                    timedelta(seconds=-1), "access")
    r = c.get("/api/v1/me", headers={"Authorization": f"Bearer {stale}"})
    assert r.status_code == 401
    assert "token expired" in r.json()["detail"]


def test_an_inactive_user_is_stopped_even_with_a_valid_token():
    t = reg("inactive@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert c.get("/api/v1/me", headers=h).status_code == 200

    db = TestingSession()
    user = db.query(models.User).filter(models.User.email == "inactive@example.com").one()
    user.is_active = False
    db.commit()
    db.close()

    assert c.get("/api/v1/me", headers=h).status_code == 401


def test_a_revoked_gateway_loses_its_token():
    _, gh, gid = registered_gateway("revoked-gw@example.com")
    db = TestingSession()
    gw = db.query(models.Gateway).filter(models.Gateway.id == gid).one()
    gw.status = "revoked"
    db.commit()
    db.close()
    assert c.post("/api/v1/gateways/heartbeat", headers=gh,
                  json={"nonce": "1"}).status_code == 401


def test_admin_routes_gate_plain_users(monkeypatch):
    t = reg("plain@example.com")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert c.get("/api/v1/admin/gateways", headers=h).status_code == 403

    db = TestingSession()
    user = db.query(models.User).filter(models.User.email == "plain@example.com").one()
    user.is_admin = True
    db.commit()
    db.close()

    assert c.get("/api/v1/admin/gateways", headers=h).status_code == 200


# ------------------------------------------------------------------ authz ----

def _user_in_db(email="p@example.com", active=True):
    db = TestingSession()
    user = models.User(email=email, password_hash="x", is_active=active)
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


def test_a_gateway_that_is_revoked_or_unregistered_is_unreachable():
    from fastapi import HTTPException
    from app.authz import can_access_gateway

    owner = _user_in_db("rev@example.com")
    db = TestingSession()
    for status in ("revoked", "unregistered"):
        gw = models.Gateway(owner_user_id=owner.id, device_type="linux", status=status)
        db.add(gw)
    db.commit()

    for gw in db.query(models.Gateway).all():
        with pytest.raises(HTTPException) as e:
            can_access_gateway(db, owner.id, gw)
        assert e.value.status_code == 403
    db.close()


def test_a_revoked_grant_confers_no_access():
    from fastapi import HTTPException
    from app.authz import can_access_gateway

    owner = _user_in_db("owner@example.com")
    friend = _user_in_db("friend@example.com")
    db = TestingSession()
    gw = models.Gateway(owner_user_id=owner.id, device_type="linux", status="online")
    db.add(gw)
    db.flush()  # populate gw.id before the grant references it
    db.add(models.GatewayGrant(gateway_id=gw.id, grantee_user_id=friend.id,
                               access_type="PARTNER_GATEWAY", revoked=True))  # revoked
    db.commit()

    with pytest.raises(HTTPException) as e:
        can_access_gateway(db, friend.id, gw, access_type="PARTNER_GATEWAY")
    assert e.value.status_code == 403
    db.close()


def test_an_unknown_access_type_is_refused_even_for_the_owner():
    from fastapi import HTTPException
    from app.authz import can_access_gateway

    owner = _user_in_db("futurist@example.com")
    db = TestingSession()
    gw = models.Gateway(owner_user_id=owner.id, device_type="linux", status="online")
    db.add(gw)
    db.commit()

    with pytest.raises(HTTPException) as e:
        can_access_gateway(db, owner.id, gw, access_type="ALIEN_TELEPATHY")
    assert e.value.status_code == 403
    db.close()


def test_entitlement_requires_the_latest_subscription_to_be_active():
    from fastapi import HTTPException
    from app.authz import check_subscription_entitlement

    user = _user_in_db("sub@example.com")
    db = TestingSession()
    with pytest.raises(HTTPException) as e:
        check_subscription_entitlement(db, user.id)     # no subscription at all
    assert e.value.status_code == 403

    # A stale (inactive) newer subscription must not grant access either.
    db.add(models.Subscription(user_id=user.id, plan="personal", status="cancelled"))
    db.commit()
    with pytest.raises(HTTPException) as e:
        check_subscription_entitlement(db, user.id)
    assert e.value.status_code == 403

    db.add(models.Subscription(user_id=user.id, plan="personal", status="active"))
    db.commit()
    sub = check_subscription_entitlement(db, user.id)
    assert sub.status == "active"
    db.close()


# ------------------------------------------------- keypair local storage ----

def test_private_key_is_written_owner_only_and_reads_back_exactly(tmp_path):
    from app.gateway.keypair import (
        store_wg_private_key_locally,
        read_wg_private_key_from_local_storage,
        is_wg_keypair_generated,
    )

    target = str(tmp_path / "keys" / "wg_private_key")
    key = base64.b64encode(os.urandom(32)).decode()

    assert store_wg_private_key_locally(key, path=target) is True
    assert read_wg_private_key_from_local_storage(target) == key
    assert is_wg_keypair_generated(target) is True

    mode = os.stat(target).st_mode
    dir_mode = os.stat(os.path.dirname(target)).st_mode
    assert (mode & 0o777) == 0o600, f"key file must be owner-only, got {oct(mode)}"
    assert (dir_mode & 0o777) == 0o700, f"key dir must be owner-only, got {oct(dir_mode)}"


def test_absent_and_empty_key_files_read_as_absent(tmp_path):
    from app.gateway.keypair import (
        read_wg_private_key_from_local_storage,
        is_wg_keypair_generated,
    )

    missing = str(tmp_path / "nope")
    assert read_wg_private_key_from_local_storage(missing) is None
    assert is_wg_keypair_generated(missing) is False

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "key").touch()
    assert read_wg_private_key_from_local_storage(str(empty / "key")) is None
    assert is_wg_keypair_generated(str(empty / "key")) is False


def test_an_unwritable_private_key_path_returns_false_not_an_exception(tmp_path):
    from app.gateway.keypair import store_wg_private_key_locally

    # /proc is not creatable, even by root; making the failure deterministic
    # regardless of the uid the tests run under would need a read-only bind of
    # a real directory, which /proc gives us for free.
    assert store_wg_private_key_locally("AAAA", path="/proc/odivora/wg_key") is False


def test_two_devices_never_reuse_or_cross_substitute_a_keypair(tmp_path):
    """Each device generates under its own directory and owns its own key."""
    from app.gateway.keypair import (
        generate_wg_keypair,
        get_wg_public_key_from_private,
        store_wg_private_key_locally,
        is_wg_keypair_generated,
    )

    dev_a = str(tmp_path / "dev_a" / "wg_private_key")
    dev_b = str(tmp_path / "dev_b" / "wg_private_key")

    ka, kb = generate_wg_keypair(), generate_wg_keypair()
    store_wg_private_key_locally(ka["private_key"], path=dev_a)
    store_wg_private_key_locally(kb["private_key"], path=dev_b)

    assert is_wg_keypair_generated(dev_a)
    assert is_wg_keypair_generated(dev_b)
    # Distinct private keys, distinct published public keys, and each device's
    # public key derives from its own private material — not the other's.
    assert ka["private_key"] != kb["private_key"]
    assert ka["public_key"] != kb["public_key"]
    assert get_wg_public_key_from_private(ka["private_key"]) == ka["public_key"]
    assert get_wg_public_key_from_private(kb["private_key"]) == kb["public_key"]
    assert ka["public_key"] != kb["public_key"]


# ------------------------------------------------------- gateway_crypto ----

def _ed25519_pair(pem=False):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    if pem:
        pub = priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        pub = base64.b64encode(priv.public_key().public_bytes_raw())
    return priv, pub.decode()


def test_signature_check_rejects_wrong_key_nonce_signature_and_junk():
    from app.gateway_crypto import verify_signature

    priv, pub = _ed25519_pair()
    other_priv, other_pub = _ed25519_pair()
    sig = base64.b64encode(priv.sign(b"nonce-value")).decode()

    assert verify_signature(pub, "nonce-value", sig) is True
    # The adversary signs with a different key.
    other_sig = base64.b64encode(other_priv.sign(b"nonce-value")).decode()
    assert verify_signature(pub, "nonce-value", other_sig) is False
    # Same key, wrong nonce.
    assert verify_signature(pub, "tampered-nonce", sig) is False
    # Not even base64.
    assert verify_signature(pub, "nonce-value", "!!!not base64!!!") is False
    # A dev/opaque public key has no crypto and is never accepted as verified.
    assert verify_signature("dev-gateway-key-1234", "nonce-value", sig) is False


def test_signature_check_accepts_a_pem_encoded_public_key():
    from app.gateway_crypto import verify_signature

    priv, pub_pem = _ed25519_pair(pem=True)
    assert "BEGIN PUBLIC KEY" in pub_pem
    sig = base64.b64encode(priv.sign(b"nonce-value")).decode()
    assert verify_signature(pub_pem, "nonce-value", sig) is True


def test_nonce_expiry_is_the_configured_ttl_ahead():
    from app.gateway_crypto import NONCE_TTL_MIN, nonce_expiry

    delta = nonce_expiry() - datetime.utcnow()
    assert timedelta(minutes=NONCE_TTL_MIN - 1) < delta <= timedelta(minutes=NONCE_TTL_MIN)