"""Billing stubs: plans visible, initiate validates, callback idempotent, V1 free intact."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_billing.db"
try:
    if os.path.exists("./test_billing.db"):
        os.remove("./test_billing.db")
except PermissionError:
    pass

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_billing.db", connect_args={"check_same_thread": False})
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


def test_plans_and_free_untouched():
    r = c.get("/api/v1/billing/plans")
    assert r.status_code == 200 and any(p["plan"] == "personal" for p in r.json())
    reg = c.post("/api/v1/auth/register",
                 json={"email": "bill@example.com", "password": "Password123!"})
    assert reg.status_code == 200
    h = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    sub = c.get("/api/v1/me/subscription", headers=h).json()
    assert sub["plan"] == "free"


def test_initiate_validates_and_callback_idempotent():
    reg = c.post("/api/v1/auth/register",
                 json={"email": "mpesa@example.com", "password": "Password123!"})
    h = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    bad = c.post("/api/v1/me/billing/mpesa/initiate",
                 json={"plan": "personal", "phone": "123"}, headers=h)
    assert bad.status_code == 422
    ok = c.post("/api/v1/me/billing/mpesa/initiate",
                json={"plan": "personal", "phone": "0712345678"}, headers=h)
    assert ok.status_code == 200 and ok.json()["live"] is False
    cid = ok.json()["checkout_request_id"]
    payload = {"Body": {"stkCallback": {
        "MerchantRequestID": "m1", "CheckoutRequestID": cid,
        "ResultCode": 0, "ResultDesc": "success",
        "CallbackMetadata": {"Item": [
            {"Name": "MpesaReceiptNumber", "Value": "ABC123"},
            {"Name": "Amount", "Value": 500},
            {"Name": "PhoneNumber", "Value": 254712345678}]}}}}
    cb1 = c.post("/api/v1/billing/mpesa/callback", json=payload)
    assert cb1.json()["ResultCode"] == 0
    cb2 = c.post("/api/v1/billing/mpesa/callback", json=payload)
    assert cb2.json()["ResultDesc"] == "duplicate ignored"
    # stub mode: subscription stays free
    sub = c.get("/api/v1/me/subscription", headers=h).json()
    assert sub["plan"] == "free"
    badshape = c.post("/api/v1/billing/mpesa/callback", json={"x": 1})
    assert badshape.status_code == 422


def test_daraja_helpers_and_live_activation_unit():
    import base64
    from datetime import datetime
    from app.billing import daraja_password, daraja_timestamp, normalize_msisdn, \
        activate_subscription_for_transaction, PLANS
    from app import models
    assert normalize_msisdn("0712345678") == "254712345678"
    assert normalize_msisdn("+254712345678") == "254712345678"
    ts = daraja_timestamp(datetime(2024, 1, 1, 12, 0, 0))
    assert ts == "20240101120000"
    pw = daraja_password("174379", "pass", ts)
    assert base64.b64decode(pw).decode() == "174379pass20240101120000"
    db = TestingSession()
    u = models.User(email="live@example.com", password_hash="x")
    db.add(u)
    db.flush()
    tx = models.PaymentTransaction(user_id=u.id, provider="mpesa-daraja",
                                   plan="personal", amount=500, currency="KES",
                                   phone_msisdn="254712345678", status="success")
    db.add(tx)
    db.flush()
    activate_subscription_for_transaction(db, tx)
    db.commit()
    assert tx.subscription_id is not None
    sub = db.query(models.Subscription).filter(
        models.Subscription.id == tx.subscription_id).first()
    assert sub.plan == "personal"
    assert sub.entitlements is not None
    db.close()
