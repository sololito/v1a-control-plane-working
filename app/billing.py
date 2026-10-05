"""Billing abstraction. M-Pesa Daraja (Safaricom Kenya) is the chosen provider.

Modes:
  BILLING_LIVE=false (default, V1): MpesaDarajaStub — no network, no charge,
    callbacks record receipt but NEVER flip entitlements.
  BILLING_LIVE=true (after sandbox creds + public callback URL): MpesaDarajaLive —
    OAuth + STK-push, callback success activates Subscription.

Design preserved: User -> Subscription -> entitlements
                  User -> PaymentTransaction -> Subscription (on live success)
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any
import base64
import re


PROVIDER_MPESA_DARAJA = "mpesa-daraja"

PLANS: Dict[str, Dict[str, Any]] = {
    "free": {"plan": "free", "price": 0, "currency": "KES",
             "entitlements": {"max_gateways": 2, "max_sessions": 1}},
    "personal": {"plan": "personal", "price": 500, "currency": "KES",
                 "entitlements": {"max_gateways": 3, "max_sessions": 2}},
    "premium": {"plan": "premium", "price": 1000, "currency": "KES",
                "entitlements": {"max_gateways": 5, "max_sessions": 5}},
    "monthly": {"plan": "monthly", "price": 500, "currency": "KES",
                "entitlements": {"max_gateways": 3, "max_sessions": 2}},
    "annual": {"plan": "annual", "price": 5000, "currency": "KES",
               "entitlements": {"max_gateways": 5, "max_sessions": 5}},
}


def normalize_msisdn(phone: str) -> str:
    p = re.sub(r"[\s\-()]", "", (phone or "").strip())
    if p.startswith("+"):
        p = p[1:]
    if re.fullmatch(r"0\d{9}", p):
        return "254" + p[1:]
    if re.fullmatch(r"254\d{9}", p):
        return p
    raise ValueError("phone must be 07XXXXXXXX or 2547XXXXXXXX")


def daraja_base(env: str) -> str:
    return "https://sandbox.safaricom.co.ke" if env != "production" \
        else "https://api.safaricom.co.ke"


def daraja_password(shortcode: str, passkey: str, timestamp: str) -> str:
    raw = f"{shortcode}{passkey}{timestamp}"
    return base64.b64encode(raw.encode()).decode()


def daraja_timestamp(now: datetime | None = None) -> str:
    return (now or datetime.utcnow()).strftime("%Y%m%d%H%M%S")


@dataclass
class InitiateResult:
    checkout_request_id: str
    merchant_request_id: str
    message: str


class PaymentProvider(ABC):
    provider_name: str = "abstract"

    @abstractmethod
    def initiate(self, user_id: str, plan: str, msisdn: str, amount: int) -> InitiateResult:
        raise NotImplementedError

    @abstractmethod
    def parse_callback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class MpesaDarajaStub(PaymentProvider):
    provider_name = PROVIDER_MPESA_DARAJA

    def initiate(self, user_id: str, plan: str, msisdn: str, amount: int) -> InitiateResult:
        import uuid
        return InitiateResult(
            checkout_request_id=f"ws_CO_{uuid.uuid4().hex[:12]}",
            merchant_request_id=f"stub-{uuid.uuid4().hex[:8]}",
            message="STK push stub — no charge sent (BILLING_LIVE=false)")

    def parse_callback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            cb = payload["Body"]["stkCallback"]
        except KeyError:
            raise ValueError("invalid Daraja callback shape")
        items = {i.get("Name"): i.get("Value") for i in
                 cb.get("CallbackMetadata", {}).get("Item", [])}
        return {
            "checkout_request_id": cb.get("CheckoutRequestID", ""),
            "merchant_request_id": cb.get("MerchantRequestID", ""),
            "result_code": int(cb.get("ResultCode", -1)),
            "result_desc": cb.get("ResultDesc", ""),
            "receipt": items.get("MpesaReceiptNumber"),
            "amount": items.get("Amount"),
            "phone": items.get("PhoneNumber"),
            "raw": payload,
        }


class MpesaDarajaLive(PaymentProvider):
    """Live Daraja: OAuth (consumer key/secret) + STK-push. Network calls here only."""
    provider_name = PROVIDER_MPESA_DARAJA

    def __init__(self, env: str, consumer_key: str, consumer_secret: str,
                 shortcode: str, passkey: str, callback_url: str):
        import httpx
        self.env = env
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.shortcode = shortcode
        self.passkey = passkey
        self.callback_url = callback_url
        self._httpx = httpx

    def _token(self) -> str:
        base = daraja_base(self.env)
        r = self._httpx.get(
            f"{base}/oauth/v1/generate?grant_type=client_credentials",
            auth=(self.consumer_key, self.consumer_secret), timeout=15)
        r.raise_for_status()
        return r.json()["access_token"]

    def initiate(self, user_id: str, plan: str, msisdn: str, amount: int) -> InitiateResult:
        from app.config import get_settings
        s = get_settings()
        ts = daraja_timestamp()
        pw = daraja_password(self.shortcode, self.passkey, ts)
        token = self._token()
        body = {
            "BusinessShortCode": self.shortcode,
            "Password": pw,
            "Timestamp": ts,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": msisdn,
            "PartyB": self.shortcode,
            "PhoneNumber": msisdn,
            "CallBackURL": self.callback_url,
            "AccountReference": getattr(s, "mpesa_account_ref", "ODIVORA"),
            "TransactionDesc": f"{getattr(s, 'mpesa_transaction_desc', 'ODIVORA plan')} {plan}",
        }
        r = self._httpx.post(f"{daraja_base(self.env)}/mpesa/stkpush/v1/processrequest",
                             json=body,
                             headers={"Authorization": f"Bearer {token}"}, timeout=20)
        r.raise_for_status()
        data = r.json()
        if data.get("ResponseCode") not in (None, "0", 0):
            raise RuntimeError(f"STK rejected: {data}")
        return InitiateResult(
            checkout_request_id=data.get("CheckoutRequestID", ""),
            merchant_request_id=data.get("MerchantRequestID", ""),
            message="STK push sent — approve on phone")

    parse_callback = MpesaDarajaStub.parse_callback


def get_payment_provider() -> PaymentProvider:
    from app.config import get_settings
    s = get_settings()
    if s.billing_live:
        # Prefer your working vendor script; fall back to built-in httpx live client.
        try:
            from app.mpesa_adapter import VendorMpesaProvider
            from scripts.mpesa_service import MpesaService  # noqa: F401 (presence check)
            return VendorMpesaProvider()
        except (ImportError, RuntimeError):
            pass
        missing = [k for k in ("mpesa_consumer_key", "mpesa_consumer_secret",
                               "mpesa_shortcode", "mpesa_passkey", "mpesa_callback_url")
                   if not getattr(s, k, "")]
        if missing:
            raise RuntimeError(f"BILLING_LIVE=true but missing: {', '.join(missing)}")
        return MpesaDarajaLive(s.mpesa_env, s.mpesa_consumer_key, s.mpesa_consumer_secret,
                               s.mpesa_shortcode, s.mpesa_passkey, s.mpesa_callback_url)
    return MpesaDarajaStub()


def activate_subscription_for_transaction(db, tx) -> None:
    """Create/upgrade Subscription from a successful live transaction. Stub mode never calls this."""
    import json
    from app import models
    spec = PLANS.get(tx.plan, PLANS["personal"])
    sub = models.Subscription(user_id=tx.user_id, plan=tx.plan, status="active",
                              entitlements=json.dumps(spec["entitlements"]))
    db.add(sub)
    db.flush()
    tx.subscription_id = sub.id
