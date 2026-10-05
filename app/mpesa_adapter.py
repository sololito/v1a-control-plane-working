"""Adapter: vendor `scripts/mpesa_service.py` (MpesaService) -> app PaymentProvider.

Why an adapter instead of editing the vendor file:
  - The vendor script is your tested, working Daraja code — it stays untouched.
  - Env names differ (MPESA_ENV vs MPESA_ENVIRONMENT, MPESA_ACCOUNT_REF vs
    MPESA_ACCOUNT_REFERENCE, URL trio). The bridge maps ours -> theirs without
    overwriting anything you explicitly set.
  - MpesaService() raises RuntimeError when unconfigured; the adapter converts
    that (and Flask-legacy edges) into clear errors at request time, never at import.

Vendor result states (completed/cancelled/timeout/rejected/failed) are mapped to
our PaymentTransaction statuses (pending/success/failed/cancelled):
  completed -> success | cancelled -> cancelled | timeout/rejected/failed -> failed
The original numeric ResultCode is always preserved for audit.
"""
import os
from contextlib import contextmanager
from typing import Any, Dict

from app.billing import (
    PROVIDER_MPESA_DARAJA,
    InitiateResult,
    PaymentProvider,
    normalize_msisdn,
)

_DARAJA_URLS = {
    "sandbox": {
        "MPESA_AUTH_URL": "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        "MPESA_STK_PUSH_URL": "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        "MPESA_QUERY_URL": "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query",
    },
    "production": {
        "MPESA_AUTH_URL": "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        "MPESA_STK_PUSH_URL": "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        "MPESA_QUERY_URL": "https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query",
    },
}

# vendor state -> (our tx status, fallback numeric code when Daraja gives none)
_STATE_MAP = {
    "completed": ("success", 0),
    "cancelled": ("cancelled", 1032),
    "timeout": ("failed", 1037),
    "rejected": ("failed", 2001),
    "failed": ("failed", 1),
}


@contextmanager
def _bridge_env():
    """Map our env names to the vendor's expected names (setdefault only)."""
    env = os.getenv("MPESA_ENV", os.getenv("MPESA_ENVIRONMENT", "sandbox")).lower()
    if env not in ("sandbox", "production"):
        env = "sandbox"
    bridge = {
        "MPESA_ENVIRONMENT": env,
        "MPESA_ACCOUNT_REFERENCE": os.getenv(
            "MPESA_ACCOUNT_REFERENCE", os.getenv("MPESA_ACCOUNT_REF", "ODIVORA")),
        "MPESA_TRANSACTION_DESC": os.getenv("MPESA_TRANSACTION_DESC", "ODIVORA plan"),
    }
    bridge.update({k: v for k, v in _DARAJA_URLS[env].items() if not os.getenv(k)})
    if not os.getenv("MPESA_CALLBACK_URL"):
        # Our settings name for the same value; vendor reads MPESA_CALLBACK_URL.
        from app.config import get_settings
        cb = (get_settings().mpesa_callback_url or "").strip()
        if cb:
            bridge["MPESA_CALLBACK_URL"] = cb
    saved = {k: os.environ.get(k) for k in bridge}
    os.environ.update({k: v for k, v in bridge.items() if v})
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _vendor_service():
    """Instantiate vendor MpesaService with bridged env (lazy: no import-time crash)."""
    try:
        from scripts.mpesa_service import MpesaService
    except ImportError as e:
        raise RuntimeError(f"vendor mpesa script unavailable: {e}")
    with _bridge_env():
        try:
            return MpesaService()
        except RuntimeError as e:
            raise RuntimeError(f"M-PESA not configured: {e}")


def validate_phone_for_mpesa(phone: str) -> str:
    """Strict Kenyan validation via vendor; falls back to normalize_msisdn."""
    try:
        from scripts.mpesa_service import MpesaService
        with _bridge_env():
            try:
                svc = MpesaService()
            except RuntimeError:
                svc = None
        if svc is not None:
            out = svc.validate_phone_number(phone)
            if out:
                return out
            raise ValueError("phone must be a valid Kenyan M-PESA number (07XXXXXXXX)")
    except ImportError:
        pass
    return normalize_msisdn(phone)


def validate_callback_origin(client_ip: str) -> bool:
    """Daraja IP allowlist via vendor (empty allowlist in prod = skip, per vendor).

    Unconfigured vendor (stub/dev mode) -> True: there is no allowlist to
    enforce against, and stub callbacks must keep working without creds.
    """
    try:
        svc = _vendor_service()
    except RuntimeError:
        return True
    return svc.validate_callback_origin(client_ip or "")


class VendorMpesaProvider(PaymentProvider):
    """Live provider delegating OAuth/STK/query to scripts/mpesa_service.MpesaService."""
    provider_name = PROVIDER_MPESA_DARAJA

    def initiate(self, user_id: str, plan: str, msisdn: str, amount: int) -> InitiateResult:
        svc = _vendor_service()
        if not svc.callback_url:
            # Vendor would hit a Flask-only fallback (ImportError) here; fail clearly instead.
            raise RuntimeError("MPESA_CALLBACK_URL is not set")
        res = svc.initiate_stk_push(msisdn, amount,
                                    account_reference=f"ODIVORA {plan}",
                                    description=f"ODIVORA {plan}")
        if not res:
            raise RuntimeError("STK push failed (no response from Daraja)")
        if str(res.get("ResponseCode")) != "0":
            raise RuntimeError(f"STK rejected: {res.get('ResponseDesc') or res}")
        cid = res.get("CheckoutRequestID", "")
        if not cid:
            raise RuntimeError(f"STK response missing CheckoutRequestID: {res}")
        return InitiateResult(checkout_request_id=cid,
                              merchant_request_id=res.get("MerchantRequestID", ""),
                              message="STK push sent — approve on phone")

    def parse_callback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        svc = _vendor_service()
        if not svc.validate_callback_data(payload):
            raise ValueError("invalid Daraja callback shape")
        cb = payload["Body"]["stkCallback"]
        code = cb.get("ResultCode", -1)
        try:
            code_int = int(code)
        except (TypeError, ValueError):
            code_int = -1
        state, message = svc.get_payment_state(str(code), cb.get("ResultDesc", ""))
        items = {i.get("Name"): i.get("Value") for i in
                 cb.get("CallbackMetadata", {}).get("Item", [])}
        receipt = items.get("MpesaReceiptNumber")
        if state != "completed":
            receipt = None
        tx_status, fallback = _STATE_MAP.get(state, ("failed", 1))
        return {
            "checkout_request_id": cb.get("CheckoutRequestID", ""),
            "merchant_request_id": cb.get("MerchantRequestID", ""),
            "result_code": code_int if code_int >= 0 else fallback,
            "result_desc": cb.get("ResultDesc", "") or message,
            "receipt": receipt,
            "amount": items.get("Amount"),
            "phone": items.get("PhoneNumber"),
            "mpesa_state": state,      # completed|cancelled|timeout|rejected|failed
            "tx_status": tx_status,    # success|cancelled|failed (our PaymentTransaction values)
            "raw": payload,
        }
