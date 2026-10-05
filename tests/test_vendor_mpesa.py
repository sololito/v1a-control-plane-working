"""Vendor M-Pesa wiring tests. No network: vendor service is faked.

Covers: initiate mapping + rejection, callback state mapping
(completed/cancelled/timeout/bad-shape), strict phone fallback,
live provider selection.
"""
import pytest

from app import billing as billing_mod
from app import mpesa_adapter as ad


class FakeVendor:
    callback_url = "https://example.test/callback"

    def __init__(self, stk_response=None):
        self._stk = stk_response or {
            "ResponseCode": "0",
            "CheckoutRequestID": "ws_CO_test123",
            "MerchantRequestID": "m_test",
        }

    def initiate_stk_push(self, phone, amount, account_reference=None, description=None):
        assert phone == "254712345678"
        return dict(self._stk)

    def validate_callback_data(self, payload):
        cb = (payload.get("Body") or {}).get("stkCallback", {})
        return "CheckoutRequestID" in cb and "ResultCode" in cb

    def get_payment_state(self, code, desc):
        return {
            "0": ("completed", "Payment completed successfully"),
            "1032": ("cancelled", "Payment cancelled by user"),
            "1037": ("timeout", "Payment request timed out. Please try again."),
            "2001": ("rejected", "Payment was rejected; please verify your PIN and try again"),
        }.get(str(code).strip(), ("failed", desc or "Payment failed"))


def _cb(code, receipt="ABC123"):
    items = [{"Name": "MpesaReceiptNumber", "Value": receipt},
             {"Name": "Amount", "Value": 500},
             {"Name": "PhoneNumber", "Value": 254712345678}]
    cb = {"MerchantRequestID": "m1", "CheckoutRequestID": "ws_CO_x",
          "ResultCode": code, "ResultDesc": f"rc {code}"}
    if str(code) == "0":
        cb["CallbackMetadata"] = {"Item": items}
    return {"Body": {"stkCallback": cb}}


def test_initiate_maps_vendor_response(monkeypatch):
    monkeypatch.setattr(ad, "_vendor_service", lambda: FakeVendor())
    p = ad.VendorMpesaProvider()
    res = p.initiate("u1", "personal", "254712345678", 500)
    assert res.checkout_request_id == "ws_CO_test123"
    assert "approve on phone" in res.message


def test_initiate_rejection_raises(monkeypatch):
    fake = FakeVendor({"ResponseCode": "2001", "ResponseDesc": "rejected"})
    monkeypatch.setattr(ad, "_vendor_service", lambda: fake)
    with pytest.raises(RuntimeError, match="STK rejected"):
        ad.VendorMpesaProvider().initiate("u1", "personal", "254712345678", 500)


def test_initiate_no_response_raises(monkeypatch):
    class Silent(FakeVendor):
        def initiate_stk_push(self, *a, **k):
            return None
    monkeypatch.setattr(ad, "_vendor_service", lambda: Silent())
    with pytest.raises(RuntimeError, match="no response"):
        ad.VendorMpesaProvider().initiate("u1", "personal", "254712345678", 500)


def test_callback_state_mapping(monkeypatch):
    monkeypatch.setattr(ad, "_vendor_service", FakeVendor)
    p = ad.VendorMpesaProvider()
    ok = p.parse_callback(_cb("0"))
    assert (ok["tx_status"], ok["result_code"], ok["receipt"]) == ("success", 0, "ABC123")
    assert ok["mpesa_state"] == "completed"
    cancel = p.parse_callback(_cb("1032"))
    assert (cancel["tx_status"], cancel["result_code"], cancel["receipt"]) == ("cancelled", 1032, None)
    timeout = p.parse_callback(_cb("1037"))
    assert (timeout["tx_status"], timeout["mpesa_state"]) == ("failed", "timeout")
    rejected = p.parse_callback(_cb("2001"))
    assert (rejected["tx_status"], rejected["mpesa_state"]) == ("failed", "rejected")
    with pytest.raises(ValueError):
        p.parse_callback({"junk": True})


def test_strict_phone_fallback():
    assert ad.validate_phone_for_mpesa("0712345678") == "254712345678"
    assert ad.validate_phone_for_mpesa("+254712345678") == "254712345678"
    with pytest.raises(ValueError):
        ad.validate_phone_for_mpesa("123")


def test_live_selects_vendor(monkeypatch):
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "billing_live", True)
    assert isinstance(billing_mod.get_payment_provider(), ad.VendorMpesaProvider)
    monkeypatch.setattr(settings, "billing_live", False)
    assert isinstance(billing_mod.get_payment_provider(), billing_mod.MpesaDarajaStub)
