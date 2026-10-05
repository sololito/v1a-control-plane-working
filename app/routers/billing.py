"""Billing: plans, M-Pesa initiate, Daraja callback (idempotent).

BILLING_LIVE=false: stub only, never flips entitlements.
BILLING_LIVE=true:  live STK-push + callback success activates Subscription.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.billing import PLANS, PROVIDER_MPESA_DARAJA, activate_subscription_for_transaction, get_payment_provider, normalize_msisdn
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_user_device
from app.ratelimit import check_rate, client_ip
from fastapi import Request

router = APIRouter(tags=["billing"])
settings = get_settings()


@router.get("/billing/plans")
def list_plans():
    return [{"plan": v["plan"], "price": v["price"], "currency": v["currency"],
             "entitlements": v["entitlements"]} for v in PLANS.values()]


@router.get("/me/subscription")
def my_subscription(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, _ = user_dev
    sub = (db.query(models.Subscription).filter(models.Subscription.user_id == user.id)
           .order_by(models.Subscription.started_at.desc()).first())
    if not sub:
        raise HTTPException(status_code=404, detail="no subscription")
    return {"plan": sub.plan, "status": sub.status,
            "entitlements": json.loads(sub.entitlements or "{}")}


@router.post("/me/billing/mpesa/initiate")
def mpesa_initiate(body: dict, request: Request, user_dev=Depends(get_current_user_device),
                   db: Session = Depends(get_db)):
    check_rate("billing_initiate", client_ip(request), 10)
    user, _ = user_dev
    plan = (body.get("plan") or "personal").lower()
    if plan not in PLANS or plan == "free":
        raise HTTPException(status_code=422, detail="plan must be paid (personal|premium|monthly|annual)")
    try:
        from app.mpesa_adapter import validate_phone_for_mpesa
        msisdn = validate_phone_for_mpesa(body.get("phone", ""))
    except ImportError:
        msisdn = normalize_msisdn(body.get("phone", ""))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    spec = PLANS[plan]
    try:
        res = get_payment_provider().initiate(str(user.id), plan, msisdn, spec["price"])
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    tx = models.PaymentTransaction(
        user_id=user.id, provider=PROVIDER_MPESA_DARAJA, plan=plan,
        amount=spec["price"], currency=spec["currency"], phone_msisdn=msisdn,
        checkout_request_id=res.checkout_request_id, merchant_request_id=res.merchant_request_id,
        status="pending", result_desc=res.message)
    db.add(tx)
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="billing.initiate",
                           resource_type="payment_transaction",
                           resource_id=res.checkout_request_id,
                           detail=json.dumps({"plan": plan, "msisdn": msisdn})))
    db.commit()
    return {"checkout_request_id": res.checkout_request_id, "plan": plan,
            "amount": spec["price"], "currency": spec["currency"],
            "live": settings.billing_live, "message": res.message}


@router.post("/billing/mpesa/callback")
def mpesa_callback(payload: dict, request: Request, db: Session = Depends(get_db)):
    """Public Daraja callback (IP-allowlisted when configured). Idempotent by checkout_request_id."""
    check_rate("billing_callback", client_ip(request), 60)
    try:
        from app.mpesa_adapter import validate_callback_origin
        if not validate_callback_origin(client_ip(request)):
            raise HTTPException(status_code=403, detail="callback origin not allowed")
    except ImportError:
        pass
    try:
        norm = get_payment_provider().parse_callback(payload)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    tx = (db.query(models.PaymentTransaction)
          .filter(models.PaymentTransaction.checkout_request_id == norm["checkout_request_id"])
          .first())
    if not tx:
        # Unknown checkout id — acknowledge to stop Daraja retries, audit for review.
        db.add(models.AuditLog(actor_type="system", actor_id="mpesa", action="billing.callback_unknown",
                               resource_id=norm["checkout_request_id"] or "?"))
        db.commit()
        return {"ResultCode": 0, "ResultDesc": "ignored"}
    if tx.status in ("success", "failed", "cancelled"):
        return {"ResultCode": 0, "ResultDesc": "duplicate ignored"}
    tx_status = norm.get("tx_status")
    if tx_status == "success":
        ok = True
    elif tx_status in ("cancelled", "failed"):
        ok = False
    else:  # stub/legacy shape: success only on ResultCode 0
        ok = norm["result_code"] == 0
    tx.result_code = norm["result_code"]
    tx.result_desc = norm["result_desc"][:255]
    tx.mpesa_receipt = norm.get("receipt")
    tx.raw_callback = json.dumps(payload)[:8000]
    if ok:
        tx.status = "success"
        if settings.billing_live:
            activate_subscription_for_transaction(db, tx)
        # else stub mode: keep free subscription untouched
    else:
        if norm.get("tx_status") == "cancelled" or norm["result_code"] == 1032:
            tx.status = "cancelled"
        else:
            tx.status = "failed"
    db.add(models.AuditLog(actor_type="system", actor_id="mpesa", action="billing.callback",
                           resource_type="payment_transaction", resource_id=tx.checkout_request_id,
                           detail=json.dumps({"status": tx.status, "code": tx.result_code})))
    db.commit()
    return {"ResultCode": 0, "ResultDesc": "accepted"}
