"""Authorization/policy layer. V1 default PERSONAL_GATEWAY (owner).
V2-ready: PARTNER_GATEWAY via explicit grants (owner grants user); other types 403.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app import models


def _has_grant(db: Session, user_id, gateway_id) -> bool:
    g = (db.query(models.GatewayGrant)
         .filter(models.GatewayGrant.gateway_id == gateway_id,
                 models.GatewayGrant.grantee_user_id == user_id,
                 models.GatewayGrant.revoked == False)  # noqa: E712
         .first())
    return g is not None


def can_access_gateway(db: Session, user_id, gateway: models.Gateway,
                       access_type: str = "PERSONAL_GATEWAY"):
    if gateway.status in ("revoked", "unregistered"):
        raise HTTPException(status_code=403, detail=f"gateway {gateway.status}")
    if access_type == "PERSONAL_GATEWAY":
        if gateway.owner_user_id is None or str(gateway.owner_user_id) != str(user_id):
            # Fall back to grant (partner-style share) without rewriting callers.
            if _has_grant(db, user_id, gateway.id):
                return True
            raise HTTPException(status_code=403, detail="not gateway owner")
        return True
    if access_type in ("PARTNER_GATEWAY", "PUBLIC_HOTSPOT", "BUSINESS_GATEWAY"):
        if _has_grant(db, user_id, gateway.id):
            return True
        raise HTTPException(status_code=403, detail=f"{access_type} grant required")
    raise HTTPException(status_code=403, detail=f"unknown access type {access_type}")


def check_subscription_entitlement(db: Session, user_id) -> models.Subscription:
    sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user_id)
        .order_by(models.Subscription.started_at.desc())
        .first()
    )
    if not sub or sub.status != "active":
        raise HTTPException(status_code=403, detail="no active subscription/entitlement")
    return sub
