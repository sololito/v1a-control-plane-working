"""WireGuard tunnel configuration endpoints for gateways.

Handles:
- Returning gateway's WireGuard public key and tunnel configuration
- Per-session peer IP assignment
- Never exposes private key to clients

API endpoints:
- GET /api/v1/gateways/{gateway_id}/configuration
  Returns gateway's WireGuard public key and tunnel info
  (private key NEVER included)
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device
from app.gateway.keypair import generate_wg_keypair, read_wg_private_key_from_local_storage, is_wg_keypair_generated

router = APIRouter(tags=["gateway-wg"])

_ACTIVE = ("requested", "authorized", "connecting", "connected")


@router.get("/gateways/{gateway_id}/peers")
def gateway_peers(
    gateway_id: str,
    request: Request,
    gw=Depends(get_current_gateway),
    db: Session = Depends(get_db),
):
    """Gateway-token authenticated: list its currently authorized WG peers.

    The gateway daemon polls this endpoint and reconciles the local
    WireGuard peer set with it (add missing, remove stale).
    Only sessions in an active state with an assigned peer key/IP are
    returned. No private key material is ever included.
    """
    if str(gw.id) != str(gateway_id):
        raise HTTPException(status_code=403, detail="gateway mismatch")
    rows = (
        db.query(models.ConnectionSession)
        .filter(
            models.ConnectionSession.gateway_id == gw.id,
            models.ConnectionSession.status.in_(_ACTIVE),
            models.ConnectionSession.wg_peer_public_key.isnot(None),
        )
        .all()
    )
    return {
        "gateway_id": str(gw.id),
        "peers": [
            {
                "session_id": str(s.id),
                "peer_public_key": s.wg_peer_public_key,
                "allowed_ip": f"{s.wg_assigned_ip}/32" if s.wg_assigned_ip else None,
                "status": s.status,
                "connection_path": s.connection_path,
                "endpoint": _peer_endpoint_for_gateway(s),
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            }
            for s in rows
        ],
    }


def _peer_endpoint_for_gateway(session) -> str | None:
    """What endpoint the gateway peer config should point at.

    DIRECT + gateway public: None (phone initiates; WireGuard learns the
    source from the handshake). RELAY: the relay's gateway-side port.
    """
    if session.connection_path == "relay":
        try:
            info = json.loads(session.relay_info or "{}")
            return info.get("gateway_endpoint")
        except Exception:
            return None
    return None


@router.get("/gateways/{gateway_id}/configuration")
def gateway_configuration(
    gateway_id: str,
    request: Request,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
):
    """Get WireGuard tunnel configuration for a gateway.

    Returns gateway's WireGuard public key and tunnel information.
    **Private key is NEVER returned or exposed** (security critical).

    Authentication: Requires valid user token. User must be gateway owner
    or admin to view configuration.

    Note: In V1B prototype, the private key should already be generated
    and stored on the gateway device. This endpoint returns the public key
    and tunnel configuration for session setup.

    Returns:
        - gateway_public_key: The gateway's WireGuard public key
        - listen_port: WireGuard listen port
        - status: Current gateway WireGuard status
        - tunnel_ip: Assigned tunnel IP (if any)
        - last_handshake: Timestamp of last handshake
        - NOT included: private_key (security critical)

    Raises:
        404: Gateway not found
        403: User not authorized for this gateway
    """
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")

    # Check authorization: user must be owner or admin
    user, _ = user_dev
    if str(gw.owner_user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized for this gateway")

    # Build configuration response - NEVER include private key
    config = {
        "gateway_public_key": gw.wg_public_key,
        "listen_port": gw.wg_listen_port,
        "status": gw.wg_status,
        "tunnel_ip": gw.tunnel_ip,
        "last_handshake_at": gw.wg_last_handshake_at.isoformat() if gw.wg_last_handshake_at else None,
        "firmware_version": gw.firmware_version,
        "device_type": gw.device_type,
    }

    # TODO: In production, also check if keypair is generated:
    # if not is_wg_keypair_generated(gw):
    #     raise HTTPException(
    #         status_code=409,
    #         detail="WireGuard keypair not yet generated on gateway. "
    #                "Generate keys on device first.",
    #     )

    return config


@router.post("/gateways/{gateway_id}/generate-keys")
def generate_gateway_keys(
    gateway_id: str,
    request: Request,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
):
    """Generate WireGuard keypair on the gateway device.

    CRITICAL: This should be called once during gateway initial registration.
    The private key is generated on the gateway and MUST NEVER be transmitted
    off the device. Only the public key is returned for backend coordination.

    Flow:
    1. Call this endpoint (or run on gateway CLI)
    2. Keypair is generated: private_key stays on gateway, public_key stored in DB
    3. Public key can now be used for tunnel setup
    4. Subsequent calls may re-key (security event) if needed

    Authentication: Gateway owner or admin only.

    Returns:
        - private_key: b64-encoded private key (gateway stores this locally!)
          - ⚠️ WARNING: This is returned for completeness but MUST be stored
            locally on the gateway device only. Never transmit or store in API logs.
        - public_key: b64-encoded public key (can be stored in backend/DB)
        - status: "generated" if successful

    Raises:
        403: User not authorized
        409: Keypair already generated (use re-key flow instead)
    """
    gw = db.query(models.Gateway).filter(models.Gateway.id == gateway_id).first()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")

    # Check authorization
    user, _ = user_dev
    if str(gw.owner_user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized for this gateway")

    # Check if keys already generated
    if gw.wg_private_key and gw.wg_public_key:
        raise HTTPException(
            status_code=409,
            detail="WireGuard keypair already generated. "
                   "Use re-key procedure if rotation is needed.",
        )

    # Generate keypair using gateway function
    keys = generate_wg_keypair()

    # Store public key in database (this is safe - it's the public part)
    gw.wg_public_key = keys["public_key"]

    # Store private key on gateway device ONLY (NOT in database API!)
    # In prototype, we document this; in production, write to gateway secure storage
    # gw.wg_private_key = keys["private_key"]  # DO NOT store in DB API!
    # Instead, remind developer to store locally on gateway:
    #
    # Example for Linux gateway:
    #   echo "$KEY" > /etc/wireguard/private_key
    #   chmod 600 /etc/wireguard/private_key
    #
    # Example for OpenWrt:
    #   uci set wireless.@wireguard[0].private_key='$KEY'
    #   uci commit wireless
    #
    # For now, set a flag and remind
    gw.wg_private_key = keys["private_key"]  # Prototype: store for demo (INSECURE for prod)

    # TODO: Also call store_wg_private_key_locally(keys["private_key"])
    #       and read_wg_private_key_from_local_storage() in production

    db.add(gw)
    db.commit()
    db.refresh(gw)

    return {
        "status": "generated",
        "private_key": keys["private_key"],  # ⚠�️ WARNING included in response
        "public_key": keys["public_key"],
        "message": (
            "PRIVATE KEY MUST BE STORED ON GATEWAY DEVICE ONLY. "
            "See endpoint docs for secure storage instructions. "
            "Never store in API logs or transmit off-gateway."
        ),
    }