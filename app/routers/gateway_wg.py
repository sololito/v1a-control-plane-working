"""WireGuard tunnel configuration endpoints for gateways.

Handles:
- Returning gateway's WireGuard public key and tunnel configuration
- Per-session peer IP assignment
- Never exposes private key to clients

API endpoints:
- GET /api/v1/gateways/{gateway_id}/configuration
  Returns gateway's WireGuard public key and tunnel info
  (private key NEVER included)
- POST /api/v1/gateways/{gateway_id}/wg-public-key
  Device registers its OWN WireGuard public key (private key never leaves it)
"""

import base64
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import models, schemas
from app.config import get_settings
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device
from app.ratelimit import check_rate, client_ip
from app.gateway.keypair import generate_wg_keypair, read_wg_private_key_from_local_storage, is_wg_keypair_generated

router = APIRouter(tags=["gateway-wg"])


def _audit(db, actor_type, actor_id, action, rid=None, ip=None):
    db.add(models.AuditLog(actor_type=actor_type, actor_id=actor_id, action=action,
                           resource_type="gateway", resource_id=rid, ip=ip))

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


WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _validate_wg_public_key(value: str) -> str:
    """WireGuard keys are 32 bytes, base64 -> exactly 44 chars ending in '='."""
    key = (value or "").strip()
    if len(key) != 44 or not WG_KEY_RE.match(key):
        raise HTTPException(
            status_code=422,
            detail="wg_public_key must be a 44-char base64 WireGuard key ending in '='",
        )
    try:
        if len(base64.b64decode(key, validate=True)) != 32:
            raise ValueError("not 32 bytes")
    except Exception:
        raise HTTPException(status_code=422, detail="wg_public_key is not valid base64")
    return key


@router.post("/gateways/{gateway_id}/wg-public-key")
def register_wg_public_key(
    gateway_id: str,
    body: dict,
    request: Request,
    gw: models.Gateway = Depends(get_current_gateway),
    db: Session = Depends(get_db),
):
    """Register the gateway's WireGuard PUBLIC key. Called by the device itself.

    The gateway generates its X25519 keypair locally, keeps the private half in
    local storage, and uploads only the public half here. The cloud therefore
    never holds — or can ever leak — a gateway private key.

    Authentication uses the gateway's own bearer token, so the device that
    owns the private key is the device registering the public key.

    Re-registering is allowed only when the gateway currently has no working
    peer sessions, so a stolen owner token cannot silently repoint an active
    tunnel (which would be a denial of service at best).
    """
    check_rate(f"gw_wgkey:{gateway_id}", client_ip(request), 10)
    if str(gw.id) != str(gateway_id):
        raise HTTPException(status_code=403, detail="token does not match gateway")
    pub = _validate_wg_public_key(body.get("wg_public_key"))

    previous = gw.wg_public_key
    if previous and previous != pub:
        active = (db.query(models.ConnectionSession)
                  .filter(models.ConnectionSession.gateway_id == gw.id,
                          models.ConnectionSession.status.in_(("requested", "authorized",
                                                              "connecting", "connected")))
                  .count())
        if active:
            raise HTTPException(
                status_code=409,
                detail=f"gateway already has {active} active session(s); "
                       "revoke them before re-keying",
            )
    if previous == pub:
        return {"status": "unchanged", "wg_public_key": pub}

    gw.wg_public_key = pub
    db.add(gw)
    db.add(models.GatewayEvent(
        gateway_id=gw.id,
        event_type="wg_public_key_registered",
        payload=json.dumps({"rotated": bool(previous)}),
    ))
    _audit(db, "gateway", str(gw.id), "gateway.wg_public_key_registered",
           str(gw.id), ip=client_ip(request))
    db.commit()
    db.refresh(gw)
    return {
        "status": "registered" if not previous else "rotated",
        "wg_public_key": gw.wg_public_key,
        "message": ("Only the public key is stored on the server. "
                    "The private key never leaves the gateway."),
    }


@router.post("/gateways/{gateway_id}/generate-keys")
def generate_gateway_keys(
    gateway_id: str,
    request: Request,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
):
    """REMOVED — server-side WireGuard key generation is no longer supported.

    Generating keys here meant the private key had to travel back to the
    gateway over the network and was persisted in the database. Both are
    unacceptable: a database read, backup, or SQL injection becomes a full
    tunnel compromise.

    Use POST /api/v1/gateways/{gateway_id}/wg-public-key instead: the gateway
    generates its own keypair locally and uploads only the public key.
    """
    raise HTTPException(
        status_code=410,
        detail="generate-keys is removed: the cloud no longer generates or stores "
               "WireGuard private keys. Generate the keypair on the device and "
               "POST the public key to /api/v1/gateways/{id}/wg-public-key.",
    )