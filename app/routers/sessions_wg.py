"""WireGuard per-session peer configuration endpoints (V1B Stage 3).

Handles:
- Authorizing a phone as a WG peer for its selected gateway
- Allocating a collision-free tunnel IP per peer session
- Generating short-lived peer configuration (public key + tunnel IP)
- Marking session as CONNECTED when handshake occurs
- Revoking peer when session ends (IP freed via allocator status check)

Never exposes private gateway keys. Uses backend-coordinated
peer setup where private key stays on gateway device.

Flow (per V1B Section #6):
1. Phone requests connection authorization
2. Cloud authenticates user, device, verifies gateway ownership/grant
3. Cloud verifies gateway online, subscription active, session limits OK
4. Cloud coordinates gateway to add temporary WG peer (private key local)
5. Cloud returns peer config to phone: assigned IP + gateway public key
6. Phone configures WG using wg-quick or similar
7. Phone sends handshake -> Cloud marks session CONNECTED
8. On disconnect/revoke, Cloud removes WG peer
"""

import base64
import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import models
from app.db import get_db
from app.deps import get_current_user_device
from app.gateway.ip_alloc import allocate_tunnel_ip, gateway_tunnel_ip, gateway_tunnel_network
from app.ratelimit import client_ip

router = APIRouter(tags=["sessions-wg"])

_TERMINAL = ("disconnected", "failed", "expired", "revoked")


def _verify_gateway_wg_status(gw: models.Gateway) -> bool:
    """Check gateway has WG keypair and is online."""
    if not gw.wg_public_key:
        return False
    if gw.status != "online":
        return False
    return True


def _get_session_or_404(db: Session, session_id: str) -> models.ConnectionSession:
    session = (
        db.query(models.ConnectionSession)
        .filter(models.ConnectionSession.id == session_id)
        .first()
    )
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


def _authorize_owner(session: models.ConnectionSession, user, db: Session) -> models.Gateway:
    gateway = db.query(models.Gateway).filter(models.Gateway.id == session.gateway_id).first()
    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if str(gateway.owner_user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized for this gateway")
    return gateway


def _new_demo_client_keypair() -> dict:
    """Generate a real X25519 keypair for demo/test mobile clients.

    In production the phone generates this itself and only sends the
    public key; this helper exists so the API remains usable before the
    native mobile client ships.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b = base64.b64encode(
        priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    pub_b = base64.b64encode(
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return {"private_key": priv_b, "public_key": pub_b}


def _valid_wg_public_key(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32
    except Exception:
        return False


@router.post("/sessions/{session_id}/authorize-wg")
def authorize_wg_peer(
    session_id: str,
    request: Request,
    body: dict = None,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
):
    """Authorize a phone as a WireGuard peer for its selected gateway.

    Flow:
    1. Verify user owns the gateway associated with this session
    2. Verify gateway is online and has WG keypair generated
    3. Allocate a collision-free tunnel IP
    4. Return config to phone; phone sets up WG tunnel
    5. Phone sends handshake -> mark session CONNECTED
    6. On disconnect/revoke -> remove WG peer, mark session terminated

    Request body (all optional):
        phone_public_key: phone's own WireGuard public key (base64, 32 bytes).
            If omitted, a demo keypair is generated and returned to the phone.

    Returns peer configuration for phone to establish WG tunnel.
    Private gateway key NEVER leaves the gateway device.
    """
    body = body or {}
    session = _get_session_or_404(db, session_id)
    user, device = user_dev
    gateway = _authorize_owner(session, user, db)

    if session.status in _TERMINAL:
        raise HTTPException(
            status_code=409,
            detail=f"Session is '{session.status}' and cannot be authorized.",
        )
    if session.status == "connected":
        raise HTTPException(status_code=409, detail="Session already connected.")
    if session.wg_peer_public_key and session.status == "authorized":
        raise HTTPException(
            status_code=409,
            detail="Peer already authorized for this session. "
                   "Revoke it first (POST /sessions/{id}/revoke-wg).",
        )

    if not _verify_gateway_wg_status(gateway):
        raise HTTPException(
            status_code=409,
            detail="Gateway not online or WireGuard not configured. "
                   "Generate keys first via POST /api/v1/gateways/{id}/generate-keys",
        )

    # Phone key: prefer the phone's own public key; otherwise mint a demo one.
    phone_public_key = (body.get("phone_public_key") or "").strip()
    demo_private_key = None
    if phone_public_key:
        if not _valid_wg_public_key(phone_public_key):
            raise HTTPException(status_code=422, detail="Invalid phone_public_key format")
    else:
        demo = _new_demo_client_keypair()
        phone_public_key = demo["public_key"]
        demo_private_key = demo["private_key"]

    assigned_ip = allocate_tunnel_ip(db, gateway)
    if not gateway.tunnel_ip:
        gateway.tunnel_ip = gateway_tunnel_ip(gateway.id)

    session.wg_peer_public_key = phone_public_key
    session.wg_assigned_ip = assigned_ip
    session.data_plane = "wireguard"
    session.status = "authorized"
    if not session.authorized_at:
        session.authorized_at = datetime.utcnow()

    # Connection path: DIRECT when the gateway exposes a public endpoint,
    # otherwise a relay pair is allocated (gateway behind NAT/CGNAT).
    from app.relay import alloc_relay_session
    try:
        meta = json.loads(gateway.ip_metadata or "{}")
    except Exception:
        meta = {}
    requested_path = session.connection_path if session.connection_path in ("direct", "relay") else None
    if requested_path == "direct" and not meta.get("wg_endpoint"):
        raise HTTPException(
            status_code=409,
            detail="connection_path 'direct' requires gateway ip_metadata.wg_endpoint "
                   "(gateway behind NAT? use 'relay' or leave 'unknown').",
        )
    if requested_path == "direct" or (requested_path is None and meta.get("wg_endpoint")):
        session.connection_path = "direct"
        session.relay_info = None
    else:
        # Fail before mutating/persisting anything if the relay will not
        # confirm the port pair. Committing a session whose ports are not
        # bound hands the phone an endpoint that can never answer, and the
        # failure would only surface as a handshake timeout much later.
        from app.relay import RelayUnavailable, alloc_relay_session
        try:
            session.relay_info = json.dumps(alloc_relay_session(str(session.id)))
        except RelayUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail="Tunnel relay is unavailable; retry shortly. "
                       f"({exc})",
            )
        session.connection_path = "relay"

    db.add(session)
    db.add(gateway)
    db.add(models.SessionEvent(
        session_id=session.id, event="peer_created",
        detail=json.dumps({"assigned_ip": assigned_ip, "path": session.connection_path}),
    ))
    db.add(models.AuditLog(
        actor_type="user", actor_id=str(user.id), action="tunnel_authorized",
        resource_type="connection_session", resource_id=str(session.id),
        ip=client_ip(request),
    ))
    db.commit()
    db.refresh(session)

    config = {
        "assigned_ip": assigned_ip,
        "peer_public_key": phone_public_key,
        "session_key": base64.b64encode(os.urandom(16)).decode("utf-8"),
        "gateway_public_key": gateway.wg_public_key,
        "listen_port": gateway.wg_listen_port,
        "gateway_tunnel_ip": gateway.tunnel_ip,
        "tunnel_subnet": str(gateway_tunnel_network(gateway.id)),
        "connection_path": session.connection_path,
        "relay": json.loads(session.relay_info) if session.relay_info else None,
        "status": "authorized",
        "message": (
            "Phone should now configure WireGuard using these parameters. "
            "After connection, call POST /api/v1/sessions/{id}/handshake to confirm."
        ),
    }
    if demo_private_key is not None:
        config["client_private_key"] = demo_private_key
        config["message"] += " Demo client keypair included (production clients generate their own)."
    return config


@router.get("/sessions/{session_id}/wg-config")
def wg_config_download(
    session_id: str,
    request: Request,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
) -> dict:
    """Return a ready-to-use wg-quick config for the phone (test client).

    Requires the session to be in authorized/connecting/connected state
    with an allocated peer IP. The config contains the phone's own peer
    public key reference; the phone's *private* key is never returned
    here — clients must generate their own (the demo private key from
    authorize-wg applies only when the phone has not supplied its own).

    This is the V1B §18 "mobile test client" contract: the future ODIVORA
    app consumes exactly this payload.
    """
    session = _get_session_or_404(db, session_id)
    user, device = user_dev
    gateway = db.query(models.Gateway).filter(models.Gateway.id == session.gateway_id).first()
    if not gateway or (str(gateway.owner_user_id) != str(user.id) and not user.is_admin):
        raise HTTPException(status_code=403, detail="Not authorized")
    if session.status in _TERMINAL:
        raise HTTPException(status_code=409, detail=f"Session is '{session.status}'")
    if not session.wg_assigned_ip or not session.wg_peer_public_key:
        raise HTTPException(status_code=409, detail="Run POST /sessions/{id}/authorize-wg first")

    # Endpoint: prefer metadata-declared public endpoint, else placeholder.
    try:
        meta = json.loads(gateway.ip_metadata or "{}")
        endpoint = meta.get("wg_endpoint")
    except Exception:
        endpoint = None
    if session.connection_path == "relay":
        try:
            endpoint = json.loads(session.relay_info or "{}").get("phone_endpoint")
        except Exception:
            endpoint = None
    endpoint = endpoint or f"<gateway-public-ip>:{gateway.wg_listen_port}"

    config = (
        "[Interface]\n"
        "PrivateKey = <phone private key — generated on the phone, never sent to Cloud>\n"
        f"Address = {session.wg_assigned_ip}/32\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {gateway.wg_public_key}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )
    db.add(models.SessionEvent(session_id=session.id, event="config_issued",
                               detail=json.dumps({"path": session.connection_path})))
    db.commit()
    return {"filename": f"odivora-{str(session.id)[:8]}.conf", "config": config,
            "assigned_ip": session.wg_assigned_ip, "endpoint": endpoint,
            "allowed_ips": "0.0.0.0/0", "dns": "1.1.1.1"}


@router.post("/sessions/{session_id}/handshake")
def wg_handshake_confirm(
    session_id: str,
    request: Request,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
) -> dict:
    """Confirm WireGuard handshake occurred for this session.

    After the phone sets up the WG tunnel and sends its first handshake,
    this endpoint marks the session as CONNECTED and records the timestamp.
    """
    session = _get_session_or_404(db, session_id)
    user, device = user_dev
    gateway = db.query(models.Gateway).filter(models.Gateway.id == session.gateway_id).first()
    if gateway and str(gateway.owner_user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    if session.status == "connected":
        raise HTTPException(status_code=409, detail="Session already connected")
    if session.status not in ("requested", "authorized"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot connect from state '{session.status}'. "
                   "Expected 'requested' or 'authorized'.",
        )

    session.status = "connected"
    session.wg_handshake_at = datetime.now(timezone.utc)
    session.connected_at = datetime.utcnow()

    db.add(session)
    db.add(models.SessionEvent(
        session_id=session.id, event="tunnel_connected",
        detail=json.dumps({"handshake_at": session.wg_handshake_at.isoformat()}),
    ))
    db.add(models.AuditLog(
        actor_type="user", actor_id=str(user.id), action="tunnel_connected",
        resource_type="connection_session", resource_id=str(session.id),
        ip=client_ip(request),
    ))
    if gateway:
        gateway.wg_last_handshake_at = session.wg_handshake_at
        gateway.wg_status = "online"
        db.add(gateway)
    db.commit()
    db.refresh(session)

    return {
        "status": "connected",
        "handshake_at": session.wg_handshake_at.isoformat(),
        "message": "WireGuard tunnel confirmed connected",
    }


@router.post("/sessions/{session_id}/revoke-wg")
def revoke_wg_peer(
    session_id: str,
    request: Request,
    body: dict = None,
    user_dev=Depends(get_current_user_device),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke WireGuard peer for this session.

    Called when the user terminates the connection, the session expires,
    the gateway/device is revoked, or a security event fires.

    Actions:
    - Mark session as terminated/revoked
    - Set disconnect reason
    - Free the allocated tunnel IP (allocator ignores non-active sessions)
    - Log a peer_revoked event

    Gateway-side peer removal (`wg set ... peer <pubkey> remove`) is
    executed on the gateway via its control channel / next poll.
    """
    body = body or {}
    session = _get_session_or_404(db, session_id)
    user, device = user_dev
    gateway = db.query(models.Gateway).filter(models.Gateway.id == session.gateway_id).first()
    if gateway and str(gateway.owner_user_id) != str(user.id) and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    if session.status in _TERMINAL:
        raise HTTPException(status_code=409, detail=f"Session already '{session.status}'")

    session.status = "revoked"
    session.wg_terminated_at = datetime.now(timezone.utc)
    session.wg_disconnect_reason = (body.get("reason") or "user_terminated")[:120]
    session.ended_at = datetime.utcnow()

    if session.connection_path == "relay":
        from app.relay import free_relay_session
        free_relay_session(str(session.id))

    db.add(session)
    db.add(models.SessionEvent(
        session_id=session.id, event="peer_revoked",
        detail=json.dumps({"reason": session.wg_disconnect_reason}),
    ))
    db.add(models.AuditLog(
        actor_type="user", actor_id=str(user.id), action="peer_revoked",
        resource_type="connection_session", resource_id=str(session.id),
        ip=client_ip(request),
    ))
    db.commit()
    db.refresh(session)

    return {
        "status": "revoked",
        "disconnect_reason": session.wg_disconnect_reason,
        "handshake_at": session.wg_handshake_at.isoformat() if session.wg_handshake_at else None,
        "terminated_at": session.wg_terminated_at.isoformat(),
        "message": "WireGuard peer revoked and session terminated",
    }
