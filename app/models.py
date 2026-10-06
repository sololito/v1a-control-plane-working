"""Canonical SQLAlchemy models. Mirrors migrations/001_init.sql (Postgres)."""
import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, String, Text, Integer,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import TypeDecorator, CHAR
import sqlalchemy as sa

from app.db import Base


class GUID(TypeDecorator):
    """Portable UUID: Postgres UUID, otherwise CHAR(36)."""
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


def new_uuid():
    return uuid.uuid4()


def utcnow():
    return datetime.utcnow()


class User(Base):
    __tablename__ = "users"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    display_name = Column(String(120), nullable=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class UserDevice(Base):
    __tablename__ = "user_devices"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_name = Column(String(120), nullable=False, default="phone")
    device_type = Column(String(40), nullable=False, default="mobile")  # mobile|tablet|other
    status = Column(String(20), nullable=False, default="active")  # active|revoked
    refresh_token_hash = Column(String(255), nullable=True)
    refresh_prev_hash = Column(String(255), nullable=True)  # 30s grace for concurrent refresh
    refresh_prev_at = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    # --- Device fingerprint for the audit trail (client-declared where noted) ---
    # ip_address is server-observed (X-Forwarded-For aware), never client-claimed.
    ip_address = Column(String(64), nullable=True)
    # IMEI/MAC are only reachable by a native app (OS APIs); they arrive through
    # POST /me/device-identity and are unverified self-reported identifiers.
    imei = Column(String(32), nullable=True)
    mac_address = Column(String(32), nullable=True)
    user_agent = Column(String(255), nullable=True)
    identity_updated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    revoked_at = Column(DateTime, nullable=True)


class Gateway(Base):
    __tablename__ = "gateways"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    owner_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    device_type = Column(String(40), nullable=False, default="esp32")  # esp32|linux|openwrt|other
    firmware_version = Column(String(40), nullable=True)
    status = Column(String(20), nullable=False, default="unregistered")
    # unregistered|pairing|registered|online|offline|revoked
    pairing_code_hash = Column(String(255), nullable=True)
    pairing_expires_at = Column(DateTime, nullable=True)
    pairing_attempts = Column(Integer, nullable=False, default=0)
    last_nonce = Column(String(80), nullable=True)  # replay protection, monotonic per gateway
    public_key = Column(Text, nullable=True)  # Ed25519 gateway identity (V1A)
    # --- WireGuard data-plane fields (V1B) ---
    # NOTE: there is deliberately NO wg_private_key column. The gateway
    # generates its X25519 keypair locally and keeps the private half in local
    # storage; only the public half is ever registered with this service (see
    # POST /gateways/{id}/wg-public-key). The column was removed in migration
    # 006 after it was found to persist gateway private keys in the database.
    wg_public_key = Column(String(44), nullable=True)  # Public key - safe to store and share
    # WireGuard format: base64-encoded 255-bit key (44 chars incl. '=' padding)
    wg_listen_port = Column(Integer, default=51820)  # Default WireGuard listen port
    wg_status = Column(String(20), default="offline")  # offline|online|handshaking|error
    wg_last_handshake_at = Column(DateTime, nullable=True)  # Timestamp of last WG handshake
    tunnel_ip = Column(String(45), nullable=True)  # Assigned tunnel IP for this gateway's session
    # --- End WireGuard fields ---
    last_seen = Column(DateTime, nullable=True)
    ip_metadata = Column(Text, nullable=True)  # JSON string
    health = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class GatewayCredential(Base):
    __tablename__ = "gateway_credentials"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    algorithm = Column(String(20), nullable=False, default="ed25519")
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String(128), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class GatewayEvent(Base):
    __tablename__ = "gateway_events"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(60), nullable=False)
    payload = Column(Text, nullable=True)  # JSON string
    # Store-and-forward backfill: rows that arrived in a batch carry the uuid
    # the gateway minted at record time, so a resent batch after a lost
    # response is counted as a duplicate instead of a second copy. Server
    # generated rows (heartbeat, nonce_resync, ...) keep NULL and are exempt
    # from the unique index by its partial WHERE clause.
    event_id = Column(String(36), nullable=True)
    # created_at is when the event happened — for batched rows that is the
    # *gateway's* clock. received_at/remote_ip are what the Cloud observed, and
    # they double as the provenance flag: non-NULL means the gateway sent the
    # row (a claim, shown as unverified), NULL means the Cloud wrote it itself
    # (heartbeat, registered, ...) and no sensor is speaking. A large gap
    # between the two clocks means the sensor has no NTP yet.
    received_at = Column(DateTime, nullable=True)
    remote_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        Index("uq_gw_event_id", "gateway_id", "event_id", unique=True,
              sqlite_where=sa.text("event_id IS NOT NULL"),
              postgresql_where=sa.text("event_id IS NOT NULL")),
        Index("ix_gw_event_gateway_time", "gateway_id", "created_at"),
    )


class GatewayNonce(Base):
    """Single-use Ed25519 challenge. Gateway signs nonce bytes with private key."""
    __tablename__ = "gateway_nonces"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    nonce = Column(String(80), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class GatewayGrant(Base):
    """V2-ready: owner grants another user access without transfer of ownership."""
    __tablename__ = "gateway_grants"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    grantee_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    access_type = Column(String(30), nullable=False, default="PARTNER_GATEWAY")
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ConnectionSession(Base):
    __tablename__ = "connection_sessions"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(GUID(), ForeignKey("user_devices.id", ondelete="SET NULL"), nullable=True)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False, default="requested")
    connection_path = Column(String(20), nullable=False, default="unknown")  # direct|relay|unknown
    session_token_hash = Column(String(255), nullable=True)
    relay_info = Column(Text, nullable=True)  # JSON placeholder for future relay
    disconnect_reason = Column(String(120), nullable=True)
    requested_at = Column(DateTime, default=utcnow, nullable=False)
    authorized_at = Column(DateTime, nullable=True)
    connected_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    # --- WireGuard data-plane fields (V1B) ---
    wg_peer_public_key = Column(String(44), nullable=True)  # Phone's WG public key
    wg_assigned_ip = Column(String(45), nullable=True)  # Tunnel IP assigned to this peer
    wg_handshake_at = Column(DateTime, nullable=True)  # When WG handshake occurred
    wg_terminated_at = Column(DateTime, nullable=True)  # When peer was terminated
    wg_disconnect_reason = Column(String(120), nullable=True)  # Last disconnect reason
    data_plane = Column(String(20), default="none")  # none|wireguard|relay
    # --- End WireGuard fields ---


class SessionEvent(Base):
    __tablename__ = "session_events"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    session_id = Column(GUID(), ForeignKey("connection_sessions.id", ondelete="CASCADE"), nullable=False)
    event = Column(String(60), nullable=False)
    detail = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=utcnow, nullable=False)


class DeviceVisit(Base):
    """First N destinations a device reached while a tunnel session was live.

    Populated by the mobile client (POST /me/visits) — the cloud never sees
    plaintext traffic inside a WireGuard tunnel, so the app reports it. `rank`
    is the 1-based order of arrival and is capped at VISIT_SITE_LIMIT per
    (device, session): only the FIRST ten sites are ever kept.
    """
    __tablename__ = "device_visits"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(GUID(), ForeignKey("user_devices.id", ondelete="SET NULL"), nullable=True)
    session_id = Column(GUID(), ForeignKey("connection_sessions.id", ondelete="CASCADE"),
                        nullable=False)
    gateway_id = Column(GUID(), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False)
    rank = Column(Integer, nullable=False)  # 1..VISIT_SITE_LIMIT
    host = Column(String(255), nullable=False)  # normalized host/site visited
    url = Column(Text, nullable=True)
    client_ip = Column(String(64), nullable=True)
    visited_at = Column(DateTime, default=utcnow, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    plan = Column(String(40), nullable=False, default="free")  # free|personal|premium|...
    status = Column(String(20), nullable=False, default="active")
    entitlements = Column(Text, nullable=True)  # JSON string
    started_at = Column(DateTime, default=utcnow, nullable=False)
    ends_at = Column(DateTime, nullable=True)


class PaymentTransaction(Base):
    """M-Pesa (or future provider) charge attempt. Callback updates status idempotently."""
    __tablename__ = "payment_transactions"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    subscription_id = Column(GUID(), ForeignKey("subscriptions.id", ondelete="SET NULL"), nullable=True)
    provider = Column(String(40), nullable=False, default="mpesa-daraja")
    plan = Column(String(40), nullable=False, default="personal")
    amount = Column(Integer, nullable=False, default=0)
    currency = Column(String(10), nullable=False, default="KES")
    phone_msisdn = Column(String(20), nullable=False, default="")
    checkout_request_id = Column(String(80), unique=True, nullable=True, index=True)
    merchant_request_id = Column(String(80), nullable=True)
    mpesa_receipt = Column(String(40), nullable=True)
    status = Column(String(20), nullable=False, default="pending")  # pending|success|failed|cancelled
    result_code = Column(Integer, nullable=True)
    result_desc = Column(String(255), nullable=True)
    raw_callback = Column(Text, nullable=True)  # JSON string, never secrets
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(GUID(), primary_key=True, default=new_uuid)
    actor_type = Column(String(20), nullable=False)  # user|gateway|admin|system
    actor_id = Column(String(80), nullable=True)
    action = Column(String(80), nullable=False)
    resource_type = Column(String(60), nullable=True)
    resource_id = Column(String(80), nullable=True)
    detail = Column(Text, nullable=True)
    ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


Index("ix_gateway_status", Gateway.status)
Index("ix_gateway_owner", Gateway.owner_user_id)
Index("ix_session_gateway_status", ConnectionSession.gateway_id, ConnectionSession.status)
Index("ix_session_user", ConnectionSession.user_id)
Index("ix_audit_action", AuditLog.action)
Index("ix_audit_resource", AuditLog.resource_type, AuditLog.resource_id)
Index("ix_visit_session", DeviceVisit.session_id, DeviceVisit.rank)
Index("ix_visit_gateway", DeviceVisit.gateway_id)
Index("ix_device_user", UserDevice.user_id, UserDevice.status)
