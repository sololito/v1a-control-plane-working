-- ODIVORA Home Connectivity — canonical Postgres schema (V1 foundation).
-- SQLite dev tables are auto-created by SQLAlchemy; this file is the prod source of truth.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name VARCHAR(120),
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- NOTE: CITEXT requires citext extension; fallback to VARCHAR(320) if unavailable.

CREATE TABLE IF NOT EXISTS user_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name VARCHAR(120) NOT NULL DEFAULT 'phone',
  device_type VARCHAR(40) NOT NULL DEFAULT 'mobile',
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  refresh_token_hash TEXT,
  last_seen TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_user_devices_user ON user_devices(user_id);

CREATE TABLE IF NOT EXISTS gateways (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  device_type VARCHAR(40) NOT NULL DEFAULT 'esp32',
  firmware_version VARCHAR(40),
  status VARCHAR(20) NOT NULL DEFAULT 'unregistered',
  pairing_code_hash TEXT,
  pairing_expires_at TIMESTAMPTZ,
  public_key TEXT,
  last_seen TIMESTAMPTZ,
  ip_metadata JSONB,
  health JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_gateway_status ON gateways(status);
CREATE INDEX IF NOT EXISTS ix_gateway_owner ON gateways(owner_user_id);

CREATE TABLE IF NOT EXISTS gateway_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  algorithm VARCHAR(20) NOT NULL DEFAULT 'ed25519',
  public_key TEXT NOT NULL,
  fingerprint VARCHAR(128) NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gateway_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  event_type VARCHAR(60) NOT NULL,
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_gateway_events_gw ON gateway_events(gateway_id, created_at);

CREATE TABLE IF NOT EXISTS connection_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID REFERENCES user_devices(id) ON DELETE SET NULL,
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL DEFAULT 'requested',
  connection_path VARCHAR(20) NOT NULL DEFAULT 'unknown',
  session_token_hash TEXT,
  relay_info JSONB,
  disconnect_reason VARCHAR(120),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  authorized_at TIMESTAMPTZ,
  connected_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_session_gateway_status ON connection_sessions(gateway_id, status);
CREATE INDEX IF NOT EXISTS ix_session_user ON connection_sessions(user_id);

CREATE TABLE IF NOT EXISTS session_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES connection_sessions(id) ON DELETE CASCADE,
  event VARCHAR(60) NOT NULL,
  detail JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan VARCHAR(40) NOT NULL DEFAULT 'free',
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  entitlements JSONB,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ends_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_type VARCHAR(20) NOT NULL,
  actor_id VARCHAR(80),
  action VARCHAR(80) NOT NULL,
  resource_type VARCHAR(60),
  resource_id VARCHAR(80),
  detail JSONB,
  ip VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_logs(action, created_at);
