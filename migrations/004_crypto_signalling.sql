-- 004: gateway crypto nonces, grants, refresh grace.
CREATE TABLE IF NOT EXISTS gateway_nonces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  nonce VARCHAR(80) UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS gateway_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  grantee_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_type VARCHAR(30) NOT NULL DEFAULT 'PARTNER_GATEWAY',
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS refresh_prev_hash TEXT;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS refresh_prev_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS ix_grant_gw_user ON gateway_grants(gateway_id, grantee_user_id);
