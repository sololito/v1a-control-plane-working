-- 003: production hardening (gateway replay + attempts, perf indexes).
ALTER TABLE gateways ADD COLUMN IF NOT EXISTS pairing_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE gateways ADD COLUMN IF NOT EXISTS last_nonce VARCHAR(80);
CREATE INDEX IF NOT EXISTS ix_payment_checkout ON payment_transactions(checkout_request_id);
CREATE INDEX IF NOT EXISTS ix_conn_user_status ON connection_sessions(user_id, status);
CREATE INDEX IF NOT EXISTS ix_conn_expires ON connection_sessions(expires_at);
CREATE INDEX IF NOT EXISTS ix_gw_owner_status ON gateways(owner_user_id, status);
CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs(created_at);
