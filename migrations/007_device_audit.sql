-- 007: device forensics + visited-site audit trail (mobile app foundation).
--
-- Every device that can reach the cloud gets an audit record: the IP it
-- arrived from (server-observed), plus IMEI/MAC when the native app is able to
-- read them (OS-restricted, self-reported, hence nullable).
--
-- ALTER lines are single statements because deploy/install_server.sh feeds this
-- file to SQLite line by line (a repeat run just skips duplicate columns); the
-- CREATE TABLE below is Postgres-canonical and SQLite gets the same table from
-- `Base.metadata.create_all` at startup.
ALTER TABLE user_devices ADD COLUMN ip_address VARCHAR(64);
ALTER TABLE user_devices ADD COLUMN imei VARCHAR(32);
ALTER TABLE user_devices ADD COLUMN mac_address VARCHAR(32);
ALTER TABLE user_devices ADD COLUMN user_agent VARCHAR(255);
ALTER TABLE user_devices ADD COLUMN identity_updated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS ix_user_devices_user_status ON user_devices(user_id, status);

-- First ten sites a device visited while a given tunnel session was live.
-- Reported by the mobile client; the cloud never inspects tunnel payloads.
CREATE TABLE IF NOT EXISTS device_visits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID REFERENCES user_devices(id) ON DELETE SET NULL,
  session_id UUID NOT NULL REFERENCES connection_sessions(id) ON DELETE CASCADE,
  gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  rank INTEGER NOT NULL,
  host VARCHAR(255) NOT NULL,
  url TEXT,
  client_ip VARCHAR(64),
  visited_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_visit_session ON device_visits(session_id, rank);
CREATE INDEX IF NOT EXISTS ix_visit_gateway ON device_visits(gateway_id);
CREATE INDEX IF NOT EXISTS ix_audit_resource ON audit_logs(resource_type, resource_id);
