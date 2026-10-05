-- 005: V1B WireGuard data-plane columns.
ALTER TABLE gateways ADD COLUMN wg_private_key VARCHAR(512);
ALTER TABLE gateways ADD COLUMN wg_public_key VARCHAR(44);
ALTER TABLE gateways ADD COLUMN wg_listen_port INTEGER DEFAULT 51820;
ALTER TABLE gateways ADD COLUMN wg_status VARCHAR(20) DEFAULT 'offline';
ALTER TABLE gateways ADD COLUMN wg_last_handshake_at TIMESTAMP;
ALTER TABLE gateways ADD COLUMN tunnel_ip VARCHAR(45);
ALTER TABLE connection_sessions ADD COLUMN wg_peer_public_key VARCHAR(44);
ALTER TABLE connection_sessions ADD COLUMN wg_assigned_ip VARCHAR(45);
ALTER TABLE connection_sessions ADD COLUMN wg_handshake_at TIMESTAMP;
ALTER TABLE connection_sessions ADD COLUMN wg_terminated_at TIMESTAMP;
ALTER TABLE connection_sessions ADD COLUMN wg_disconnect_reason VARCHAR(120);
ALTER TABLE connection_sessions ADD COLUMN data_plane VARCHAR(20) DEFAULT 'none';
