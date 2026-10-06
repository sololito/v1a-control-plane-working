-- 008: gateway event cache — store-and-forward backfill (GATEWAY_EVENT_CACHE.md).
--
-- The gateway is a sensor, the Cloud is the ledger. Events the gateway
-- observed while it could not reach the Cloud arrive later in a batch and must
-- land exactly once, so each one carries the uuid the gateway minted when it
-- recorded the event; a resent batch after a lost response is a duplicate.
--
-- ALTER lines are single statements because deploy/install_server.sh feeds this
-- file to SQLite line by line (a repeat run just skips duplicate columns); the
-- CREATE INDEX lines are portable and skipped if they already exist.
ALTER TABLE gateway_events ADD COLUMN event_id VARCHAR(36);
ALTER TABLE gateway_events ADD COLUMN received_at TIMESTAMPTZ;
ALTER TABLE gateway_events ADD COLUMN remote_ip VARCHAR(64);
-- event_id is NULL for server-generated rows (heartbeat, nonce_resync, ...),
-- which are written once by the Cloud and need no dedup key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_gw_event_id ON gateway_events(gateway_id, event_id) WHERE event_id IS NOT NULL;
-- The audit report reads one gateway over a time window; without this it scans
-- the whole table and sorts.
CREATE INDEX IF NOT EXISTS ix_gw_event_gateway_time ON gateway_events(gateway_id, created_at);
