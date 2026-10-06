-- 006: stop persisting WireGuard private keys server-side.
--
-- Migration 005 added gateways.wg_private_key and the /generate-keys endpoint
-- wrote the gateway's private key into it. That key was also returned in the
-- HTTP response, so a database read, backup, log, or SQL injection became a
-- complete tunnel compromise.
--
-- Fix: the gateway now generates its X25519 keypair locally and registers only
-- the public half via POST /api/v1/gateways/{id}/wg-public-key.
--
-- This migration destroys any private key already stored. Affected gateways must
-- re-key: run setup_gateway.py on the device, which generates a fresh local
-- keypair and uploads its public key. The public key is left intact so an
-- existing tunnel keeps working until the device is re-keyed.

-- 1. Overwrite secrets before dropping the column so they are not left in
--    freelist pages / WAL of the database file.
UPDATE gateways SET wg_private_key = NULL WHERE wg_private_key IS NOT NULL;

-- 2. Remove the column entirely (SQLite 3.35+ / modern Postgres).
ALTER TABLE gateways DROP COLUMN wg_private_key;