# Gateway event cache — store-and-forward backfill

Status: implemented (agent spool, batch endpoint, retention, audit surfaces;
tests in `tests/test_event_{spool,batch,backfill}.py`).

## 0. The rule this design follows

The **cloud is the ledger, the gateway is a sensor**.

| Record | Lives where | Why |
|---|---|---|
| Identity, authn/authz, sessions, AuditLog (server-observed), DeviceVisit | Cloud only | One authority; cannot be deleted by whoever is holding the premises box |
| WireGuard keys, peer set, forwarding/NAT | Gateway | Already the case — the cloud never touches payloads |
| Packets | Gateway + relay | Relay stays a stateless UDP port-mapper: no records, no decryption |
| What the gateway itself *observed* (peer added/removed, handshake, WAN change, sync failure) | Gateway spool → shipped to cloud | Evidence is worthless if the box holding it is stolen, powered off, or tampered with |

The gateway may cache; it never becomes authoritative. Everything it ships is
labelled **gateway-reported (unverified)** in the audit report, because a
gateway owner can fabricate rows about their own tunnel — that is inherent to
the sensor, and is exactly why auth records never move off the cloud.

## 1. What is captured

Event types emitted by the Linux/OpenWrt agent (`firmware/linux_gateway/gateway_agent.py`
and `app/gateway/daemon.py`):

| `event_type` | Emitted when | Payload (bounded) |
|---|---|---|
| `agent_started` / `agent_stopped` | process lifecycle | `pid`, `version` |
| `peer_added` / `peer_removed` | `dataplane.sync_peers` delta | `peer_public_key`, `allowed_ip`, `session_id` |
| `handshake_seen` | peer handshake timestamp advanced | `peer_public_key`, `allowed_ip` (deduped per peer per run) |
| `nat_applied` / `forwarding_error` | NAT / `ip_forward` verification | `iface`, `errors[]` (≤5) |
| `wan_ip_changed` | resolved WAN interface address changed | `old`, `new` |
| `wg_iface_down` | `interface_up()` false during sync | `iface` |
| `sync_error` | `sync_once` raised or returned errors | `error` (≤300 chars) |
| `token_refreshed` | bearer refresh after 401 | — |
| `event_batch_rejected` | Cloud answered 422 to a batch (our rows broke the contract) | `detail` (≤300 chars) |
| `spool_overflow` | local queue hit its cap, oldest rows dropped | `dropped`, `bytes` (carried forward from any marker dropped with them) |

Never captured: packet payloads, full URLs, DNS queries, credentials, keys.
The data-plane stays dark; this is liveness and change evidence only.

**ESP32 firmware is out of scope for the spool** (flash wear, no durable
append). It already produces server-observed rows via heartbeat → `GatewayEvent`.
A later option is piggybacking a small `events: []` array on `HeartbeatRequest`
so the ESP32 gets the same backfill through one transport; not in V1.

## 2. Local spool (Linux agent)

Append-only JSON Lines, one event per line, at
`/var/lib/odivora/events.jsonl` (override: `EVENT_SPOOL` in
`/etc/odivora/gateway.env`; falls back next to `STATE_FILE` if that path is
unwritable).

```
{"event_id":"b7e0…","recorded_at":"2026-10-06T19:44:12.413Z","type":"peer_added","payload":{…}}
```

- **`event_id` is a uuid4 minted at record time.** A gapless per-gateway
  sequence counter was rejected: the crash window between "increment counter"
  and "persist counter" permanently drops or duplicates events, which is worse
  than no counter at all. Idempotency comes from `event_id` (§4), ordering from
  `recorded_at` (§5).
- Single writer: events are appended from the main loop thread. If a second
  emitter is ever needed it must go through a `queue.Queue` drained by one
  writer — never two open file handles.
- Append durability matches the existing `state.json` style: one `write()` +
  `flush()` per line; no per-event fsync (a power cut may lose the tail of the
  spool, never the spool's earlier contents).
- **Rotation:** at 1 MB or 5000 lines the active file is renamed
  `events-<seq>-<utc>.jsonl`, where `<seq>` is 000001, 000002, … continued from
  whatever is on disk. The sequence, not the clock, keeps segments ordered: an
  `ack` rewrites a segment and would otherwise push an older one behind a newer
  one. At most 3 rotated files are kept beside the active one — and **a rotated
  file is still part of the queue**: `pending()`/`batch()` read every segment
  oldest-first and `ack()` trims whichever held the confirmed rows, so rotation
  never orphans an unshipped backlog.
- **Cap:** 5 MB total. On overflow the oldest segment goes first (then the
  oldest lines of the active file, as one contiguous newest run) and one
  `spool_overflow` event recording how many were lost is appended — an explicit
  gap marker beats silent loss. A marker that is itself dropped hands its
  counts forward, so the announced gap never shrinks.
- **Corruption:** a truncated/garbage line is skipped at read time with a
  `[spool] skipping bad line` warning; never fatal.
- The spool holds only events, never tokens or keys (it sits beside, not
  inside, `state.json`).

## 3. Shipping

`POST /api/v1/gateways/{gateway_id}/events/batch`, existing gateway bearer
auth, gateway-id match enforced as on every other gateway route.

```json
{
  "events": [
    {"event_id": "b7e0…", "recorded_at": "2026-10-06T19:44:12.413Z",
     "type": "peer_added", "payload": {"peer_public_key": "…", "allowed_ip": "10.8.0.3"}}
  ]
}
```

Response: `{"ok": true, "stored": 18, "duplicates": 2}`.

- **Trigger:** one batch attempt after a *successful* heartbeat, only when the
  queue holds ≥1 events, and only if ≥20 events are pending or ≥30 s since the
  last attempt. With no attempt yet recorded the batch goes out immediately —
  a backlog carried over from the last run matters at startup. Timeout 5 s. It
  runs in the existing loop — no second thread.
- **Ack is implicit:** the agent deletes the batch from the spool only after a
  2xx. A lost response means the next attempt re-sends the same rows and the
  server drops them as duplicates. No `last_seq` handshake to get wrong.
- Spool failures never fail the heartbeat; a failed ship simply leaves rows
  queued for the next iteration's backoff cycle.
- Caps enforced server-side: ≤200 events and ≤256 KB per request,
  `event_type` ≤60 chars, payload JSON ≤8 KB, `recorded_at` ISO-8601 — 422
  otherwise (an agent bug must not be able to grow the table unbounded).
- Rate limit: own bucket (`gw_events:{id}`), `gateway_rate_per_minute`.

## 4. Server storage

`gateway_events` already exists (`app/models.py:127`) and the single-event
`POST /gateways/{id}/events` route (`app/routers/gateways.py:216`) stays.
Migration `008_gateway_event_batch.sql` adds:

```sql
ALTER TABLE gateway_events ADD COLUMN event_id VARCHAR(36);
ALTER TABLE gateway_events ADD COLUMN received_at DATETIME;
ALTER TABLE gateway_events ADD COLUMN remote_ip VARCHAR(64);
CREATE UNIQUE INDEX uq_gw_event_id ON gateway_events (gateway_id, event_id)
  WHERE event_id IS NOT NULL;
```

- `event_id` is NULL for rows written before this change and for
  server-generated rows (`heartbeat`, `nonce_resync`, `registered`, …), which
  are written once by the cloud and need no dedupe.
- `received_at` = server clock at insert, `remote_ip` = `client_ip(request)` —
  server-observed, same split used for `ip_hint` vs `remote_ip` on heartbeats.
- Duplicate `event_id` in the same batch or across batches → counted in
  `duplicates`, not an error.
- **Provenance:** `received_at` doubles as the flag that says *who wrote this
  row*. Non-NULL means the gateway sent it (batch, or the single-event
  `POST /gateways/{id}/events`, which now stamps `received_at`/`remote_ip`
  too); NULL means the Cloud wrote it itself (`heartbeat`, `registered`,
  `claimed`, `nonce_resync`, `revoked`, `wg_public_key_registered`, …). The
  admin query and the report's gateway section filter on it, so a row the
  server observed is never presented as a sensor claim.

**Retention:** new job `prune_gateway_events(db, days)` in `app/jobs.py`,
registered in `app/maintenance.py`, config
`gateway_event_retention_days: int = 90`. Raw events are evidence, not the
report; the report reads them through a filtered query, so 90 days of raw rows
plus the permanent AuditLog/DeviceVisit rows are enough.

## 5. Time and ordering

| Field | Clock | Use |
|---|---|---|
| `recorded_at` | gateway | Primary ordering; shown in the report |
| `received_at` | cloud | Proof of when the cloud learned it; tie-breaker |

- If `|recorded_at − received_at| > 24 h` the row is flagged `clock_suspect`
  (freshly imaged gateway without NTP is the common cause) and the report uses
  `received_at` for display instead.
- No wall-clock sorting across the whole table in one pass: queries filter by
  gateway + time window first (indexes exist on `gateway_id`, `created_at`).

## 6. Where it surfaces

1. **Audit report** (`app/audit_report.py::build_tunnel_report`): new
   `gateway_events` section covering the session's time window — peer
   added/removed, handshakes, NAT/forwarding errors, WAN changes — explicitly
   labelled *gateway-reported (unverified)*, with `recorded_at` and
   `received_at` columns.
2. **Admin API:** `GET /admin/gateways/{gateway_id}/events?since=&until=&type=&limit=`
   (`app/routers/admin.py`, admin-only like the existing `/admin/audit`).
3. **Admin UI:** the tunnel audit view gains the events table below the sessions
   block (`app/static/admin.html`).

AuditLog stays what the *server* observed; `gateway_events` is what the
*gateway* claims. The report keeps them in separate sections so a reader can
tell which is which.

## 7. Failure modes

| Failure | Behaviour |
|---|---|
| Cloud down for an hour | Spool fills, backoff runs, heartbeat fails, gateway keeps tunneling locally; on recovery the next successful heartbeat ships the whole backlog in ≤200-row batches |
| Cloud down past the 5 MB cap | Oldest events dropped, one `spool_overflow` marker written — visible gap, not silent loss |
| Response lost after server stored the rows | Agent re-sends; `duplicates` absorbs it; nothing is lost or double-counted |
| Gateway token expired mid-backlog | Existing refresh path (`token_refreshed` event) runs first; ship is retried next iteration |
| Gateway reboot mid-append | Partial last line skipped at read; earlier lines intact |
| Gateway clock wrong | `clock_suspect` flag; report falls back to `received_at` |
| Two agents against one gateway id | Second one is rejected by bearer auth; spool is per-box anyway |
| Malicious gateway fabricating rows | Inherent to a sensor; rows are labelled unverified and never substitute for server-side auth/audit records |
| Disk full | Append fails → events dropped with a logged warning; heartbeat continues (evidence loss beats tunnel loss) |

## 8. Implementation checklist

- [x] `migrations/008_gateway_event_batch.sql` (+ baseline note in `alembic/env.py`)
- [x] `app/schemas.py`: `GatewayEventBatchIn`
- [x] `app/routers/gateways.py`: `POST /gateways/{gateway_id}/events/batch` (+ audit action `gateway.events_batch`)
- [x] `app/config.py`: `gateway_event_retention_days`, `event_batch_max_events`, `event_batch_max_bytes`
- [x] `app/jobs.py::prune_gateway_events` + registration in `app/maintenance.py`
- [x] `firmware/linux_gateway/gateway_agent.py`: `EventSpool` (append / read / trim / rotate / cap), emit points, batch ship in the loop
- [x] `app/gateway/daemon.py`: emit `peer_added`/`peer_removed`/`sync_error` from `sync_once` results
- [x] `app/audit_report.py`: `gateway_events` section; `app/routers/admin.py`: events query; `app/static/admin.html`: events table
- [x] `API.md` + `ARCHITECTURE.md` + `.env.example`
- [x] Tests (§9)
- [x] `TODO_NEXT_PHASE.md` tick

## 9. Test plan

- `tests/test_event_spool.py` — agent-side: append round-trip, skip corrupt
  line, rotation at cap, overflow marker with correct `dropped`, trim-on-ack,
  no token material ever written, single-writer rule.
- `tests/test_event_batch.py` — server-side: auth + gateway-id mismatch 403,
  dedupe by `event_id` within and across batches, 200-event and 256-KB caps
  → 422, ordering by `recorded_at`, `received_at`/`remote_ip` recorded,
  rate-limit bucket, retention job deletes only rows past `days`.
- `tests/test_event_backfill.py` — end-to-end: emit → offline (server returns
  5xx) → spool grows → server recovers → one batch lands everything → second
  batch is a no-op → audit report shows the section labelled unverified.

## 10. Non-goals

- No payload, DNS, or URL capture — `POST /me/visits` already covers the
  first-ten-sites requirement from the phone side.
- No relay storage of anything: the relay forwards UDP and nothing else.
- No push/WebSocket for events; batch POST is enough for a sensor.
- No ESP32 spool in this phase (server-side heartbeat events still land).
- No re-attempt to make gateway events tamper-proof — that would need a
  hardware root of trust; they are evidence, not authority.
