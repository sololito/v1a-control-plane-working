# Security (production)
- bcrypt passwords (min 10), SHA256-hashed pairing codes / refresh / session tokens. No plaintext secrets, no secret logging.
- JWT with `jti`: access 15m, refresh 30d rotation, gateway 60m, session 60m. Expired -> 401 distinct. Refresh reuse revokes device (theft detection).
- Login lockout: 5 fails / 15 min per email+IP -> 429. Register/login/refresh rate-limited per IP (Redis sliding-window, in-memory fallback fail-open).
- Pairing: 6-digit code hashed, 15m TTL, max 5 attempts -> 429. ID alone cannot claim. Entitlement caps gateways per plan.
- Gateway heartbeat: optional monotonic `nonce` rejects replays (409). Full Ed25519 challenge-response is next (M-Pesa hardening deferred with it).
- AuthN vs AuthZ server-side: ownership + active subscription + online + session-cap checks on every connection. Session token verify endpoint for gateways.
- Validation: Pydantic allowlists (device_type, algorithm, connection_path), length caps, msisdn normalize, UUID checks.
- Audit: register/login/fail/claim/heartbeat-replay/connections/revokes/billing in audit_logs + request-ID logs. CORS locked (explicit origins when not `*`), security headers (nosniff/DENY/HSTS), 500s hide stacks with request_id.
- TLS at proxy; secrets via env; `SECRET_KEY>=32` enforced in prod. Callback/IP-allowlist is part of M-Pesa hardening (later).
