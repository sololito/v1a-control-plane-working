# M-Pesa Daraja — sandbox creds, callback URL, live flip

Live path now delegates to your working `scripts/mpesa_service.py` via
`app/mpesa_adapter.py`, gated by `BILLING_LIVE`. Stubs run by default so V1
free is untouched. Your vendor file is never edited — the adapter bridges it.

## 1. Get sandbox creds (https://developer.safaricom.co.ke)
1. Create account, create App, enable `M-Pesa Express (STK-Push)` + `OAuth`.
2. Copy: Consumer Key, Consumer Secret.
3. Sandbox defaults (test): Shortcode `174379`, Passkey = sandbox passkey shown on Daraja
   “M-Pesa Express Simulate” page. Test phone `254708374149` (Daraja sandbox).
4. Never commit these — put only in local `.env`.

## 2. Public callback URL (Daraja must reach you)
- Sandbox can use ngrok: `ngrok http 8000` -> `https://<id>.ngrok.io/api/v1/billing/mpesa/callback`
- Set `MPESA_CALLBACK_URL` to that HTTPS URL. Must be public HTTPS (no localhost).
- Prod: real domain + IP-allowlist/callback auth (TODO).

## 3. `.env` for live sandbox
```ini
BILLING_LIVE=true
MPESA_ENV=sandbox
MPESA_CONSUMER_KEY=<from daraja>
MPESA_CONSUMER_SECRET=<from daraja>
MPESA_SHORTCODE=174379
MPESA_PASSKEY=<sandbox passkey>
MPESA_CALLBACK_URL=https://<you>/api/v1/billing/mpesa/callback
MPESA_ACCOUNT_REF=ODIVORA
```

## 4. Flip + verify
1. `docker compose up --build` or `uvicorn app.main:app` restart.
2. `GET /api/v1/billing/plans` -> pick `personal`.
3. `POST /api/v1/me/billing/mpesa/initiate {"plan":"personal","phone":"0712345678"}`
   -> real STK push to phone, `checkout_request_id` = `ws_CO_...`.
4. Approve on phone (PIN `1234` on sandbox test phone).
5. Daraja POSTs to callback -> tx `success`, new paid Subscription, audit `billing.callback`.
6. `GET /api/v1/me/subscription` shows paid plan. Duplicate callbacks return “duplicate ignored”.

## 5. Prod checklist
- `MPESA_ENV=production`, real Lipa-na-M-Pesa shortcode + production passkey.
- Restrict `/billing/mpesa/callback` by Safaricom IPs (`MPESA_CALLBACK_ALLOWED_IPS`) + TLS everywhere. Origin is enforced in `app/routers/billing.py` via the vendor allowlist (empty in prod = structural + CheckoutRequestID check, per vendor).
- Reconcile with C2B/query API; add B2C refunds as needed.

## 6. Vendor wiring notes (your scripts/)
- `mpesa_service.py` — WIRED via `app/mpesa_adapter.py` (OAuth token cache, STK push, strict KE phone check, callback validate/parse/state, origin allowlist). Env bridged: `MPESA_ENV`->`MPESA_ENVIRONMENT`, `MPESA_ACCOUNT_REF`->`MPESA_ACCOUNT_REFERENCE`, Daraja URL trio derived from env when empty. Keep `requests` in requirements.
- `mpesa_reconciliation.py` — NOT wired: imports Flask (`..models`, `..user.routes.mpesa`, app-context worker) and a different `MpesaPayment` model (verification_data/expires_at/mark_*). Port path: rewrite `reconcile_expired_payment`/`sweep_expired_payments` against our `PaymentTransaction` + `verify_transaction`, run from `POST /admin/jobs/sweep` instead of a Flask thread.
- `purchase_email_service.py` — NOT wired: needs Flask + `monetization.email_system` package (absent here) and serves digital-product purchases, not gateway subscriptions. Port path: vendor a FastAPI SMTP sender or queue table, then call it from callback success.
- `subscription_service.py` — NOT wired: PayPal + `SingleToolSubscription` (TTS/STT tools product), different model from gateway `Subscription`/entitlements. No change needed for wifi_gateway MVP.
