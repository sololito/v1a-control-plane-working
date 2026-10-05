-- 002: M-Pesa-ready billing stubs (Safaricom Daraja). V1 free untouched.
CREATE TABLE IF NOT EXISTS payment_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
  provider VARCHAR(40) NOT NULL DEFAULT 'mpesa-daraja',
  plan VARCHAR(40) NOT NULL DEFAULT 'personal',
  amount INTEGER NOT NULL DEFAULT 0,
  currency VARCHAR(10) NOT NULL DEFAULT 'KES',
  phone_msisdn VARCHAR(20) NOT NULL DEFAULT '',
  checkout_request_id VARCHAR(80) UNIQUE,
  merchant_request_id VARCHAR(80),
  mpesa_receipt VARCHAR(40),
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  result_code INTEGER,
  result_desc VARCHAR(255),
  raw_callback JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_payment_user ON payment_transactions(user_id, status);
