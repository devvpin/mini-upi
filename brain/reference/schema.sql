-- Mini-UPI reference schema (PostgreSQL 16). Alembic migrations must reproduce this.
-- Simulation only: all amounts are virtual, stored as integer paise.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ───────── Campus hierarchy ─────────
CREATE TABLE departments (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL
);

CREATE TABLE classes (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_id  UUID NOT NULL REFERENCES departments(id),
  name           TEXT NOT NULL,
  year           SMALLINT NOT NULL CHECK (year BETWEEN 1 AND 4),
  division       TEXT,
  UNIQUE (department_id, year, name)
);

-- ───────── Identity ─────────
CREATE TYPE user_role   AS ENUM ('student','faculty','admin','auditor');
CREATE TYPE user_status AS ENUM ('active','frozen','disabled');

CREATE TABLE users (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role                  user_role NOT NULL,
  college_id            TEXT NOT NULL UNIQUE,
  full_name             TEXT NOT NULL,
  email                 TEXT NOT NULL UNIQUE,
  department_id         UUID REFERENCES departments(id),
  class_id              UUID REFERENCES classes(id),
  password_hash         TEXT NOT NULL,
  must_change_password  BOOLEAN NOT NULL DEFAULT TRUE,
  failed_logins         INT NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  status                user_status NOT NULL DEFAULT 'active',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (role <> 'student' OR class_id IS NOT NULL)
);

CREATE TABLE mpin_credentials (
  user_id       UUID PRIMARY KEY REFERENCES users(id),
  mpin_hash     TEXT NOT NULL,
  failed_count  INT NOT NULL DEFAULT 0,
  locked_until  TIMESTAMPTZ,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id),
  public_key_jwk  JSONB NOT NULL,
  label           TEXT,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ
);
CREATE INDEX ON devices(user_id) WHERE status = 'active';

CREATE TABLE refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id   UUID NOT NULL,
  user_id     UUID NOT NULL REFERENCES users(id),
  device_id   UUID REFERENCES devices(id),
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ
);

-- ───────── Money ─────────
CREATE TABLE bank_accounts (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID UNIQUE REFERENCES users(id),      -- NULL only for the TREASURY system account
  is_system  BOOLEAN NOT NULL DEFAULT FALSE,
  status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','frozen'))
);

CREATE TABLE wallets (
  account_id      UUID PRIMARY KEY REFERENCES bank_accounts(id),
  balance_paise   BIGINT NOT NULL DEFAULT 0,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Non-system wallets may never go negative; the treasury (system) may.
CREATE OR REPLACE FUNCTION wallet_non_negative() RETURNS trigger AS $$
BEGIN
  IF NEW.balance_paise < 0 AND NOT (SELECT is_system FROM bank_accounts WHERE id = NEW.account_id) THEN
    RAISE EXCEPTION 'negative balance not allowed';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_wallet_non_negative BEFORE INSERT OR UPDATE ON wallets
  FOR EACH ROW EXECUTE FUNCTION wallet_non_negative();

CREATE TABLE vpas (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  UUID NOT NULL REFERENCES bank_accounts(id),
  handle      TEXT NOT NULL UNIQUE,                 -- e.g. 22ce045@gcet
  is_primary  BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TYPE txn_status AS ENUM ('pending','success','failed');
CREATE TYPE txn_kind   AS ENUM ('PAY','COLLECT_SETTLE','TOPUP');

CREATE TABLE transactions (
  id                  UUID PRIMARY KEY,             -- client-supplied txn_id (idempotency key)
  kind                txn_kind NOT NULL,
  payer_account_id    UUID NOT NULL REFERENCES bank_accounts(id),
  payee_account_id    UUID NOT NULL REFERENCES bank_accounts(id),
  amount_paise        BIGINT NOT NULL CHECK (amount_paise > 0),
  note                TEXT,
  status              txn_status NOT NULL,
  failure_reason      TEXT,
  receipt_json        JSONB,
  receipt_signature   TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at        TIMESTAMPTZ,
  CHECK (payer_account_id <> payee_account_id)
);
CREATE INDEX ON transactions(payer_account_id, created_at DESC);
CREATE INDEX ON transactions(payee_account_id, created_at DESC);

CREATE TABLE ledger_entries (
  id                    BIGSERIAL PRIMARY KEY,
  txn_id                UUID NOT NULL REFERENCES transactions(id),
  account_id            UUID NOT NULL REFERENCES bank_accounts(id),
  direction             TEXT NOT NULL CHECK (direction IN ('DEBIT','CREDIT')),
  amount_paise          BIGINT NOT NULL CHECK (amount_paise > 0),
  balance_after_paise   BIGINT NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON ledger_entries(account_id, created_at DESC);

CREATE TABLE collect_requests (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_account_id  UUID NOT NULL REFERENCES bank_accounts(id),
  payer_account_id      UUID NOT NULL REFERENCES bank_accounts(id),
  amount_paise          BIGINT NOT NULL CHECK (amount_paise > 0),
  note                  TEXT,
  status                TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','declined','expired')),
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ───────── Security ─────────
CREATE TABLE used_nonces (
  nonce       TEXT PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX ON used_nonces(expires_at);

CREATE TABLE audit_log (
  seq            BIGSERIAL PRIMARY KEY,
  event_type     TEXT NOT NULL,
  txn_id         UUID,
  actor_user_id  UUID,
  payload_json   JSONB NOT NULL,                    -- never contains secrets
  prev_hash      BYTEA NOT NULL,
  entry_hash     BYTEA NOT NULL,
  entry_hmac     BYTEA NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_append_only();

CREATE TABLE pki_certificates (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject         TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('PSP','SWITCH','BANK')),
  public_key_pem  TEXT NOT NULL,
  cert_pem        TEXT NOT NULL,
  not_before      TIMESTAMPTZ NOT NULL,
  not_after       TIMESTAMPTZ NOT NULL
);
