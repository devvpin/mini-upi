"""0001_baseline — Create all tables from reference schema.

Revision ID: 0001
Revises: None
Create Date: 2026-10-21

Applies the reference schema (brain/reference/schema.sql) as the baseline
migration for Mini-UPI. All tables, enums, constraints, triggers, and
indexes from the spec are created here.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UPGRADE_SQL = """
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
DO $$ BEGIN
  CREATE TYPE user_role   AS ENUM ('student','faculty','admin','auditor');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE user_status AS ENUM ('active','frozen','disabled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

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
  user_id    UUID UNIQUE REFERENCES users(id),
  is_system  BOOLEAN NOT NULL DEFAULT FALSE,
  status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','frozen'))
);

CREATE TABLE wallets (
  account_id      UUID PRIMARY KEY REFERENCES bank_accounts(id),
  balance_paise   BIGINT NOT NULL DEFAULT 0,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
  handle      TEXT NOT NULL UNIQUE,
  is_primary  BOOLEAN NOT NULL DEFAULT TRUE
);

DO $$ BEGIN
  CREATE TYPE txn_status AS ENUM ('pending','success','failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE txn_kind   AS ENUM ('PAY','COLLECT_SETTLE','TOPUP');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE transactions (
  id                  UUID PRIMARY KEY,
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
  payload_json   JSONB NOT NULL,
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
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS pki_certificates CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS used_nonces CASCADE;
DROP TABLE IF EXISTS collect_requests CASCADE;
DROP TABLE IF EXISTS ledger_entries CASCADE;
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS vpas CASCADE;
DROP TABLE IF EXISTS wallets CASCADE;
DROP TABLE IF EXISTS bank_accounts CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS mpin_credentials CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS classes CASCADE;
DROP TABLE IF EXISTS departments CASCADE;
DROP TYPE IF EXISTS txn_kind CASCADE;
DROP TYPE IF EXISTS txn_status CASCADE;
DROP TYPE IF EXISTS user_status CASCADE;
DROP TYPE IF EXISTS user_role CASCADE;
DROP FUNCTION IF EXISTS wallet_non_negative CASCADE;
DROP FUNCTION IF EXISTS audit_append_only CASCADE;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
