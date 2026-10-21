# 04 — Database Schema

Authoritative DDL lives in `brain/reference/schema.sql`. Alembic migrations must produce the same result.

## Conventions
- UUID primary keys (`gen_random_uuid()`), `created_at timestamptz default now()`.
- Money: `BIGINT` paise. Never floats.
- Soft state via `status` columns; no hard deletes of financial rows.
- All foreign keys are explicit; all uniqueness is enforced by the database.

## Tables

### Campus hierarchy
- `departments(id, code UNIQUE, name)` — 11 rows
- `classes(id, department_id → departments, name, year smallint 1..4, division)` — 39 rows (17 + 22)

### Identity
- `users(id, role, college_id UNIQUE, full_name, email UNIQUE, department_id, class_id NULL for faculty,
  password_hash, must_change_password, status, created_at)`
- `devices(id, user_id, public_key_jwk, label, status, created_at, revoked_at)` — ECDSA P-256 public key
- `refresh_tokens(id, user_id, token_hash, device_id, expires_at, revoked_at)`
- `mpin_credentials(user_id PK, mpin_hash, failed_count, locked_until, updated_at)`

### Money
- `bank_accounts(id, user_id UNIQUE, status)` — one simulated account per user, plus `TREASURY` system account
- `wallets(account_id PK, balance_paise BIGINT CHECK >= 0 (except treasury), updated_at)`
- `vpas(id, account_id, handle UNIQUE, is_primary)` — e.g. `22ce045@gcet`
- `transactions(id = txn_id, payer_account_id, payee_account_id, amount_paise CHECK > 0, note, status,
  kind ['PAY','COLLECT_SETTLE','TOPUP'], created_at, completed_at)`
- `ledger_entries(id, txn_id, account_id, direction ['DEBIT','CREDIT'], amount_paise, balance_after_paise, created_at)`
- `collect_requests(id, requester_account_id, payer_account_id, amount_paise, note, status, expires_at)`

### Security
- `used_nonces(nonce PK, user_id, expires_at)` — replay protection, periodic cleanup
- `audit_log(seq BIGSERIAL PK, event_type, txn_id NULL, actor_user_id NULL, payload_json,
  prev_hash, entry_hash, entry_hmac, created_at)` — hash chain; **append-only** (trigger blocks UPDATE/DELETE)
- `pki_certificates(id, subject, role ['PSP','SWITCH','BANK'], public_key_pem, cert_pem, not_before, not_after)`

## Key invariants (enforce with constraints/tests)
1. `SUM(wallet balances incl. treasury offset)` is constant across all payments.
   Model: treasury starts at `-minted`; sum of every wallet balance = 0 at all times.
2. Every transaction has exactly one DEBIT and one CREDIT entry of equal amount.
3. `balance_after_paise` on ledger rows replays correctly from zero.
4. `audit_log` chain verifies from `seq = 1` to head.
5. A `nonce` is accepted at most once.

## Indexes
- `ledger_entries(account_id, created_at DESC)` for history
- `transactions(payer_account_id, created_at DESC)`, `transactions(payee_account_id, created_at DESC)`
- `vpas(handle)` unique, `users(college_id)` unique, `used_nonces(expires_at)`

## Seed expectations
- 11 departments, 39 classes, ~2,700 students, ~180 faculty, 2–3 admins.
- Seeder is idempotent and reads CSV (`scripts/seed/*.csv`); generates one-time passwords, writes them
  to a **local-only** `one_time_credentials.csv` that is git-ignored.
