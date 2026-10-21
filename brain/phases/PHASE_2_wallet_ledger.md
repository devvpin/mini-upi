# PHASE 2 — Wallet & Ledger

**Goal:** correct, atomic virtual money with a provable double-entry ledger.
**Read:** 03 (Bank), 04 (Money, invariants).

## Tasks
- [ ] Migrations + models: `bank_accounts`, `wallets`, `vpas`, `transactions`, `ledger_entries`
- [ ] `TREASURY` system account (allowed negative); one account + wallet + primary VPA per user (`<college_id>@gcet`, suffix from env)
- [ ] `bank/ledger.py`: `post_transfer(txn_id, from, to, amount)`
  - one DB transaction; lock both wallets `FOR UPDATE` ordered by account id (no deadlocks)
  - check balance ≥ amount, status active, amount > 0
  - write DEBIT + CREDIT rows with `balance_after_paise`
  - idempotent on `txn_id`
- [ ] Admin top-up: `POST /admin/topup` (treasury → user), audited, reason required
- [ ] `GET /wallet`, `GET /transactions` (cursor pagination), `GET /vpa/resolve`, `GET /vpa/me`
- [ ] Limits service (per-transaction, daily) read from config
- [ ] Ledger verifier: recomputes balances from entries and checks the global zero-sum invariant
- [ ] Tests: hypothesis property tests (random transfers keep sum = 0, no negative balances), concurrency test (100 parallel transfers on the same wallet), idempotency, freeze behaviour

## Phase Gate
- ☐ 100 concurrent transfers → no overdraft, no deadlock, totals consistent
- ☐ Repeating a `txn_id` never double-posts
- ☐ Ledger verifier returns OK after a randomized 10,000-transfer run
- ☐ Resolving VPAs is rate limited and returns only a masked name
- ☐ Faculty/students cannot read other users' balances
- ☐ `PROGRESS.md` updated
