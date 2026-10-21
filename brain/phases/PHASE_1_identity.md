# PHASE 1 — Identity & Campus Hierarchy

**Goal:** the real college structure in the DB; secure login; role-based access.
**Read:** 01, 04, 05 (§1), 06 (Auth section).

## Tasks
- [ ] Migrations + models: `departments`, `classes`, `users`, `refresh_tokens`, `mpin_credentials`
- [ ] Argon2id hashing service (`crypto/kdf.py`): pepper pre-hash, tunable params, `needs_rehash`
- [ ] `POST /auth/login` with dummy-hash timing equalisation; generic `AUTH_FAILED`
- [ ] JWT access (15 min) + rotating refresh (hashed at rest, reuse detection revokes the family)
- [ ] `POST /auth/change-password`, forced when `must_change_password`
- [ ] RBAC dependency: `require_role("admin")` etc.; faculty cannot see others' balances
- [ ] Login rate limits and account lockout (password failures: 5 → 15 min lock)
- [ ] Admin CSV import (`POST /admin/import`, dry-run + commit): departments, classes, users; idempotent upsert; validates duplicates, emails, college IDs
- [ ] `scripts/seed/` with sample CSVs: 11 departments, 39 classes (17 for years 1–2, 22 for years 3–4), ~200 fake students, ~20 faculty
- [ ] Generate one-time passwords to a git-ignored local CSV
- [ ] Tests: hashing params, timing-equalisation smoke test, lockout, refresh rotation + reuse, RBAC matrix, CSV edge cases

## Phase Gate
- ☐ Seed script loads the full hierarchy; counts match (11 / 39)
- ☐ Login works; wrong password and unknown user return identical responses
- ☐ 6th wrong password in the window is locked even with the right password
- ☐ Replaying an old refresh token revokes the session family
- ☐ A student token gets 403 on every `/admin/*` route (matrix test)
- ☐ No password hash or secret appears in any API response or log
- ☐ `PROGRESS.md` updated
