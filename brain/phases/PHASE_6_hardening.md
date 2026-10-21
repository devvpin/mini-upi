# PHASE 6 — Hardening & Attack Demos

**Goal:** prove the security claims with runnable attacks and close the gaps they reveal.
**Read:** 05, 06 (headers, limits).

## Attack demo scripts (`backend/security_tests/`, each prints PASS = "attack blocked")
- [ ] `replay_attack.py` — capture a valid pay request, resend it → `REPLAY_DETECTED`
- [ ] `tamper_attack.py` — flip one ciphertext bit / change amount after signing → `ENVELOPE_INVALID` / `SIGNATURE_INVALID`
- [ ] `stolen_token_attack.py` — valid JWT, attacker's own key → `DEVICE_NOT_BOUND`
- [ ] `mpin_bruteforce.py` — 10⁶ MPIN guesses → locked after 3, timing flat
- [ ] `forged_receipt_attack.py` — fake "success" receipt → client verification fails
- [ ] `rogue_psp_attack.py` — message signed by an uncertified key / wrong role → Switch rejects
- [ ] `audit_tamper_attack.py` — edit a ledger/audit row in Postgres → `/audit/verify` pinpoints `seq`
- [ ] `directory_scrape_attack.py` — enumerate VPAs → rate limited
- [ ] `timing_oracle_check.py` — compare login timings for known vs unknown user

## Hardening tasks
- [ ] Security headers + strict CSP; CORS locked to the web origin
- [ ] Rate limits as specified in `06`; limits tested
- [ ] Dependency audit (`pip-audit`, `npm audit`), pinned versions
- [ ] Input validation review (Pydantic strict types, length caps, UUID parsing)
- [ ] SQL injection review (parameterised only) and a negative test
- [ ] Secrets review: nothing sensitive in logs, errors, or git history
- [ ] Optional light theme + final a11y pass
- [ ] Threat-model document `docs/threat_model.md` (STRIDE table: asset, threat, control, test)

## Phase Gate
- ☐ All attack scripts report "blocked" and are wired into `make attacks`
- ☐ `pip-audit` and `npm audit` show no high/critical issues (or documented exceptions)
- ☐ Threat model covers every row of the mapping table in `05`
- ☐ Rate-limit tests pass
- ☐ `PROGRESS.md` updated
