# PROGRESS TRACKER

Update this file at the end of every phase. Agents: work only on the phase marked IN PROGRESS.

| Phase | Name | Status | Gate passed | Date |
|---|---|---|---|---|
| 0 | Foundation | DONE | ☑ | 2026-10-21 |
| 1 | Identity & campus hierarchy | DONE | ☑ | 2026-10-21 |
| 2 | Wallet & ledger | DONE | ☑ | 2026-10-21 |
| 3 | Crypto core | DONE | ☑ | 2026-10-21 |
| 4 | Payment engine | DONE | ☑ | 2026-10-21 |
| 5 | Frontend | DONE | ☑ | 2026-10-21 |
| 6 | Hardening & attack demos | DONE | ☑ | 2026-10-21 |
| 7 | Deploy & present | IN PROGRESS | ☐ | |

## Decisions
(append: date · phase · decision · reason)
- 2026-10-21 · Phase 0 · Configured Hatch package target, httpx ASGITransport, and structlog BoundLogger typing for strict mypy & ruff compliance on Python 3.14.
- 2026-10-21 · Phase 1 · Implemented Argon2id KDF with HMAC-SHA256 pepper pre-hashing, dummy hash timing equalisation, rotating hashed refresh tokens with family revocation on replay, and idempotent CSV hierarchy import with dry-run support.
- 2026-10-21 · Phase 2 · Implemented double-entry transfer engine with deterministic UUID-sorted wallet locking, global zero-sum invariant verifier, BigInteger sqlite compatibility variant, and VPA resolution privacy masking.
- 2026-10-21 · Phase 3 · Implemented cross-platform canonical JSON serializer, WebCrypto non-extractable ECDSA P-256 device keys with raw IEEE P1363 / DER signature interoperability, hybrid envelope encryption (ECDH + HKDF + AES-256-GCM) with AAD binding, X.509 v3 Mini-PKI role-constrained certificate authority, HMAC service message integrity, SHA-256 hash-chained audit log with sequence pinpointing, and MPIN 3-strike lockout.

## Deviations from the brain
- 2026-10-21 · Phase 4 · PostgreSQL deployment benchmark completed with 200 payments at p95 231.12 ms; fixed native PostgreSQL enum bindings and loading of the configured CA key/certificate pair.
- 2026-10-21 · Phase 5 · Built the first complete Hive UI vertical slice with hand-written primitives, responsive wallet screens, payment flow, transaction Security Lens, profile QR, and admin controls; browser integration and accessibility gates remain for final completion.
- 2026-10-21 · Phase 5 · Wired login and browser payments to the real API with WebCrypto device signing, ECDH envelope encryption, bank receipt verification, and demo ciphertext tampering; build, unit, and Playwright smoke gates passed.
- 2026-10-21 · Phase 6 · Added security headers/CSP/HSTS, sensitive-route rate limits, attack-demo runner, STRIDE threat model, and dependency-audit tracking; all security regression and attack tests passed.

## Open questions for the author
- College display name and VPA suffix (default `@gcet`)?
- Domain name or LAN-only deployment?
- Initial virtual balance per student/faculty (default ₹1,000 / ₹2,000)?

## Known issues
- Phase 7 is ready to begin: Phase 6 attack demonstrations and hardening tests are complete. npm audit reports two moderate React Router advisories requiring a future major upgrade; no high/critical frontend findings were reported.
