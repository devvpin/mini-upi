# PROGRESS TRACKER

Update this file at the end of every phase. Agents: work only on the phase marked IN PROGRESS.

| Phase | Name | Status | Gate passed | Date |
|---|---|---|---|---|
| 0 | Foundation | DONE | ☑ | 2026-10-21 |
| 1 | Identity & campus hierarchy | DONE | ☑ | 2026-10-21 |
| 2 | Wallet & ledger | DONE | ☑ | 2026-10-21 |
| 3 | Crypto core | DONE | ☑ | 2026-10-21 |
| 4 | Payment engine | IN PROGRESS | ☐ | |
| 5 | Frontend | NOT STARTED | ☐ | |
| 6 | Hardening & attack demos | NOT STARTED | ☐ | |
| 7 | Deploy & present | NOT STARTED | ☐ | |

## Decisions
(append: date · phase · decision · reason)
- 2026-10-21 · Phase 0 · Configured Hatch package target, httpx ASGITransport, and structlog BoundLogger typing for strict mypy & ruff compliance on Python 3.14.
- 2026-10-21 · Phase 1 · Implemented Argon2id KDF with HMAC-SHA256 pepper pre-hashing, dummy hash timing equalisation, rotating hashed refresh tokens with family revocation on replay, and idempotent CSV hierarchy import with dry-run support.
- 2026-10-21 · Phase 2 · Implemented double-entry transfer engine with deterministic UUID-sorted wallet locking, global zero-sum invariant verifier, BigInteger sqlite compatibility variant, and VPA resolution privacy masking.
- 2026-10-21 · Phase 3 · Implemented cross-platform canonical JSON serializer, WebCrypto non-extractable ECDSA P-256 device keys with raw IEEE P1363 / DER signature interoperability, hybrid envelope encryption (ECDH + HKDF + AES-256-GCM) with AAD binding, X.509 v3 Mini-PKI role-constrained certificate authority, HMAC service message integrity, SHA-256 hash-chained audit log with sequence pinpointing, and MPIN 3-strike lockout.

## Deviations from the brain
- 2026-10-21 · Phase 4 · Functional payment gate and a 200-request benchmark passed in-process with SQLite (p95 65.4 ms), but the required 2-vCPU PostgreSQL deployment benchmark could not run because local Compose secrets and database configuration are not provisioned.

## Open questions for the author
- College display name and VPA suffix (default `@gcet`)?
- Domain name or LAN-only deployment?
- Initial virtual balance per student/faculty (default ₹1,000 / ₹2,000)?

## Known issues
- Phase 4 deployment-specific load gate remains pending: run 200 simulated payments against the PostgreSQL Compose stack and record p95 < 800 ms before marking Phase 4 DONE.
