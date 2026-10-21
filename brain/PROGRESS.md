# PROGRESS TRACKER

Update this file at the end of every phase. Agents: work only on the phase marked IN PROGRESS.

| Phase | Name | Status | Gate passed | Date |
|---|---|---|---|---|
| 0 | Foundation | DONE | ☑ | 2026-10-21 |
| 1 | Identity & campus hierarchy | DONE | ☑ | 2026-10-21 |
| 2 | Wallet & ledger | IN PROGRESS | ☐ | |
| 3 | Crypto core | NOT STARTED | ☐ | |
| 4 | Payment engine | NOT STARTED | ☐ | |
| 5 | Frontend | NOT STARTED | ☐ | |
| 6 | Hardening & attack demos | NOT STARTED | ☐ | |
| 7 | Deploy & present | NOT STARTED | ☐ | |

## Decisions
(append: date · phase · decision · reason)
- 2026-10-21 · Phase 0 · Configured Hatch package target, httpx ASGITransport, and structlog BoundLogger typing for strict mypy & ruff compliance on Python 3.14.
- 2026-10-21 · Phase 1 · Implemented Argon2id KDF with HMAC-SHA256 pepper pre-hashing, dummy hash timing equalisation, rotating hashed refresh tokens with family revocation on replay, and idempotent CSV hierarchy import with dry-run support.

## Deviations from the brain
(append: what differs and why)

## Open questions for the author
- College display name and VPA suffix (default `@gcet`)?
- Domain name or LAN-only deployment?
- Initial virtual balance per student/faculty (default ₹1,000 / ₹2,000)?

## Known issues
(none yet)
