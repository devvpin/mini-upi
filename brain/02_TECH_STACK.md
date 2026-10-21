# 02 — Tech Stack and Why

Chosen for the author's existing skills (Python, FastAPI, PostgreSQL, JavaScript) so the project
stays explainable and defensible in a viva.

## Backend
- **FastAPI + Pydantic v2**: typed request/response models, automatic OpenAPI docs for the demo.
- **SQLAlchemy 2.0 async + asyncpg**: explicit transactions, `SELECT … FOR UPDATE` for balances.
- **Alembic**: every schema change is a migration; never edit the DB by hand.
- **argon2-cffi**: Argon2id for password and MPIN hashing.
- **cryptography**: ECDSA/ECDH (P-256), AES-256-GCM, HKDF, HMAC, X.509 for the mini-CA.
- **PyJWT**: short-lived access tokens (15 min) + rotating refresh tokens stored hashed.
- **slowapi** (or a tiny Postgres-backed limiter): rate limiting.
- **structlog**: JSON logs, never log secrets, MPINs, private keys, or full tokens.

## Database
- **PostgreSQL 16**. Money as `BIGINT` paise. Constraints enforce invariants (balance ≥ 0, unique nonce).
- No Redis in v1 (fewer moving parts). Nonce replay table lives in Postgres with a TTL cleanup job.

## Frontend
- **React 18 + TypeScript + Vite**.
- **Hand-written CSS** with CSS variables and CSS modules. No component kit, no template.
- **React Router**, **TanStack Query** (data fetching), **zod** (form validation).
- **WebCrypto API** for all browser-side crypto. Private keys are generated `extractable: false`
  and stored in IndexedDB as `CryptoKey` objects (never exported, never in localStorage).
- **qrcode** + a small QR scanner (camera) library for QR pay.
- Icons: `lucide-react` (allowed utility).

## Infra
- **Docker Compose**: `db`, `api`, `web`, `caddy`.
- **Caddy**: automatic HTTPS (use a self-signed/local CA on a campus LAN if no public domain).
- **Backups**: nightly `pg_dump` to a mounted volume; verify restore once.

## Testing
- `pytest` + `pytest-asyncio` for API and services.
- `hypothesis` property tests for ledger invariants (sum of balances constant, never negative).
- Dedicated `security_tests/` folder: replay, tamper, brute force, token-without-device.
- Playwright: one happy-path smoke test (login → bind device → pay → see history).

## Why not the alternatives
| Option | Why not |
|---|---|
| Flutter | Great, but WebCrypto + browser demo is easier to project in a seminar room |
| Node/Express | Author is stronger in FastAPI; Python crypto libs are the reference-quality choice |
| MongoDB | Ledger needs ACID multi-row transactions and constraints |
| Microservices | Overkill. Use a **modular monolith** with hard module boundaries that talk through the same
signed/encrypted message layer as if they were separate services (see `03_ARCHITECTURE.md`) |

## Versions (pin in lockfiles)
Python 3.12 · Node 20 LTS · PostgreSQL 16 · FastAPI latest stable · React 18
