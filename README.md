# Mini-UPI — Secure Campus Payment Simulation

> **Simulation only.** All money is virtual campus points. No real payments are processed.

A UPI-style payment simulation for a university campus (~3,000 users), built as a
project for the **Information Network Security (Cryptography)** course. Every transaction
demonstrates a specific cryptographic mechanism: ECDSA signatures, ECDH key exchange,
AES-GCM encryption, hash-chained audit logs, and more.

## Tech Stack

| Layer     | Technology                                                    |
|-----------|---------------------------------------------------------------|
| Backend   | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic         |
| Database  | PostgreSQL 16                                                 |
| Crypto    | `cryptography`, `argon2-cffi` (server), WebCrypto API (client)|
| Frontend  | React 18, TypeScript, Vite, hand-written CSS                  |
| Infra     | Docker Compose, Caddy (auto-HTTPS)                            |

## Quick Start (5 commands)

```bash
# 1. Clone and enter the project
git clone <repo-url> && cd mini-upi

# 2. Create .env from example and fill in secrets
cp .env.example .env
# Edit .env: generate secrets with:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

# 3. Start the full stack
make up

# 4. Run database migrations
make migrate

# 5. Verify everything works
curl http://localhost/health     # → {"status":"ok"}
curl http://localhost/ready      # → {"status":"ready","db":"ok"}
```

## Development

```bash
# Run tests
make test

# Run linter
make lint

# View logs
make logs
```

## Project Structure

```
mini-upi/
├─ brain/           # Specifications, phases, progress tracking
├─ backend/         # FastAPI + SQLAlchemy + crypto modules
│  ├─ app/
│  │  ├─ core/      # config, database, logging, errors
│  │  ├─ identity/  # users, auth, RBAC, devices
│  │  ├─ psp/       # payment service provider
│  │  ├─ switch/    # NPCI-like routing
│  │  ├─ bank/      # ledger, wallets, receipts
│  │  ├─ crypto/    # pure crypto functions
│  │  ├─ messaging/ # signed inter-module messages
│  │  ├─ audit/     # hash-chained audit log
│  │  └─ admin/     # CSV import, top-up, freeze
│  ├─ alembic/      # database migrations
│  └─ tests/
├─ web/             # React + TypeScript + Vite
│  └─ src/
│     ├─ design/    # tokens.css, base.css
│     ├─ crypto/    # WebCrypto wrappers
│     ├─ components/# hand-written UI primitives
│     └─ features/  # auth, wallet, pay, etc.
├─ docker-compose.yml
├─ Caddyfile
├─ Makefile
└─ scripts/         # seed data, backup, load test
```

## Phases

| # | Phase                        | Status       |
|---|------------------------------|--------------|
| 0 | Foundation                   | ✅ Complete   |
| 1 | Identity & campus hierarchy  | Not started  |
| 2 | Wallet & ledger              | Not started  |
| 3 | Crypto core                  | Not started  |
| 4 | Payment engine               | Not started  |
| 5 | Frontend                     | Not started  |
| 6 | Hardening & attack demos     | Not started  |
| 7 | Deploy & present             | Not started  |

## License

University project — not for production use.
