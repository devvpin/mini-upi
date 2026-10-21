# PHASE 0 — Foundation

**Goal:** a running skeleton: containers up, DB migrated, health endpoints, test harness green.
**Read:** 02, 03, 08.

## Tasks
- [ ] Create repo layout from `03_ARCHITECTURE.md` (empty module packages with docstring headers)
- [ ] `docker-compose.yml` (db, api, web, caddy) from `brain/reference/docker-compose.yml`
- [ ] `.env.example` from `brain/reference/env.example`; config loader with Pydantic Settings (fail fast on missing secrets)
- [ ] Backend: `pyproject.toml` (pin deps), FastAPI app factory, `/health`, `/ready`
- [ ] Async SQLAlchemy engine/session, Alembic initialised, migration `0001_baseline` applies `reference/schema.sql` objects (or equivalent models)
- [ ] Structured logging with `request_id` middleware; secret-scrubbing log filter
- [ ] Tooling: `ruff`, `mypy`, `pytest`, pre-commit config, `Makefile` (`make up`, `make test`, `make lint`, `make migrate`)
- [ ] Web: Vite + React + TS scaffold, route stub, tokens.css + base.css from `07_UI_DESIGN_SYSTEM.md` (no components yet)
- [ ] README with a 5-command quickstart

## Phase Gate
- ☐ `make up` brings the stack up; `GET /health` → 200; `GET /ready` → 200 only when DB reachable
- ☐ `make migrate` applies cleanly on an empty DB and is repeatable
- ☐ `make test` and `make lint` pass
- ☐ App refuses to start if `PEPPER`, `JWT_SECRET`, or `AUDIT_HMAC_KEY` are missing
- ☐ Logs show `request_id`; a test proves a fake secret is scrubbed from logs
- ☐ `PROGRESS.md` updated
