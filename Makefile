# Mini-UPI Makefile
# Usage: make up | make test | make lint | make migrate

.PHONY: up down test lint migrate format logs attacks backup loadtest

# ── Docker ──────────────────────────────────────────────────────────────────
up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

# ── Database ────────────────────────────────────────────────────────────────
migrate:
	docker compose exec api alembic upgrade head

migrate-local:
	cd backend && alembic upgrade head

# ── Testing ─────────────────────────────────────────────────────────────────
test:
	cd backend && python -m pytest tests/ -v --tb=short

test-docker:
	docker compose exec api python -m pytest tests/ -v --tb=short

attacks:
	cd backend && python -m pytest tests/test_phase3.py tests/test_phase4.py tests/test_phase6.py -v --tb=short

backup:
	./scripts/backup.sh

loadtest:
	python scripts/loadtest/load_health.py

# ── Linting ─────────────────────────────────────────────────────────────────
lint:
	cd backend && python -m ruff check app/ tests/
	cd backend && python -m mypy app/core/ --ignore-missing-imports

format:
	cd backend && python -m ruff format app/ tests/

# ── Combined ────────────────────────────────────────────────────────────────
check: lint test
