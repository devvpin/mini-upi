#!/usr/bin/env bash
set -e

echo "================================================================"
echo "          Mini-UPI — Codespaces Automated Setup                 "
echo "================================================================"

# 1. Ensure secrets directory exists
mkdir -p secrets

# 2. Ensure .env exists with strong random secrets
if [ ! -f .env ]; then
  echo "[1/4] Generating fresh .env with cryptographic secrets..."
  cp .env.example .env

  PEPPER=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  AUDIT_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  SWITCH_BANK_MAC_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
  DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

  sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=${DB_PASSWORD}|" .env
  sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://miniupi:${DB_PASSWORD}@db:5432/miniupi|" .env
  sed -i "s|^PEPPER=.*|PEPPER=${PEPPER}|" .env
  sed -i "s|^JWT_SECRET=.*|JWT_SECRET=${JWT_SECRET}|" .env
  sed -i "s|^AUDIT_HMAC_KEY=.*|AUDIT_HMAC_KEY=${AUDIT_HMAC_KEY}|" .env
  sed -i "s|^SWITCH_BANK_MAC_KEY=.*|SWITCH_BANK_MAC_KEY=${SWITCH_BANK_MAC_KEY}|" .env
  echo "      .env successfully created."
else
  echo "[1/4] .env already exists. Checking for missing secrets..."
fi

if [ "$1" = "--init-only" ]; then
  echo "Init complete. Run 'make up && make migrate && make seed' to start."
  exit 0
fi

# 3. Launch Docker containers
echo "[2/4] Starting containers (PostgreSQL, FastAPI, Web UI, Caddy)..."
docker compose up -d --build

# 4. Run database migrations
echo "[3/4] Running database migrations (Alembic)..."
docker compose exec -T api alembic upgrade head

# 5. Seed test data
echo "[4/4] Seeding campus hierarchy and initial accounts..."
docker compose exec -T api python -m scripts.seed.seed_database

echo ""
echo "================================================================"
echo "    Mini-UPI is LIVE and READY in GitHub Codespaces!           "
echo "================================================================"
echo "  Access the App:"
echo "    - Open the 'PORTS' tab in the bottom panel."
echo "    - Click the Globe icon for Port 80 (or open the forwarded URL)."
echo "    - Note: GitHub Codespaces provides HTTPS automatically!"
echo ""
echo "  Demo Accounts:"
echo "    Admin:   admin01@gcet.edu    | Password: AdminPassword@123"
echo "    Faculty: fac_cp_01@gcet.edu  | Password: FacultyPassword@123"
echo "    Student: 22cp010@gcet.edu    | Password: StudentPassword@123"
echo ""
echo "  Useful Commands:"
echo "    make attacks-docker   -> Run crypto attack test suite"
echo "    make logs             -> View real-time container logs"
echo "    make down             -> Stop all containers"
echo "================================================================"
