#!/usr/bin/env bash
set -euo pipefail

backup_dir="${BACKUP_DIR:-./backups}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
docker compose exec -T db pg_dump -U miniupi -d miniupi --format=custom > "$backup_dir/miniupi-$timestamp.dump"
chmod 600 "$backup_dir/miniupi-$timestamp.dump"
echo "Created $backup_dir/miniupi-$timestamp.dump"
