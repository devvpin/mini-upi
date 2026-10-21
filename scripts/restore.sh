#!/usr/bin/env bash
set -euo pipefail

dump="${1:?Usage: scripts/restore.sh backups/miniupi-<timestamp>.dump}"
test -f "$dump"
cat "$dump" | docker compose exec -T db pg_restore -U miniupi -d miniupi --clean --if-exists --no-owner
echo "Restored $dump"
