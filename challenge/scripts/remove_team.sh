#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yaml"

# Manager DB — override with MANAGER_DB env var if layout differs
MANAGER_DB="${MANAGER_DB:-$(dirname "$PROJECT_DIR")/manager/data/manager.db}"

TEAM="${1:-}"

if [[ -z "$TEAM" ]]; then
    echo "Usage: $0 <team_name>"
    exit 1
fi

PROJECT_NAME="ctf_${TEAM}"

echo "Removing instance for team '$TEAM'..."

docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    down -v

echo "Team '$TEAM' Docker instance removed."

# ── Manager DB cleanup ───────────────────────────────────────────────────────
if [[ -f "$MANAGER_DB" ]] && command -v sqlite3 &>/dev/null; then
    sqlite3 "$MANAGER_DB" \
        "DELETE FROM hint_purchases WHERE team_name='${TEAM}';
         DELETE FROM submissions   WHERE team_name='${TEAM}';
         DELETE FROM teams         WHERE name='${TEAM}';"
    echo "Team '$TEAM' removed from manager DB."
else
    echo "Warning: manager DB not found or sqlite3 unavailable — manager DB unchanged."
fi
