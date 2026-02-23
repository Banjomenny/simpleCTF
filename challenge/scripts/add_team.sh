#!/usr/bin/env bash
set -euo pipefail

# Resolve the project directory (one level up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yaml"

# Manager DB — override with MANAGER_DB env var if layout differs
MANAGER_DB="${MANAGER_DB:-$(dirname "$PROJECT_DIR")/manager/data/manager.db}"

TEAM="${1:-}"
PORT="${2:-}"
TEAM_PASSWORD="${3:-}"   # optional; generated if omitted

usage() {
    echo "Usage: $0 <team_name> [port] [password]"
    echo "  team_name  alphanumeric, hyphens, underscores (e.g. alpha, team-01)"
    echo "  port       host port to bind (default: auto-assigned from 8000)"
    echo "  password   manager login password (default: auto-generated)"
    exit 1
}

[[ -z "$TEAM" ]] && usage

if ! [[ "$TEAM" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: team name must contain only letters, numbers, hyphens, or underscores."
    exit 1
fi

PROJECT_NAME="ctf_${TEAM}"

# Check if this team is already running
if docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" ps --quiet 2>/dev/null | grep -q .; then
    echo "Error: team '$TEAM' already exists. Use remove_team.sh to tear it down first."
    exit 1
fi

# Auto-assign port if not provided
if [[ -z "$PORT" ]]; then
    PORT=8000
    while docker ps --format '{{.Ports}}' 2>/dev/null | grep -q "0\.0\.0\.0:${PORT}->"; do
        PORT=$((PORT + 1))
    done
    echo "Auto-assigned port: $PORT"
fi

echo "Starting instance for team '$TEAM' on port $PORT..."

PORT="$PORT" docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    up --build -d

echo ""
echo "Team '$TEAM' is up."
echo "  URL : http://localhost:$PORT"
echo "  Stop: scripts/remove_team.sh $TEAM"

# ── Manager DB registration ──────────────────────────────────────────────────
# Generate a password if none was supplied
if [[ -z "$TEAM_PASSWORD" ]]; then
    TEAM_PASSWORD="$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12 || true)"
    # Fallback if openssl unavailable
    [[ -z "$TEAM_PASSWORD" ]] && TEAM_PASSWORD="changeme_${TEAM}"
fi

if ! [[ -f "$MANAGER_DB" ]]; then
    echo ""
    echo "  Warning: manager DB not found at $MANAGER_DB"
    echo "  Team '$TEAM' was NOT registered in the manager."
    echo "  Start the manager first, or set MANAGER_DB to the correct path."
    exit 0
fi

if ! command -v python3 &>/dev/null || ! python3 -c "import bcrypt" 2>/dev/null; then
    echo ""
    echo "  Warning: python3+bcrypt not available — skipping manager registration."
    exit 0
fi

if ! command -v sqlite3 &>/dev/null; then
    echo ""
    echo "  Warning: sqlite3 not found — skipping manager registration."
    exit 0
fi

# Hash password via bcrypt (use env var to avoid shell quoting issues)
PW_HASH="$(BCRYPT_PW="$TEAM_PASSWORD" python3 -c \
    "import bcrypt, os; print(bcrypt.hashpw(os.environ['BCRYPT_PW'].encode(), bcrypt.gensalt()).decode())")"

sqlite3 "$MANAGER_DB" \
    "INSERT OR REPLACE INTO teams (name, password_hash, port, status)
     VALUES ('${TEAM}', '${PW_HASH}', ${PORT}, 'ready');"

echo ""
echo "  Manager: team registered."
echo "  Login  : team='${TEAM}'  password='${TEAM_PASSWORD}'"
