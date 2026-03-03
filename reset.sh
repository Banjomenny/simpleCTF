#!/usr/bin/env bash
# reset.sh — wipe all team state, pull latest code + images, restart manager.
#
# Use this between test runs when changes have been pushed to GitHub.
#
# What it does:
#   1. Stops and removes all ctf_* team containers
#   2. Removes all ctf_* volumes (wipes team DBs)
#   3. Removes any stale ctf_* networks
#   4. Deletes manager/data/ (wipes SQLite DB — registrations + scores)
#   5. git pull (latest code)
#   6. Pulls the active challenge image from GHCR (falls back to local build)
#   7. Rebuilds + restarts the manager container
#
# Usage (from anywhere):
#   bash /path/to/ctf/reset.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$REPO_DIR/manager/.env"

echo ""
echo "========================================"
echo "  simpleCTF — Reset & Update"
echo "========================================"
echo ""
echo "This will wipe ALL team instances, registrations, and scores,"
echo "pull the latest code from GitHub, and restart the manager."
read -rp "Continue? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi
echo ""

# ── 1. Stop and remove all team containers (not the manager itself) ───────────
echo "[1/7] Stopping and removing team containers..."
CONTAINERS=$(docker ps -a --filter "name=ctf_" --format "{{.Names}}" \
             | grep -v "^ctf_manager$" || true)
if [[ -n "$CONTAINERS" ]]; then
    echo "$CONTAINERS" | xargs docker rm -f
    echo "      Removed $(echo "$CONTAINERS" | wc -l) container(s)."
else
    echo "      No team containers found."
fi

# ── 2. Remove all ctf_* volumes ───────────────────────────────────────────────
echo "[2/7] Removing ctf_* volumes..."
VOLUMES=$(docker volume ls --filter "name=ctf_" --format "{{.Name}}" || true)
if [[ -n "$VOLUMES" ]]; then
    echo "$VOLUMES" | xargs docker volume rm
    echo "      Removed $(echo "$VOLUMES" | wc -l) volume(s)."
else
    echo "      No volumes found."
fi

# ── 3. Remove stale ctf_* networks ────────────────────────────────────────────
echo "[3/7] Removing stale ctf_* networks..."
NETWORKS=$(docker network ls --filter "name=ctf_" --format "{{.ID}}" || true)
if [[ -n "$NETWORKS" ]]; then
    echo "$NETWORKS" | xargs docker network rm 2>/dev/null || true
    echo "      Networks removed."
else
    echo "      No stale networks found."
fi

# ── 4. Wipe manager database ──────────────────────────────────────────────────
echo "[4/7] Wiping manager database (registrations + scores)..."
rm -rf "$REPO_DIR/manager/data/"
mkdir -p "$REPO_DIR/manager/data"
echo "      Done."

# ── 5. Pull latest code ───────────────────────────────────────────────────────
echo "[5/7] Pulling latest code from GitHub..."
git -C "$REPO_DIR" pull
echo "      Done."

# ── 6. Pull latest challenge image from GHCR (fall back to local build) ───────
# Determine which challenge is active from manager/.env (CTF_CONFIG_FILE).
# Falls back to BankingAI if .env is missing or the variable isn't set.
echo "[6/7] Updating challenge image..."
CTF_CONFIG_FILE_VAL=""
if [[ -f "$ENV_FILE" ]]; then
    CTF_CONFIG_FILE_VAL=$(grep -E "^CTF_CONFIG_FILE=" "$ENV_FILE" | cut -d= -f2- | tr -d '"' || true)
fi

if [[ "$CTF_CONFIG_FILE_VAL" == *"task1"* ]]; then
    GHCR_IMAGE="ghcr.io/banjomenny/simplectf/task1-web:latest"
    LOCAL_TAG="task-1-web:latest"
    BUILD_COMPOSE="$REPO_DIR/task-1/docker-compose.yml"
    BUILD_DIR="$REPO_DIR/task-1"
    IS_TASK1=true
else
    GHCR_IMAGE="ghcr.io/banjomenny/simplectf/bankingai-web:latest"
    LOCAL_TAG="ctf-web:latest"
    BUILD_COMPOSE="$REPO_DIR/challenge/docker-compose.yaml"
    BUILD_DIR="$REPO_DIR/challenge"
    IS_TASK1=false
fi

if docker pull "$GHCR_IMAGE" 2>/dev/null; then
    docker tag "$GHCR_IMAGE" "$LOCAL_TAG"
    echo "      Tagged $GHCR_IMAGE → $LOCAL_TAG"
else
    echo "      GHCR pull failed — building locally from $BUILD_DIR..."
    if [[ "$IS_TASK1" == true ]]; then
        echo "      Generating task-1 artifacts (requires Pillow + piexif)..."
        pip3 install --quiet Pillow piexif
        python3 "$BUILD_DIR/generate_artifacts.py"
    fi
    docker compose -f "$BUILD_COMPOSE" --project-directory "$BUILD_DIR" build
    echo "      Built $LOCAL_TAG locally."
fi

# ── 7. Rebuild + restart manager ──────────────────────────────────────────────
echo "[7/7] Rebuilding and restarting manager..."
docker compose -f "$REPO_DIR/manager/docker-compose.yaml" \
               --project-directory "$REPO_DIR/manager" \
               up --build -d
echo "      Done."

echo ""
echo "========================================"
echo "  Reset complete!"
echo "  All teams wiped. Manager is running."
echo "  Players can now re-register."
echo "========================================"
echo ""
