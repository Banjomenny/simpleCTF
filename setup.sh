#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== simpleCTF Setup Wizard ==="
echo ""
echo "Which CTF would you like to run?"
echo "  1) BankingAI CTF  (PHP, MySQL, 5 flags)"
echo "  2) SWO CTF Task-1 (Python Flask, 3 flags)"
read -rp "Choice [1/2]: " CTF_CHOICE

read -rp "HOST_IP (IP or hostname players connect to): " HOST_IP
read -rp "PORT_RANGE_START [8000]: " PORT_START
PORT_START="${PORT_START:-8000}"

SECRET_KEY=$(openssl rand -hex 16)
ADMIN_TOKEN=$(openssl rand -hex 16)
FLAG_SECRET=$(openssl rand -hex 16)

if [[ "$CTF_CHOICE" == "2" ]]; then
    CTF_COMPOSE_HOST_PATH="../task-1/docker-compose.yml"
    CTF_CHALLENGE_DIR="$REPO_DIR/task-1"
    CTF_CONFIG_FILE="/ctf/config/task1.json"
    CTF_NAME="SWOCTS — Task 1"
    WEB_SERVICE_NAME="web"
    STARTUP_TIMEOUT="30"
    GHCR_IMAGE="ghcr.io/banjomenny/simplectf/task1-web:latest"
    LOCAL_TAG="task-1-web:latest"
else
    CTF_COMPOSE_HOST_PATH="../challenge/docker-compose.yaml"
    CTF_CHALLENGE_DIR="$REPO_DIR/challenge"
    CTF_CONFIG_FILE="/ctf/config/bankingai.json"
    CTF_NAME="BankingAI CTF"
    WEB_SERVICE_NAME="web"
    STARTUP_TIMEOUT="180"
    GHCR_IMAGE="ghcr.io/banjomenny/simplectf/bankingai-web:latest"
    LOCAL_TAG="ctf-web:latest"
fi

echo ""
echo "Pulling challenge image from ghcr.io..."
docker pull "$GHCR_IMAGE"
docker tag "$GHCR_IMAGE" "$LOCAL_TAG"
echo "Tagged $GHCR_IMAGE → $LOCAL_TAG"

cat > "$REPO_DIR/manager/.env" <<EOF
SECRET_KEY=$SECRET_KEY
ADMIN_TOKEN=$ADMIN_TOKEN
FLAG_SECRET=$FLAG_SECRET
HOST_IP=$HOST_IP
PORT_RANGE_START=$PORT_START
CTF_COMPOSE_HOST_PATH=$CTF_COMPOSE_HOST_PATH
CTF_CHALLENGE_DIR=$CTF_CHALLENGE_DIR
CTF_CONFIG_FILE=$CTF_CONFIG_FILE
CTF_NAME=$CTF_NAME
WEB_SERVICE_NAME=$WEB_SERVICE_NAME
STARTUP_TIMEOUT=$STARTUP_TIMEOUT
EOF

echo ""
echo "=== Setup complete! ==="
echo "manager/.env written."
echo ""
echo "Start the manager:"
echo "  cd $REPO_DIR/manager && docker compose up -d"
echo ""
echo "Admin panel: http://$HOST_IP (token: $ADMIN_TOKEN)"
