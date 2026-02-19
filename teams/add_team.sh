#!/bin/bash

TEAM_ID=$1

if [ -z "$TEAM_ID" ]; then
  echo "Usage: ./add_team.sh <team_number>"
  exit 1
fi

PORT=$((8100 + TEAM_ID))
TEAM_FILE="teams/team${TEAM_ID}.yml"

if [ -f "$TEAM_FILE" ]; then
  echo "Team $TEAM_ID already exists."
  exit 1
fi

cat > $TEAM_FILE <<EOF
services:
  web:
    container_name: team${TEAM_ID}_web
    ports:
      - "${PORT}:80"
    networks:
      - team${TEAM_ID}_net

  db:
    container_name: team${TEAM_ID}_db
    volumes:
      - team${TEAM_ID}_db_data:/var/lib/mysql
    networks:
      - team${TEAM_ID}_net

networks:
  team${TEAM_ID}_net:

volumes:
  team${TEAM_ID}_db_data:
EOF

docker compose -p team${TEAM_ID} -f docker-compose.yaml -f $TEAM_FILE up -d

echo "✅ Team $TEAM_ID started on port $PORT"
