#!/bin/bash

# Usage: ./deploy_teams.sh <number_of_teams> [starting_port]
NUM_TEAMS=$1
START_PORT=${2:-8101}

if [ -z "$NUM_TEAMS" ]; then
  echo "Usage: ./deploy_teams.sh <number_of_teams> [starting_port]"
  exit 1
fi

mkdir -p teams

for i in $(seq 1 $NUM_TEAMS); do
  PORT=$((START_PORT + i - 1))
  TEAM_FILE="teams/team${i}.yml"

  if [ -f "$TEAM_FILE" ]; then
    echo "Team $i already exists, skipping..."
    continue
  fi

  cat > $TEAM_FILE <<EOF
services:
  web:
    container_name: team${i}_web
    ports:
      - "${PORT}:80"
    networks:
      - team${i}_net

  db:
    container_name: team${i}_db
    volumes:
      - team${i}_db_data:/var/lib/mysql
    networks:
      - team${i}_net

networks:
  team${i}_net:

volumes:
  team${i}_db_data:
EOF

  echo "✅ Deploying Team $i on port $PORT"
  docker compose -p team${i} -f docker-compose.yaml -f $TEAM_FILE up -d
done

echo "🎯 Deployment complete!"
