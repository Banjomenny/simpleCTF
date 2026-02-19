#!/bin/bash

# Stop and remove all team stacks
if [ ! -d "teams" ]; then
  echo "No teams found."
  exit 0
fi

for TEAM_FILE in teams/team*.yml; do
  TEAM_NAME=$(basename $TEAM_FILE .yml | sed 's/team//')
  echo "🗑 Removing Team $TEAM_NAME..."
  docker compose -p team${TEAM_NAME} -f docker-compose.yml -f $TEAM_FILE down -v
done

# Remove all override files
rm -f teams/team*.yaml

echo "✅ All teams removed."
