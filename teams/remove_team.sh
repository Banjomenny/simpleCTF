#!/bin/bash

TEAM_ID=$1

if [ -z "$TEAM_ID" ]; then
  echo "Usage: ./remove_team.sh <team_number>"
  exit 1
fi

TEAM_FILE="teams/team${TEAM_ID}.yml"

if [ ! -f "$TEAM_FILE" ]; then
  echo "Team $TEAM_ID does not exist."
  exit 1
fi

docker compose -p team${TEAM_ID} -f docker-compose.yml -f $TEAM_FILE down -v

rm $TEAM_FILE

echo "🗑️ Team $TEAM_ID removed completely"
