#!/usr/bin/env bash
touch server.log
docker compose -f docker-compose.dev.yml down
docker compose -f docker-compose.dev.yml up -d --build --force-recreate
docker exec -it $(docker ps --filter name=observatory-artifact-backend -aq) python3 manage.py makemigrations
docker exec -it $(docker ps --filter name=observatory-artifact-backend -aq) python3 manage.py migrate --noinput
docker exec -it $(docker ps --filter name=observatory-artifact-backend -aq) python3 manage.py collectstatic --noinput
