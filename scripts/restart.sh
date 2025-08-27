#!/usr/bin/env bash
touch server.log
docker compose -f docker-compose.dev.yml down
docker compose -f docker-compose.dev.yml up -d --build --force-recreate
docker compose -f docker-compose.dev.yml exec -it backend python3 manage.py makemigrations
docker compose -f docker-compose.dev.yml exec -it backend python3 manage.py migrate --noinput
docker compose -f docker-compose.dev.yml exec -it backend python3 manage.py collectstatic --noinput
