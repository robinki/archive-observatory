#!/usr/bin/env bash
docker compose -f docker-compose.dev.yml exec -it backend python3 manage.py collectstatic --noinput
