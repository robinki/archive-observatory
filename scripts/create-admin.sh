#!/usr/bin/env bash
docker compose -f docker-compose.dev.yml exec -it backend python manage.py createsuperuser
