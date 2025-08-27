#!/usr/bin/env bash
docker exec -it $(docker ps --filter name=observatory-artifact-backend -aq) python manage.py createsuperuser
