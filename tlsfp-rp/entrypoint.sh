#!/bin/sh

# its running inside docker, so host is 0.0.0.0
python3 proxy.py --key /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem --cert /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem --host 0.0.0.0 --http-port 80 --https-port 443 --domain ${DOMAIN_NAME} --upstream-host nginx --upstream-port 80

exec "$@"
