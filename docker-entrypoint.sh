#!/bin/sh
# Patch bind address so the container is reachable from the host.
# The app binds to 127.0.0.1 by default (security: localhost-only).
# Inside Docker, we need 0.0.0.0 for port-forwarding to work.
sed -i 's/"127.0.0.1"/"0.0.0.0"/g' /app/cloudhop/cli.py

exec python -m cloudhop --browser "$@"
