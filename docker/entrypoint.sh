#!/bin/sh
# Container entrypoint: `web` (migrations + gunicorn) or `scheduler`.
set -eu
umask 077

for dir in /app/data /app/keys; do
  if [ ! -w "$dir" ]; then
    echo "ERROR: $dir is not writable by uid $(id -u). On the host run: sudo chown -R $(id -u):$(id -g) ./data ./keys" >&2
    exit 1
  fi
done
mkdir -p /app/data/db /app/data/backups /app/data/logs /app/data/tmp /app/data/certs

case "${1:-web}" in
  web)
    flask db upgrade
    flask init-app
    if [ "${TLS_ENABLED:-true}" = "true" ]; then
      flask gen-cert
    fi
    exec gunicorn -c gunicorn.conf.py run:app
    ;;
  scheduler)
    exec python scheduler.py
    ;;
  *)
    exec "$@"
    ;;
esac
