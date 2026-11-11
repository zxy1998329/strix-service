#!/bin/sh
set -eu
umask 077
case "${1:-all}" in
  all) exec python launcher.py ;;
  api) exec uvicorn service:app --host 0.0.0.0 --port 8080 --no-access-log ;;
  worker) exec python worker.py ;;
  *) exec "$@" ;;
esac
