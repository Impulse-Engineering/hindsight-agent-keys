#!/bin/sh
# Entrypoint: refuse an unsafe configuration, then run the requested command
# (by default upstream's launcher). Any command override still passes the guard.
set -eu
/app/api/.venv/bin/python -m hindsight_agent_keys.guard
exec "$@"
