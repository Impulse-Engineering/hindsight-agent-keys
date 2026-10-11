#!/bin/sh
# Run the unit tests inside the pinned upstream image, which ships
# hindsight_api, pytest and pytest-asyncio. Extra args go to pytest.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=$("$ROOT/scripts/upstream-ref.sh")
exec docker run --rm \
  -v "$ROOT:/src:ro" -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint /app/api/.venv/bin/python "$BASE" \
  -m pytest -p no:cacheprovider "$@"
