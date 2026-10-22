#!/bin/sh
# Run every linter CI runs, so a local run matches CI exactly: ruff from PATH,
# then shellcheck, then actionlint as a digest-pinned container.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ACTIONLINT=rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 # v1.7.12
cd "$ROOT"
ruff check .
shellcheck -s sh scripts/*.sh docker/agent-keys-start.sh
shellcheck -s bash docker/ui-start.sh
docker run --rm -v "$ROOT:/repo:ro" -w /repo "$ACTIONLINT" -color=false
