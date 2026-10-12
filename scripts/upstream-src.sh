#!/bin/sh
# Copy the pinned upstream hindsight_api package to .upstream/<version>/ (gitignored)
# and print its path, so readers without Docker (reviewers, sandboxes) get plain files.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ref=$("$ROOT/scripts/upstream-ref.sh")
version=${ref#*:}
version=${version%%@*}
dest=$ROOT/.upstream/$version
if [ ! -d "$dest/hindsight_api" ]; then
  mkdir -p "$ROOT/.upstream"
  tmp=$(mktemp -d "$ROOT/.upstream/.tmp.XXXXXX")
  cid=$(docker create "$ref")
  trap 'docker rm "$cid" >/dev/null; rm -rf "$tmp"' EXIT
  docker cp "$cid:/app/api/hindsight_api" "$tmp/hindsight_api"
  mv "$tmp" "$dest"
fi
printf '%s\n' "$dest/hindsight_api"
