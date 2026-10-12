#!/bin/sh
# Copy the pinned upstream hindsight_api package to .upstream/<version>-<digest prefix>/
# (gitignored) and print its path, so readers without Docker (reviewers, sandboxes)
# get plain files. A pin bump, even digest-only, gets a fresh directory.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ref=$("$ROOT/scripts/upstream-ref.sh")
version=${ref#*:}
version=${version%%@*}
digest=$(printf '%s' "${ref##*sha256:}" | cut -c1-12)
dest=$ROOT/.upstream/$version-$digest
if [ ! -d "$dest/hindsight_api" ]; then
  mkdir -p "$ROOT/.upstream"
  tmp=$(mktemp -d "$ROOT/.upstream/.tmp.XXXXXX")
  cid=
  trap 'if [ -n "$cid" ]; then docker rm "$cid" >/dev/null 2>&1 || true; fi; rm -rf "$tmp"' EXIT
  cid=$(docker create "$ref")
  docker cp "$cid:/app/api/hindsight_api" "$tmp/hindsight_api"
  rm -rf "$dest"   # a leftover without hindsight_api/ is incomplete
  mv "$tmp" "$dest"
fi
[ -d "$dest/hindsight_api" ]
printf '%s\n' "$dest/hindsight_api"
