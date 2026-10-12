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
if [ -L "$ROOT/.upstream" ]; then
  echo "upstream-src: .upstream is a symlink; refusing to write or delete through it" >&2
  exit 1
fi
# .ref holds the full tag@digest and is written last, so only a complete copy has it.
if [ "$(cat "$dest/.ref" 2>/dev/null)" != "$ref" ]; then
  mkdir -p "$ROOT/.upstream"
  tmp=$(mktemp -d "$ROOT/.upstream/.tmp.XXXXXX")
  cid=
  trap 'if [ -n "$cid" ]; then docker rm "$cid" >/dev/null 2>&1 || true; fi; rm -rf "$tmp"' EXIT
  cid=$(docker create "$ref")
  docker cp "$cid:/app/api/hindsight_api" "$tmp/hindsight_api"
  printf '%s\n' "$ref" > "$tmp/.ref"
  rm -rf "$dest"   # incomplete or stale
  mv "$tmp" "$dest"
fi
printf '%s\n' "$dest/hindsight_api"
