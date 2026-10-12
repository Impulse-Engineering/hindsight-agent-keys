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
# .ref holds the full tag@digest and a fingerprint of every package file, written
# last; a copy whose files no longer match it (edited, deleted, partial) is rebuilt.
fingerprint() { (cd "$1" && find hindsight_api -type f -exec cksum {} + | LC_ALL=C sort | cksum); }
if [ "$(cat "$dest/.ref" 2>/dev/null)" != "$ref $(fingerprint "$dest" 2>/dev/null)" ]; then
  mkdir -p "$ROOT/.upstream"
  tmp=$(mktemp -d "$ROOT/.upstream/.tmp.XXXXXX")
  cid=
  trap 'if [ -n "$cid" ]; then docker rm "$cid" >/dev/null 2>&1 || true; fi; rm -rf "$tmp"' EXIT
  cid=$(docker create "$ref")
  docker cp "$cid:/app/api/hindsight_api" "$tmp/hindsight_api"
  printf '%s %s\n' "$ref" "$(fingerprint "$tmp")" > "$tmp/.ref"
  rm -rf "$dest"   # incomplete or stale
  mv "$tmp" "$dest"
fi
printf '%s\n' "$dest/hindsight_api"
