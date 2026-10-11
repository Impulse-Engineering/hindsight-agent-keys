#!/bin/sh
# Print the pinned upstream Hindsight image reference (tag@digest) from the Dockerfile.
# The one place that parses the pin; CI and the tests call it.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ref=$(sed -n 's/^FROM \(ghcr\.io\/vectorize-io\/hindsight:[0-9][0-9.]*@sha256:[0-9a-f]\{64\}\)$/\1/p' "$ROOT/Dockerfile")
count=$(printf '%s' "$ref" | grep -c . || true)
if [ "$count" -ne 1 ]; then
  echo "upstream-ref: expected one 'FROM ghcr.io/vectorize-io/hindsight:<version>@sha256:<digest>' line in Dockerfile, found $count" >&2
  exit 1
fi
printf '%s\n' "$ref"
