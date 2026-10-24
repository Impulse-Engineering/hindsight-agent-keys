#!/bin/sh
# Fail when a pin the image installs over upstream is at or below the version the pinned
# upstream image (the Dockerfile's FROM, never the built image, which carries the pins)
# already has in that pin file's interpreter: the exact pin would downgrade the package or
# change nothing. Prints one line per such pin, naming both versions. An absent pin file,
# or a pin for a package upstream does not install, passes. CI's test job runs it on every
# PR and push to main; it needs Docker and a python3 with packaging (requirements-ci.txt).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=$("$ROOT/scripts/upstream-ref.sh")

# Run in upstream's interpreter: "<name> <version>" for every package it can import.
LIST='import importlib.metadata as m
for d in m.distributions(): print(d.metadata["Name"], d.version)'

# Run on the host: compares the pin file in argv with that listing on stdin, by PEP 440
# ordering and PEP 503 names. Reads only the form uv pip compile writes, failing on any other.
COMPARE='import re, sys
from packaging.utils import canonicalize_name
from packaging.version import Version
path, name = sys.argv[1:]
upstream = {}
for line in filter(str.strip, sys.stdin):
    dist, version = line.split()
    upstream.setdefault(canonicalize_name(dist), version)
if not upstream:
    sys.exit(f"pins-above-upstream: {name}: upstream listed no packages")
low = 0
with open(path) as f:
    for n, line in enumerate(f, 1):
        text = line.strip()
        if not text or text.startswith(("#", "--hash=")):
            continue
        pin = re.fullmatch(r"([A-Za-z0-9._-]+)==(\S+?)(?: \\)?", text)
        if not pin:
            sys.exit(f"pins-above-upstream: {name}:{n}: not a name==version pin: {text}")
        have = upstream.get(canonicalize_name(pin[1]))
        if have is not None and Version(pin[2]) <= Version(have):
            print(f"pins-above-upstream: {name}: {pin[1]}=={pin[2]} is at or below upstream {have}; drop the pin", file=sys.stderr)
            low = 1
sys.exit(low)'

status=0
# check <pin file> <the --python its Dockerfile install line names>
check() {
  if [ ! -f "$ROOT/$1" ]; then
    echo "pins-above-upstream: $1: absent, nothing to check"
    return 0
  fi
  listing=$(docker run --rm --entrypoint "$2" "$BASE" -c "$LIST")
  if printf '%s\n' "$listing" | python3 -c "$COMPARE" "$ROOT/$1" "$1"; then
    echo "pins-above-upstream: $1: every pin is above upstream"
  else
    status=1
  fi
}
check docker/pins.txt /app/api/.venv/bin/python
check docker/system-pins.txt /usr/local/bin/python3
exit "$status"
