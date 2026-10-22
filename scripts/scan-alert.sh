#!/bin/sh
# File a scheduled scan of main that did not pass as an issue in this repo: open one
# titled "Scheduled scan failed on main" linking the run, or comment on the one this
# workflow already opened. The ci workflow's scan-alert job runs it with gh and the
# workflow token. Only the workflow's own issues count, since anyone can open an
# issue with that title in this public repo.
set -eu
run_url=${1:?usage: scan-alert.sh <run-url>}
title="Scheduled scan failed on main"

# Assigned first so that a failed lookup stops the run before anything is filed.
open=$(gh issue list --state open --author app/github-actions --search "in:title \"$title\"" \
  --json number,title --jq ".[] | select(.title == \"$title\") | .number")
issue=$(printf '%s\n' "$open" | head -n 1)

if [ -n "$issue" ]; then
  gh issue comment "$issue" --body "The scheduled scan did not pass again: $run_url"
else
  # One quoted string per line: tests/scripts/test_pins.py reads this file line by line.
  body=$(printf '%s\n\n%s\n' "The scheduled \`scan\` job on \`main\` did not pass: $run_url" \
    "Read its log first: a new advisory also fails the \`scan\` check of any PR built on the same pins, and is fixed forward on \`main\` (a pin in \`docker/pins.txt\` or \`docker/system-pins.txt\`, or an upstream bump), while a build or runner failure may pass on a re-run. Close this issue once a scheduled scan passes.")
  gh issue create --title "$title" --body "$body"
fi
