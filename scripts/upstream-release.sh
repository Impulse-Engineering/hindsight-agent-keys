#!/bin/sh
# Propose the latest upstream Hindsight release as a PR that bumps the pinned
# FROM line. The upstream-release workflow runs it daily on a checkout of main,
# with gh, git and docker and the workflow's own token.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
UPSTREAM=vectorize-io/hindsight
cd "$ROOT"

# GitHub's latest release is never a draft or a pre-release.
# shortcut: a release overtaken by a newer one before the next run gets no PR;
# list all releases if upstream starts publishing backports.
release=$(gh api "repos/$UPSTREAM/releases/latest" --jq '.tag_name + " " + .html_url')
tag=${release%% *}
notes_url=${release#* }
# Only an exact vX.Y.Z release becomes an image tag, so a floating tag
# (latest, 0.10) or a -slim variant is never followed.
version=$(printf '%s\n' "$tag" | sed -n 's/^v\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\)$/\1/p')
if [ -z "$version" ]; then
  echo "upstream-release: the latest release tag '$tag' is not vX.Y.Z" >&2
  exit 1
fi

old=$(scripts/upstream-ref.sh)
pinned=${old#*:}
pinned=${pinned%%@*}
if [ "$(printf '%s\n%s\n' "$pinned" "$version" | sort -V | tail -n 1)" = "$pinned" ]; then
  echo "upstream-release: the pin $pinned is current (latest release $version)"
  exit 0
fi

branch="upstream/hindsight-$version"
# Closing the PR declines the release; reopening it takes it up again.
# Assigned first so that a failed lookup stops the run.
prs=$(gh pr list --head "$branch" --state all --json number --jq '.[].number')
if [ -n "$prs" ]; then
  echo "upstream-release: a PR for $version already exists"
  exit 0
fi

digest=$(docker buildx imagetools inspect "ghcr.io/$UPSTREAM:$version" --format '{{.Manifest.Digest}}')
new="ghcr.io/$UPSTREAM:$version@$digest"
git switch --quiet -C "$branch"
sed "s|^FROM $old AS base\$|FROM $new AS base|" Dockerfile > Dockerfile.new
mv Dockerfile.new Dockerfile
# upstream-ref.sh accepts only one well-formed tag@digest pin.
if [ "$(scripts/upstream-ref.sh)" != "$new" ]; then
  echo "upstream-release: could not pin $new" >&2
  exit 1
fi

title="chore: bump upstream Hindsight to $version"
git commit --quiet -m "$title" -m "Release notes: $notes_url" -- Dockerfile
# A branch left by a run that failed before opening its PR is replaced.
git push --quiet --force origin "$branch"
gh pr create --base main --head "$branch" --title "$title" --body "Pins \`$new\`.

Release notes: $notes_url

GitHub holds CI on a PR opened by the workflow token: a maintainer starts it with **Approve workflows to run**. Nothing merges automatically. Merge once CI passes; CI on main then publishes a signed \`$version-ak.<run>\` image."
