"""Runs scripts/upstream-release.sh in a scratch repository with fake gh and docker on PATH.

The fakes stand in for GitHub and GHCR and record every call. The fake gh runs
each call's --jq expression through jq, as gh does. git is real and pushes to a
local bare remote, so the tests read what was actually pushed.
"""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IMAGE = "ghcr.io/vectorize-io/hindsight"
PINNED = f"{IMAGE}:0.10.3@sha256:{'b' * 64}"
DIGEST = f"sha256:{'a' * 64}"
DOCKERFILE = f"FROM {PINNED}\n\nCOPY hindsight_agent_keys /app/extensions/hindsight_agent_keys\n"
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Answers only the calls the watcher should make; anything else fails the run.
FAKE_GH = """#!/bin/sh
echo "gh $*" >> "$CALLS"
case "$1 $2" in
  "api repos/vectorize-io/hindsight/releases/latest") json=$RELEASE_JSON ;;
  "pr list") json=$PRS_JSON; [ "$PR_LIST_STATUS" = 0 ] || exit 1 ;;
  "pr create") echo "https://example.invalid/pull/1"; exit 0 ;;
  *) echo "fake gh: unexpected call: $*" >&2; exit 2 ;;
esac
while [ "$#" -gt 2 ]; do shift; done
[ "$1" = --jq ] || { echo "fake gh: the call does not end in --jq <expr>" >&2; exit 2; }
printf '%s' "$json" | jq -r "$2"
"""
FAKE_DOCKER = """#!/bin/sh
echo "docker $*" >> "$CALLS"
echo "$DIGEST"
"""


def git(*args, cwd):
    env = {**os.environ, **GIT_ENV}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "work"
    (work / "scripts").mkdir(parents=True)
    (work / "Dockerfile").write_text(DOCKERFILE)
    for name in ("upstream-ref.sh", "upstream-release.sh"):
        shutil.copy2(os.path.join(ROOT, "scripts", name), work / "scripts" / name)
    git("init", "--quiet", "--bare", str(tmp_path / "remote.git"), cwd=tmp_path)
    git("init", "--quiet", "-b", "main", cwd=work)
    git("add", ".", cwd=work)
    git("commit", "--quiet", "-m", "base", cwd=work)
    git("remote", "add", "origin", str(tmp_path / "remote.git"), cwd=work)
    git("push", "--quiet", "origin", "main", cwd=work)
    (tmp_path / "bin").mkdir()
    for name, body in (("gh", FAKE_GH), ("docker", FAKE_DOCKER)):
        (tmp_path / "bin" / name).write_text(body)
        (tmp_path / "bin" / name).chmod(0o755)
    return work


def notes(tag):
    return f"https://github.com/vectorize-io/hindsight/releases/tag/{tag}"


def run(repo, tag, prs="[]", pr_list_status="0"):
    calls = repo.parent / "calls"
    env = {
        **os.environ,
        **GIT_ENV,
        "PATH": f"{repo.parent / 'bin'}:{os.environ['PATH']}",
        "CALLS": str(calls),
        "RELEASE_JSON": json.dumps(
            {"tag_name": tag, "name": f"Hindsight {tag}", "html_url": notes(tag), "draft": False, "prerelease": False}
        ),
        "PRS_JSON": prs,
        "PR_LIST_STATUS": pr_list_status,
        "DIGEST": DIGEST,
    }
    result = subprocess.run(
        [str(repo / "scripts" / "upstream-release.sh")], cwd=repo, env=env, capture_output=True, text=True, check=False
    )
    return result, calls.read_text() if calls.exists() else ""


def pushed(repo):
    """Each branch on the remote, mapped to its Dockerfile."""
    remote = str(repo.parent / "remote.git")
    heads = git("for-each-ref", "--format=%(refname:short)", "refs/heads", cwd=remote).split()
    return {head: git("show", f"{head}:Dockerfile", cwd=remote) for head in heads}


@pytest.mark.parametrize("version", ["0.10.4", "0.10.10"])
def test_a_new_release_is_proposed_as_one_pr_pinning_its_exact_tag_and_digest(repo, version):
    result, calls = run(repo, f"v{version}")

    assert result.returncode == 0, result.stderr
    assert f"docker buildx imagetools inspect {IMAGE}:{version} --format {{{{.Manifest.Digest}}}}\n" in calls
    new = f"{IMAGE}:{version}@{DIGEST}"
    assert pushed(repo) == {
        "main": DOCKERFILE,
        f"upstream/hindsight-{version}": DOCKERFILE.replace(PINNED, new),
    }
    assert calls.count("gh pr create") == 1
    assert f"--base main --head upstream/hindsight-{version}" in calls
    assert notes(f"v{version}") in calls
    assert new in calls
    assert "gh pr merge" not in calls


@pytest.mark.parametrize("version", ["0.10.3", "0.10.2", "0.9.10"])
def test_nothing_happens_when_the_pin_is_current_or_newer(repo, version):
    result, calls = run(repo, f"v{version}")

    assert result.returncode == 0, result.stderr
    assert "docker" not in calls and "gh pr" not in calls
    assert pushed(repo) == {"main": DOCKERFILE}


def test_nothing_happens_when_a_pr_for_the_release_exists(repo):
    result, calls = run(repo, "v0.10.4", prs='[{"number": 42}]')

    assert result.returncode == 0, result.stderr
    assert "gh pr list --head upstream/hindsight-0.10.4 --state all" in calls
    assert "docker" not in calls and "gh pr create" not in calls
    assert pushed(repo) == {"main": DOCKERFILE}


def test_a_failed_pr_lookup_stops_the_run_before_anything_is_pushed(repo):
    result, calls = run(repo, "v0.10.4", pr_list_status="1")

    assert result.returncode != 0
    assert "docker" not in calls and "gh pr create" not in calls
    assert pushed(repo) == {"main": DOCKERFILE}


def test_a_branch_left_without_a_pr_is_replaced(repo):
    git("push", "--quiet", "origin", "main:upstream/hindsight-0.10.4", cwd=repo)
    git("commit", "--quiet", "--allow-empty", "-m", "left by a failed run", cwd=repo)
    git("push", "--quiet", "--force", "origin", "main:upstream/hindsight-0.10.4", cwd=repo)
    git("reset", "--quiet", "--hard", "origin/main", cwd=repo)

    result, calls = run(repo, "v0.10.4")

    assert result.returncode == 0, result.stderr
    assert pushed(repo)["upstream/hindsight-0.10.4"] == DOCKERFILE.replace(PINNED, f"{IMAGE}:0.10.4@{DIGEST}")
    assert calls.count("gh pr create") == 1


@pytest.mark.parametrize("tag", ["latest", "v0.11", "v0.10.4-slim", "v0.11.0-rc.1", "0.10.4"])
def test_a_release_tag_that_is_not_an_exact_version_is_never_followed(repo, tag):
    result, calls = run(repo, tag)

    assert result.returncode == 1
    assert f"the latest release tag '{tag}' is not vX.Y.Z" in result.stderr
    assert "docker" not in calls and "gh pr" not in calls
    assert pushed(repo) == {"main": DOCKERFILE}
