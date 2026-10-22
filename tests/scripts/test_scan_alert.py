"""Runs scripts/scan-alert.sh with a fake gh on PATH.

The fake records each call's full argument list and runs a list call's --jq
expression through jq, as gh does (CODING_STANDARDS.md, rule 6).
"""

import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TITLE = "Scheduled scan failed on main"
RUN_URL = "https://github.com/o/r/actions/runs/123"

FAKE_GH = """#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps(args) + "\\n")
if args[:2] == ["issue", "list"]:
    if os.environ.get("LIST_FAILS"):
        sys.exit(1)
    if args[-2] != "--jq":
        sys.exit("fake gh: the list call does not end in --jq <expr>")
    issues = json.loads(os.environ["ISSUES_JSON"])
    if "--author" in args:  # as GitHub filters by author before gh applies --jq
        issues = [i for i in issues if i["author"] == args[args.index("--author") + 1]]
    out = subprocess.run(["jq", "-r", args[-1]], input=json.dumps(issues),
                         capture_output=True, text=True, check=True).stdout
    sys.stdout.write(out)
elif args[:2] not in (["issue", "create"], ["issue", "comment"]):
    sys.exit(f"fake gh: unexpected call: {args}")
"""

BOT = "app/github-actions"
LIST = ["issue", "list", "--state", "open", "--author", BOT, "--search", f'in:title "{TITLE}"', "--json", "number,title",
        "--jq"]


def issue(number, title, author=BOT):
    return {"number": number, "title": title, "author": author}


@pytest.fixture
def gh(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(FAKE_GH)
    (bin_dir / "gh").chmod(0o755)
    return tmp_path


def run(gh, issues=None, list_fails=False):
    calls = gh / "calls"
    env = {
        **os.environ,
        "PATH": f"{gh / 'bin'}:{os.environ['PATH']}",
        "CALLS": str(calls),
        "ISSUES_JSON": json.dumps(issues or []),
    }
    if list_fails:
        env["LIST_FAILS"] = "1"
    result = subprocess.run(
        [os.path.join(ROOT, "scripts", "scan-alert.sh"), RUN_URL], env=env, capture_output=True, text=True, check=False
    )
    recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    return result, recorded


def assert_created(calls):
    assert calls[0][:-1] == LIST
    assert len(calls) == 2 and len(calls[1]) == 6
    assert calls[1][:5] == ["issue", "create", "--title", TITLE, "--body"]
    assert RUN_URL in calls[1][5]


def test_with_no_open_issue_it_opens_one_linking_the_run(gh):
    result, calls = run(gh, [issue(7, f"{TITLE} (old)")])
    assert result.returncode == 0, result.stderr
    assert_created(calls)


def test_with_an_open_issue_it_comments_on_it(gh):
    result, calls = run(gh, [issue(7, f"{TITLE} (old)"), issue(12, TITLE)])
    assert result.returncode == 0, result.stderr
    assert calls[1] == ["issue", "comment", "12", "--body", f"The scheduled scan did not pass again: {RUN_URL}"]
    assert len(calls) == 2


def test_an_issue_with_the_title_from_anyone_else_is_ignored(gh):
    result, calls = run(gh, [issue(5, TITLE, author="mallory")])
    assert result.returncode == 0, result.stderr
    assert_created(calls)


def test_a_failed_lookup_files_nothing_and_fails(gh):
    result, calls = run(gh, list_fails=True)
    assert result.returncode != 0
    assert [c[:2] for c in calls] == [["issue", "list"]]
