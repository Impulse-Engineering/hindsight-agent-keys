"""Runs scripts/pins-above-upstream.sh in a scratch copy of the repository with a fake docker on PATH.

The fake answers only the call the check makes, `docker run --rm --entrypoint <python> <pinned upstream> -c
<program>`, and runs that program with the host's Python over fake installed packages for that interpreter, so
the script reads what the program prints, as it would from upstream's image (CODING_STANDARDS.md, rule 6).
"""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PINNED = f"ghcr.io/vectorize-io/hindsight:1.1.0@sha256:{'b' * 64}"
VENV = "/app/api/.venv/bin/python"
SYSTEM = "/usr/local/bin/python3"

FAKE_DOCKER = """#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps(args) + "\\n")
if os.environ.get("DOCKER_FAILS"):
    sys.exit("fake docker: pull access denied")
if len(args) != 7 or args[:3] != ["run", "--rm", "--entrypoint"] or args[5] != "-c":
    sys.exit(f"fake docker: unexpected call: {args}")
if args[4] != os.environ["PINNED"]:
    sys.exit(f"fake docker: not the pinned upstream image: {args[4]}")
site = json.loads(os.environ["SITES"])[args[3]]
# -S keeps the host's own packages off sys.path, so the program lists only the fake ones.
env = {**os.environ, "PYTHONPATH": site}
sys.exit(subprocess.run([sys.executable, "-S", "-c", args[6]], env=env, cwd=site).returncode)
"""


def pin_file(*pins):
    """A pin file as uv pip compile writes it: name==version, then its hashes on continuation lines."""
    return "".join(f"{name}=={version} \\\n    --hash=sha256:{'0' * 64}\n" for name, version in pins)


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "work"
    (work / "scripts").mkdir(parents=True)
    (work / "docker").mkdir()
    (work / "Dockerfile").write_text(f"FROM {PINNED} AS base\n")
    for name in ("upstream-ref.sh", "pins-above-upstream.sh"):
        shutil.copy2(os.path.join(ROOT, "scripts", name), work / "scripts" / name)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "docker").write_text(FAKE_DOCKER)
    (tmp_path / "bin" / "docker").chmod(0o755)
    return work


def run(repo, pins=None, system_pins=None, venv=(), system=(), docker_fails=False):
    """Writes the pin files given as text (None leaves a file absent), installs the packages given as
    (name, version) for each interpreter, and runs the check."""
    for name, text in (("pins.txt", pins), ("system-pins.txt", system_pins)):
        if text is not None:
            (repo / "docker" / name).write_text(text)
    sites = {}
    for python, packages in ((VENV, venv), (SYSTEM, system)):
        site = repo.parent / f"site-{len(sites)}"
        site.mkdir()
        for name, version in packages:
            (site / f"{name}-{version}.dist-info").mkdir()
            (site / f"{name}-{version}.dist-info" / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            )
        sites[python] = str(site)
    calls = repo.parent / "calls"
    env = {
        **os.environ,
        "PATH": f"{repo.parent / 'bin'}:{os.environ['PATH']}",
        "CALLS": str(calls),
        "PINNED": PINNED,
        "SITES": json.dumps(sites),
    }
    if docker_fails:
        env["DOCKER_FAILS"] = "1"
    result = subprocess.run(
        [str(repo / "scripts" / "pins-above-upstream.sh")], cwd=repo, env=env, capture_output=True, text=True, check=False
    )
    recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    return result, recorded


def low(path, pin, upstream):
    return f"pins-above-upstream: {path}: {pin} is at or below upstream {upstream}; drop the pin"


def test_a_pin_at_or_below_upstream_fails_naming_each_one(repo):
    result, calls = run(
        repo,
        pins=pin_file(("aiohttp", "3.14.4"), ("certifi", "2026.10.19"), ("yarl", "1.26.0")),
        system_pins=pin_file(("uv", "0.13.3")),
        venv=[("aiohttp", "3.14.5"), ("certifi", "2026.10.19"), ("yarl", "1.25.1")],
        system=[("uv", "0.13.4")],
    )
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        low("docker/pins.txt", "aiohttp==3.14.4", "3.14.5"),
        low("docker/pins.txt", "certifi==2026.10.19", "2026.10.19"),
        low("docker/system-pins.txt", "uv==0.13.3", "0.13.4"),
    ]
    # Each file against its own interpreter, in the pinned upstream image, never the built one.
    assert [call[:5] for call in calls] == [
        ["run", "--rm", "--entrypoint", VENV, PINNED],
        ["run", "--rm", "--entrypoint", SYSTEM, PINNED],
    ]


def test_pins_above_upstream_and_pins_upstream_does_not_install_pass(repo):
    result, calls = run(
        repo,
        pins=pin_file(("aiohttp", "3.14.6"), ("not-in-upstream", "1.0")),
        system_pins=pin_file(("uv", "0.13.5")),
        venv=[("aiohttp", "3.14.5")],
        system=[("uv", "0.13.4")],
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert len(calls) == 2


def test_absent_pin_files_pass_without_running_upstream(repo):
    result, calls = run(repo)
    assert result.returncode == 0, result.stderr
    assert calls == []
    assert "docker/pins.txt: absent" in result.stdout and "docker/system-pins.txt: absent" in result.stdout


def test_versions_compare_by_pep_440(repo):
    result, _ = run(
        repo,
        pins=pin_file(("aiohttp", "3.14.10"), ("yarl", "2.0.0rc1")),
        venv=[("aiohttp", "3.14.9"), ("yarl", "2.0.0")],
    )
    assert result.returncode == 1
    assert result.stderr.splitlines() == [low("docker/pins.txt", "yarl==2.0.0rc1", "2.0.0")]


def test_names_match_after_pep_503_normalization(repo):
    result, _ = run(
        repo,
        pins=pin_file(("Pillow", "13.0.0"), ("claude_agent_sdk", "0.2.121")),
        venv=[("pillow", "13.0.0"), ("claude-agent-sdk", "0.2.168")],
    )
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        low("docker/pins.txt", "Pillow==13.0.0", "13.0.0"),
        low("docker/pins.txt", "claude_agent_sdk==0.2.121", "0.2.168"),
    ]


def test_a_failed_docker_run_fails(repo):
    result, calls = run(repo, pins=pin_file(("aiohttp", "3.14.6")), docker_fails=True)
    assert result.returncode != 0
    assert "pull access denied" in result.stderr
    assert len(calls) == 1


def test_an_interpreter_that_lists_no_packages_fails(repo):
    result, _ = run(repo, pins=pin_file(("aiohttp", "3.14.6")))
    assert result.returncode != 0
    assert "docker/pins.txt: upstream listed no packages" in result.stderr


def test_a_line_that_is_not_an_exact_pin_fails(repo):
    result, _ = run(repo, pins="aiohttp>=3.14.4 \\\n    --hash=sha256:" + "0" * 64 + "\n", venv=[("aiohttp", "3.14.5")])
    assert result.returncode != 0
    assert "docker/pins.txt:1: not a name==version pin: aiohttp>=3.14.4" in result.stderr
