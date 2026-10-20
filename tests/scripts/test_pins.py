"""CODING_STANDARDS.md rule 5, "Pin what runs", over every file CI or the image runs.

These tests locate a pin by its token (`uses:`, an image reference, `pip install`) rather than read the
shell or YAML around it: a check only needs to see the pin next to the token, and a token in an odd
place over-matches, which fails red rather than letting an unpinned one through.
"""

import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILES = sorted(
    [os.path.join(ROOT, "Dockerfile")]
    + glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))
    + glob.glob(os.path.join(ROOT, "scripts", "*.sh"))
)
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)")
# registry/name with a tag or digest, not part of a path or a variable: anchore/grype@sha256:…, moby/buildkit:v0.34.0
IMAGE = re.compile(r"(?<![\w./${:-])([a-z0-9][\w.-]*(?:/[a-z0-9][\w.-]*)+)((?::[\w.-]+)?(?:@[\w:]+)?)")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def lines():
    """(file:line, text) for every non-comment line, with backslash continuations joined onto their first line."""
    for path in FILES:
        name = os.path.relpath(path, ROOT)
        joined, start = "", 0
        with open(path) as f:
            for n, line in enumerate(f, 1):
                if not joined and line.lstrip().startswith("#"):
                    continue
                start = start or n
                joined += line.rstrip("\n")
                if joined.endswith("\\"):
                    joined = joined[:-1] + " "
                    continue
                yield f"{name}:{start}", joined
                joined, start = "", 0


def test_the_pin_check_reads_every_file_that_runs():
    names = {os.path.relpath(path, ROOT) for path in FILES}
    assert {"Dockerfile", ".github/workflows/ci.yml", "scripts/lint.sh"} <= names


def test_every_action_is_pinned_to_a_commit_sha_with_its_version():
    unpinned = [
        f"{where}: {text.strip()}"
        for where, text in lines()
        if (m := USES.match(text)) and not m.group(1).startswith("./")
        if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", m.group(1)) or "#" not in text
    ]
    assert unpinned == []


def test_every_image_is_pinned_by_digest():
    found = [(where, text, m) for where, text in lines() if not USES.match(text) for m in IMAGE.finditer(text) if m.group(2)]
    assert any(m.group(1) == "anchore/grype" for _, _, m in found), "the check no longer sees the scanner's image"
    unpinned = [
        f"{where}: {m.group(0)}"
        for where, text, m in found
        # A digest alone needs the version beside it as a comment; a tag carries it.
        if not DIGEST.search(m.group(2)) or (not m.group(2).startswith(":") and "#" not in text)
    ]
    assert unpinned == []


def test_every_python_install_checks_hashes():
    installs = [(where, text) for where, text in lines() if re.search(r"\bpip3?\s+install\b", text)]
    assert any(where.startswith("Dockerfile:") for where, _ in installs), "the check no longer sees the image's install"
    # shortcut: a line with two installs passes if either checks hashes; split such a line when one appears.
    assert [f"{where}: {text.strip()}" for where, text in installs if "--require-hashes" not in text] == []
