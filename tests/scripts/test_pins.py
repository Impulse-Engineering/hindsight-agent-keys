"""CODING_STANDARDS.md rule 5, "Pin what runs", over every file CI or the image runs.

A pin sits at a site: a `uses:` key, a Dockerfile `FROM`, an `image=` or `image:` value, the image word of a
`docker run`, `pull` or `create`, or a `pip install`. Shell words are read with shlex (POSIX quoting) and split
into commands at control operators; docker's options that take a value come from its own --help. An image
word that is a variable is checked at its assignment in the same file.
"""

import functools
import glob
import os
import re
import shlex
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILES = sorted(
    [os.path.join(ROOT, "Dockerfile")]
    + glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))
    + glob.glob(os.path.join(ROOT, "scripts", "*.sh"))
)
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"#\s*v?\d+(?:\.\d+)+\b")  # the trailing comment a digest or SHA pin carries: # v0.34.0
TAGGED = re.compile(r"^[^@/]+(?:/[^@/]+)*:[\w][\w.-]*@")  # name:tag@sha256:…, which carries its version itself
DOCKER_RUNS = ("run", "pull", "create")


def lines(path):
    """(line number, text) for each non-comment line, with backslash continuations joined onto their first line."""
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
            yield start, joined
            joined, start = "", 0


def every_line():
    for path in FILES:
        for n, text in lines(path):
            yield path, f"{os.path.relpath(path, ROOT)}:{n}", text


def commands(text):
    """The simple commands in a line of shell, each as its words."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    found, words = [], []
    for token in lexer:
        if set(token) <= set("();<>|&"):
            found, words = found + [words], []
        else:
            words.append(token)
    return [w for w in found + [words] if w]


@functools.cache
def docker_options_with_a_value(subcommand):
    """The options of `docker <subcommand>` that read the next word, from docker's own --help."""
    out = subprocess.run(["docker", subcommand, "--help"], capture_output=True, text=True, check=True).stdout
    return {o for m in re.finditer(r"^\s+(?:(-\w), )?(--[\w-]+) [a-z]\w*\s", out, re.MULTILINE) for o in m.groups() if o}


def docker_image(words):
    """The image word of a docker run, pull or create, or None for any other command."""
    i = next((i for i, w in enumerate(words) if os.path.basename(w) == "docker"), None)
    rest = words[i + 1 :] if i is not None else []
    if rest[:1] in (["container"], ["image"]):
        rest = rest[1:]
    if not rest or rest[0] not in DOCKER_RUNS:
        return None
    takes, args = docker_options_with_a_value(rest[0]), iter(rest[1:])
    for word in args:
        if not word.startswith("-"):
            return word
        if word in takes:
            next(args, None)
    return ""


def assignment(path, name):
    """The value and line a file assigns a variable, as shell (NAME=…) or a workflow env key (NAME: …)."""
    for _, text in lines(path):
        if m := re.match(rf"^\s*(?:export\s+)?{name}(?:=|:\s+)(\S+)", text):
            return m.group(1).strip("'\""), text
    return None, ""


def image_sites():
    """(where, image, the line that pins it) for every image a file runs."""
    for path, where, text in every_line():
        if m := re.match(r"^FROM\s+(?:--\S+\s+)*(\S+)", text):
            yield where, m.group(1), text
        for m in re.finditer(r"(?:\bimage=|^\s*image:\s+)(\S+)", text):
            yield where, m.group(1).strip("'\""), text
        if (m := USES.match(text)) and m.group(1).startswith("docker://"):
            yield where, m.group(1), text
        if not re.search(r"\bdocker\b", text) or USES.match(text):
            continue
        for words in commands(text):
            image = docker_image(words)
            if image is None or re.search(r"@\$\{?\w+\}?$", image):  # None: not a run; @$DIGEST: a build output's digest
                continue
            if var := re.fullmatch(r"\$\{?(\w+)\}?", image):
                value, line = assignment(path, var.group(1))
                if value and "upstream-ref.sh" in value:  # that script refuses a FROM without a digest
                    continue
                yield where, value or image, line
            else:
                yield where, image, text


def test_the_pin_check_reads_every_file_that_runs():
    names = {os.path.relpath(path, ROOT) for path in FILES}
    assert {"Dockerfile", ".github/workflows/ci.yml", "scripts/lint.sh", "scripts/unit-tests.sh"} <= names


def test_shell_words_are_split_into_commands():
    assert commands('exec docker run --rm -v "$ROOT:/r:ro" "$X" && pip --quiet install a; x=$(docker pull b)') == [
        ["exec", "docker", "run", "--rm", "-v", "$ROOT:/r:ro", "$X"],
        ["pip", "--quiet", "install", "a"],
        ["x=$"],
        ["docker", "pull", "b"],
    ]
    assert docker_image(["docker", "run", "--rm", "-v", "a:/b", "-w", "/r", "--entrypoint", "/x", "img:1", "arg"]) == "img:1"
    assert docker_image(["docker", "build", "-t", "x", "."]) is None


def test_every_action_is_pinned_to_a_commit_sha_with_its_version():
    unpinned = [
        f"{where}: {text.strip()}"
        for _, where, text in every_line()
        if (m := USES.match(text)) and not m.group(1).startswith(("./", "docker://"))
        if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", m.group(1)) or not VERSION.search(text)
    ]
    assert unpinned == []


def test_every_image_is_pinned_by_digest_with_its_version():
    sites = list(image_sites())
    seen = " ".join(image for _, image, _ in sites)
    for name in ("vectorize-io/hindsight", "anchore/grype", "moby/buildkit", "rhysd/actionlint"):
        assert name in seen, f"the check no longer sees {name}"
    unpinned = [
        f"{where}: {image}"
        for where, image, line in sites
        if not DIGEST.search(image.removeprefix("docker://")) or not (TAGGED.match(image) or VERSION.search(line))
    ]
    assert unpinned == []


def test_every_python_install_checks_hashes():
    installs = [
        (where, words)
        for _, where, text in every_line()
        if re.search(r"\bpip3?\b", text)
        for words in commands(text)
        if (i := next((i for i, w in enumerate(words) if os.path.basename(w) in ("pip", "pip3")), None)) is not None
        if "install" in words[i + 1 :]
    ]
    assert any(where.startswith("Dockerfile:") for where, _ in installs), "the check no longer sees the image's install"
    assert [f"{where}: {' '.join(words)}" for where, words in installs if "--require-hashes" not in words] == []
