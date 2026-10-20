"""CODING_STANDARDS.md rule 5, "Pin what runs", over every file CI or the image runs.

A pin sits at a site: a `uses:` key, a Dockerfile `FROM`, an `image=` or `image:` value, the image word of a
`docker run`, `pull` or `create`, or a `pip install`. Shell words are read with shlex (POSIX quoting) and split
into commands at control operators; docker's options that take a value come from its own --help. An image
word that is a variable is checked at its one assignment in the same file. A form the check does not read
(docker's global options, a variable assigned twice, a command named by a variable, a workflow value folded
over several lines, a flow mapping or a quoted key) fails, so a new form needs reading before it can pass.
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
TAGGED = re.compile(r"^[^@]*:v?\d+(?:\.\d+)+@")  # name:0.10.3@sha256:…, which carries its version itself
DOCKER_RUNS = ("run", "pull", "create")
PIP = re.compile(r"pip[\d.]*")  # pip, pip3, pip3.12


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
    if rest[:1] and rest[0].startswith("-"):
        return f"(docker global option {rest[0]}: not read)"
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


def assignments(path, name):
    """(value, line) for each place a file assigns a variable: NAME=… anywhere in a line, so a second one on the
    same line counts (one in a string or a trailing comment over-matches, which fails red), or a workflow env
    key NAME: …. The value is read from the line, which keeps a $(…) whole."""
    return [
        (m.group(1).strip("'\""), text)
        for _, text in lines(path)
        for m in [*re.finditer(rf"(?:^|[\s;&|(`]){name}=(\S+)", text), *re.finditer(rf"^\s*{name}:\s+(\S+)", text)]
    ]


@functools.cache
def upstream_ref():
    """What scripts/upstream-ref.sh prints: the image the unit tests and the source copy run."""
    script = os.path.join(ROOT, "scripts", "upstream-ref.sh")
    return subprocess.run([script], capture_output=True, text=True, check=True).stdout.strip()


def image_sites():
    """(where, image, the line that pins it) for every image a file runs."""
    for path, where, text in every_line():
        if os.path.basename(path) == "Dockerfile" and (m := re.match(r"(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)", text)):
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
                found = assignments(path, var.group(1))
                if len(found) != 1:
                    yield where, f"({image} assigned {len(found)} times: not read)", text
                elif "upstream-ref.sh" in found[0][0]:
                    yield where, upstream_ref(), ""  # name:tag@digest, which carries its version
                else:
                    yield where, *found[0]
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
    assert docker_image(["docker", "--context", "c", "run", "img"]) == "(docker global option --context: not read)"


def test_workflows_hold_only_forms_the_check_reads():
    """A value folded over several lines (run: >, or a plain or quoted value continued on deeper lines) and a
    flow mapping ({uses: …}) are not read line by line, so they fail rather than pass unread."""
    unread = []
    for path in glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml")):
        with open(path) as f:
            raw = f.read().splitlines()
        for n, text in enumerate(raw):
            where = f"{os.path.relpath(path, ROOT)}:{n + 1}: {text.strip()}"
            quoted_key = re.search(r"[\"']\s*(?:uses|run|image)\s*[\"']\s*:", text)
            flow_key = re.search(r"[{,]\s*(?:run|uses|image)\s*:", text)
            if re.search(r"\buses\s*:", text) and not USES.match(text) or quoted_key or flow_key:
                unread.append(where)
            if (m := re.match(r"^(\s*(?:-\s+)?)run:\s*(.*)$", text)) and not re.match(r"\|[-+]?\s*$", m.group(2)):
                after = next((line for line in raw[n + 1 :] if line.strip()), "")
                if len(after) - len(after.lstrip()) > len(m.group(1)):
                    unread.append(where)
    assert unread == []


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


def test_docker_and_pip_are_named_literally():
    """A command named by a variable ("$DOCKER" run, "$pip" install) is not read, so it fails. Found by its
    tokens, since a line can sit inside a string that spans lines; one in a string over-matches and fails red."""
    named = [
        f"{where}: {text.strip()}"
        for _, where, text in every_line()
        if re.search(r"[\"']?\$\{?\w+\}?[\"']?\s+(?:run|pull|create|install)\b", text)
    ]
    assert named == []


def test_every_python_install_checks_hashes():
    installs = [
        (where, words)
        for _, where, text in every_line()
        if re.search(r"\bpip", text)
        for words in commands(text)
        if (i := next((i for i, w in enumerate(words) if PIP.fullmatch(os.path.basename(w))), None)) is not None
        if "install" in words[i + 1 :]
    ]
    assert any(where.startswith("Dockerfile:") for where, _ in installs), "the check no longer sees the image's install"
    assert [f"{where}: {' '.join(words)}" for where, words in installs if "--require-hashes" not in words] == []
