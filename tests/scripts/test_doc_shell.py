"""Checks the shell the README and docs give operators (CODING_STANDARDS rule 7).

A gate is a doc function that prints STOP when its check fails. Each gate runs
under sh against fake curl and cloudflared on PATH, which answer with one
status and apply the flags the docs use as curl 8 does, and must succeed only
on the status it waits for.
"""

import glob
import itertools
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = [os.path.join(ROOT, "README.md"), *sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True))]
FENCE = re.compile(r"^[ \t]*```(?:sh|bash|shell)[ \t]*\n(.*?)^[ \t]*```", re.MULTILINE | re.DOTALL)
DEFINITION = re.compile(r"^[ \t]*(\w+)\(\)[ \t]*\{", re.MULTILINE)
OPERATORS = ("||", "&&", ";", "|", "&", "(", ")", "\n")
ANSWERS = ("200", "302", "401", "403", "404", "500", "refused")

# Answers $FAKE_ANSWER. Refuses any option the docs do not use, so a new flag
# turns the test red instead of being ignored.
FAKE_CURL = f"""#!{sys.executable}
import os, sys
takes = {{"-o": "o", "-w": "w", "-X": "X", "-H": "H", "-d": "d", "--data": "d", "--data-binary": "d"}}
switches = {{"-s": "s", "-S": "S", "-f": "f", "--fail": "f"}}
args, flags, values, urls = sys.argv[1:], set(), {{}}, []
while args:
    arg = args.pop(0)
    if arg in takes:
        values[takes[arg]] = args.pop(0)
    elif arg in switches:
        flags.add(switches[arg])
    elif arg.startswith("-") and set(arg[1:]) <= set("sSf") and len(arg) > 2:
        flags.update(arg[1:])
    elif arg.startswith("-"):
        sys.exit(f"fake curl: unsupported option {{arg}}")
    else:
        urls.append(arg)
if len(urls) != 1:
    sys.exit(f"fake curl: expected one URL, got {{urls}}")
fmt = values.get("w", "")
if "%{{" in fmt.replace("%{{http_code}}", ""):
    sys.exit(f"fake curl: unsupported write-out {{fmt}}")
answer, error, status = os.environ["FAKE_ANSWER"], None, 0
if answer == "refused":
    answer, error, status = "000", "(7) Failed to connect to example.invalid port 443: Couldn't connect to server", 7
elif "f" in flags and int(answer) >= 400:
    error, status = f"(22) The requested URL returned error: {{answer}}", 22
else:
    body = f"answer {{answer}}\\n"
    if "o" in values:
        with open(values["o"], "w") as out:
            out.write(body)
    else:
        sys.stdout.write(body)
sys.stdout.write(fmt.replace("%{{http_code}}", answer).replace("\\\\n", "\\n"))
if error and ("S" in flags or "s" not in flags):
    print(f"curl: {{error}}", file=sys.stderr)
sys.exit(status)
"""
# cloudflared access curl <url> [curl options] runs curl with the Access token added.
FAKE_CLOUDFLARED = """#!/bin/sh
[ "$1 $2" = "access curl" ] || { echo "fake cloudflared: unsupported call: $*" >&2; exit 2; }
shift 2
exec curl "$@" -H "cf-access-token: fake"
"""


def blocks(path):
    with open(path) as fh:
        return FENCE.findall(fh.read())


def tokens(text):
    """Words and operators (a newline is one), comments dropped, quotes resolved as sh does."""
    out, word, i = [], None, 0
    text = text.replace("\\\n", "")
    while i < len(text):
        c = text[i]
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if c in " \t" or op:
            if word is not None:
                out.append(word)
                word = None
            out += [op] if op else []
            i += len(op) if op else 1
        elif c == "#" and word is None:
            i = text.find("\n", i) if "\n" in text[i:] else len(text)
        elif c in "'\"":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 2 if c == '"' and text[j] == "\\" else 1
            if j >= len(text):
                raise ValueError(f"unclosed {c}")
            word, i = (word or "") + text[i + 1 : j], j + 1
        elif c == "\\":
            word, i = (word or "") + text[i + 1 : i + 2], i + 2
        else:
            word, i = (word or "") + c, i + 1
    return out + ([word] if word is not None else [])


def functions(path):
    """Each shell function a doc defines, as (name, source)."""
    found = []
    for block in blocks(path):
        lines = block.splitlines(keepends=True)
        for start, line in enumerate(lines):
            if not (m := DEFINITION.match(line)):
                continue
            for end in range(start + 1, len(lines) + 1):
                source = "".join(lines[start:end])
                try:
                    words = tokens(source)
                except ValueError:  # a quote that closes on a later line
                    continue
                if words.count("{") == words.count("}"):
                    found.append((m.group(1), source))
                    break
    return found


def shell_in(path):
    """A doc's shell blocks, then its inline commands that call curl."""
    with open(path) as fh:
        text = fh.read()
    spans = re.findall(r"`([^`\n]+)`", FENCE.sub("", text))
    return "\n".join(FENCE.findall(text) + [s for s in spans if "curl" in s])


def commands(text):
    """Each simple command in shell text, as its words."""
    found, words = [], []
    for token in tokens(text) + ["\n"]:
        if token in OPERATORS or token in ("{", "}"):
            found += [words] if words else []
            words = []
        else:
            words.append(token)
    return found


def unsafe_calls(text):
    """curl calls that PUT, PATCH or DELETE without -f, so an HTTP error still exits 0."""
    unsafe = []
    for words in commands(text):
        methods = {b for a, b in itertools.pairwise(words) if a in ("-X", "--request")}
        methods |= {w[2:] for w in words if w.startswith("-X") and len(w) > 2}
        fails = any(w in ("--fail", "--fail-with-body") or re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", w) for w in words)
        if "curl" in words and methods & {"PUT", "PATCH", "DELETE"} and not fails:
            unsafe.append(" ".join(words))
    return unsafe


def open_failures(text):
    """Failure branches (|| echo …, || { echo …; }) that do not end in false, return 1 or exit 1."""
    words, found = tokens(text), []
    for i in (i for i, w in enumerate(words) if w == "||"):
        j = i + 1
        while words[j : j + 1] == ["\n"]:
            j += 1
        if words[j : j + 1] == ["echo"]:
            found.append(" ".join(words[i : i + 8]))
        elif words[j : j + 2] == ["{", "echo"]:
            depth, statements = 0, [[]]
            for k in range(j, len(words)):
                depth += {"{": 1, "}": -1}.get(words[k], 0)
                if depth == 0:
                    break
                if words[k] in (";", "\n"):
                    statements.append([])
                elif k > j:
                    statements[-1].append(words[k])
            if [s for s in statements if s][-1] not in (["false"], ["return", "1"], ["exit", "1"]):
                found.append(" ".join(words[i : k + 1]))
    return found


GATES = [
    pytest.param(path, name, source, id=f"{os.path.relpath(path, ROOT)}:{name}")
    for path in DOCS
    for name, source in functions(path)
    if re.search(r"""echo ["']?STOP""", source)
]


@pytest.fixture(scope="module")
def fakes(tmp_path_factory):
    bin_dir = tmp_path_factory.mktemp("bin")
    for name, body in (("curl", FAKE_CURL), ("cloudflared", FAKE_CLOUDFLARED)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    return bin_dir


def test_the_runbook_gates_are_found():
    assert {name for _, name, _ in (gate.values for gate in GATES)} >= {"closed", "keyless"}


@pytest.mark.parametrize("path,name,source", GATES)
def test_a_gate_succeeds_only_on_the_status_it_waits_for(fakes, tmp_path, path, name, source):
    waits_for = set(re.findall(r'= "?(\d{3})\b', source))
    assert len(waits_for) == 1, f"{name} compares against {waits_for or 'no status'}; a gate waits for one"
    defined = "".join(f"{s}\n" for _, s in functions(path))
    env = {**os.environ, "PATH": f"{fakes}:{os.environ['PATH']}"}
    passed = set()
    for answer in ANSWERS:
        result = subprocess.run(
            ["sh", "-c", f"{defined}{name} example.invalid"],
            cwd=tmp_path, env={**env, "FAKE_ANSWER": answer}, capture_output=True, text=True, check=False, timeout=30,
        )
        assert "fake " not in result.stderr, result.stderr
        if result.returncode == 0:
            passed.add(answer)
    assert passed == waits_for


@pytest.mark.parametrize(
    "shell,found",
    [
        ('cloudflared access curl "$capi/domains/1" -sS -X PATCH --data \'{"a": 1}\'', 1),
        ("curl -sS -X DELETE https://x/y && curl -sSf -X PUT https://x/z", 1),
        ("curl -sS -f -X PUT https://x/z\ncurl -fsS -X DELETE https://x\ncurl --fail -X PATCH https://x", 0),
        ('curl -sS -o /dev/null -w "%{http_code}" https://x/health', 0),
    ],
)
def test_the_f_check_finds_state_changing_calls_without_it(shell, found):
    assert len(unsafe_calls(shell)) == found


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_state_changing_call_fails_on_an_http_error(path):
    assert unsafe_calls(shell_in(path)) == []


@pytest.mark.parametrize(
    "shell,found",
    [
        ('check && echo "ok" || echo "STOP: no 401"', 1),
        ('check ||\n  { echo "STOP: a; b"; }', 1),
        ("check || { echo STOP; true; }", 1),
        ("check || { echo STOP; foo && false; }", 1),
        ('check || { echo "STOP: a; b"; false; }\nx() { check || { echo STOP; return 1; }; }', 0),
        ("check || { echo STOP; exit 1; }\ncheck || exit 1", 0),
    ],
)
def test_the_branch_check_finds_failure_branches_that_exit_0(shell, found):
    assert len(open_failures(shell)) == found


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_failure_branch_ends_in_failure(path):
    assert open_failures(shell_in(path)) == []
