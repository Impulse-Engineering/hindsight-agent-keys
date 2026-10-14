"""Checks the shell the README and docs give operators (CODING_STANDARDS rule 7).

A gate is a doc function that prints STOP when its check fails. Each gate runs
under bash in a bash block and under sh otherwise, against fake curl and
cloudflared on PATH, which answer with one status and apply the flags the docs
use as curl 8 does, and must succeed only on the status it waits for.
"""

import glob
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = [os.path.join(ROOT, "README.md"), *sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True))]
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*([\w+-]*)[^\n]*\n(.*?)^[ \t]*\1[`~]*[ \t]*$", re.MULTILINE | re.DOTALL)
SHELLS = ("", "sh", "bash", "shell", "zsh")  # an untagged block may hold shell, so it is read too
COMPOUND = ("if", "case", "while", "until", "for")
DEFINITION = re.compile(r"[ \t]*(?:function[ \t]+(\w+)|(\w+)[ \t]*\(\))")
OPERATORS = ("||", "&&", ";", "|", "&", "(", ")", "\n")
ANSWERS = ("200", "302", "401", "403", "404", "500", "refused")
PRINTS = ("echo", "printf")
FAILS = (["false"], ["return", "1"], ["exit", "1"])

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
    """A doc's fenced blocks that may hold shell (sh, bash, shell, zsh or untagged), as (language, text)."""
    with open(path) as fh:
        found = [(m[2].lower(), m[3]) for m in FENCE.finditer(fh.read())]
    return [(language, text) for language, text in found if language in SHELLS]


def tokens(text):
    """Words and operators (a newline is one), comments dropped, quotes resolved as sh does."""
    out, word, i = [], None, 0
    text = text.replace("\\\n", "")
    while i < len(text):
        c = text[i]
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if text.startswith((">&", "<&"), i):  # a redirection such as 2>&1; its & is not an operator
            word, i = (word or "") + text[i : i + 2], i + 2
        elif c in " \t" or op:
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
    found = []
    for token in out + ([word] if word is not None else []):
        found.append(token)
        # A quoted "$(...)" is one word; its commands still run.
        if token not in OPERATORS and (sub := re.search(r"\$\((.*)\)", token, re.DOTALL)):
            found += ["(", *tokens(sub.group(1)), ")"]
    return found


def definitions(words):
    """How many functions shell words define, so a form functions() misses shows up."""
    starts = [i for i, w in enumerate(words) if i == 0 or words[i - 1] in (*OPERATORS, "{", "}")]
    return sum(words[i] == "function" or (words[i] not in OPERATORS and words[i + 1 : i + 3] == ["(", ")"]) for i in starts)


def functions(path):
    """Each shell function a doc defines, as (name, source, bash for a bash block or else sh)."""
    found = []
    for language, block in blocks(path):
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
                if words.count("{") == words.count("}") > 0:
                    found.append((m.group(1) or m.group(2), source, "bash" if language == "bash" else "sh"))
                    break
            else:
                raise ValueError(f"{path}: {m.group(1) or m.group(2)}() has no {{ }} body that closes, so it cannot be checked")
    return found


def shell_in(path):
    """A doc's shell blocks, then its inline commands that call curl."""
    with open(path) as fh:
        text = fh.read()
    spans = re.findall(r"`([^`\n]+)`", FENCE.sub("", text))
    return "\n".join([block for _, block in blocks(path)] + [s for s in spans if "curl" in s])


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


def curl_options_with_an_argument():
    """The options curl itself lists as taking an argument, so a -f after one is read as its argument."""
    help_text = subprocess.run(["curl", "--help", "all"], capture_output=True, text=True, check=True).stdout
    return {opt for pair in re.findall(r"^\s*(?:(-\w), )?(--[\w.-]+) <", help_text, re.MULTILINE) for opt in pair if opt}


CURL_ARGS = curl_options_with_an_argument()


def unsafe_calls(text):
    """curl calls that may PUT, PATCH or DELETE (a method in a variable may) without -f, so an HTTP
    error still exits 0. Options are read as curl reads them: -sSX DELETE is -s -S -X DELETE."""
    unsafe = []
    for words in commands(text):
        if "curl" not in words:
            continue
        method, fails, rest = None, False, words[words.index("curl") + 1 :]
        while rest:
            word = rest.pop(0)
            if word in ("--fail", "--fail-with-body"):
                fails = True
            elif word.startswith("--request="):
                method = word[len("--request=") :]
            elif word.startswith("--") and word in CURL_ARGS:
                value = rest.pop(0) if rest else ""
                method = value if word == "--request" else method
            elif re.match(r"-[a-zA-Z]", word):
                for n, c in enumerate(word[1:], 1):
                    fails = fails or c == "f"
                    if f"-{c}" in CURL_ARGS:
                        value = word[n + 1 :] or (rest.pop(0) if rest else "")
                        method = value if c == "X" else method
                        break
        if method and (method.upper() in ("PUT", "PATCH", "DELETE") or "$" in method) and not fails:
            unsafe.append(" ".join(words))
    return unsafe


def open_failures(text):
    """Failure branches that print (|| echo …, || { echo …; }, || ( echo … )) but exit 0: the branch
    does not end in false, return 1 or exit 1, or a later | or || takes over its status. A compound
    command after || (if, case, a loop) is refused: write the branch as { …; }."""
    words, found = tokens(text), []
    for i in (i for i, w in enumerate(words) if w == "||"):
        j = i + 1
        while words[j : j + 1] == ["\n"]:
            j += 1
        opener = words[j] if j < len(words) else ""
        closer = {"{": "}", "(": ")"}.get(opener)
        if opener in COMPOUND:
            found.append(" ".join(words[i : j + 1]))
            continue
        if not closer:
            k = next((k for k in range(j, len(words)) if words[k] in OPERATORS), len(words))
            if set(PRINTS) & set(words[j:k]):
                found.append(" ".join(words[i:k]))
            continue
        depth, statements = 0, [[]]
        for k in range(j, len(words)):
            depth += {opener: 1, closer: -1}.get(words[k], 0)
            if depth == 0:
                break
            if words[k] in (";", "\n"):
                statements.append([])
            elif k > j:
                statements[-1].append(words[k])
        printed = [w for s in statements for w in s if w in PRINTS]
        after = k + 1
        while after < len(words) and (r := re.match(r"\d*[<>]+&?", words[after])):
            after += 2 if r.end() == len(words[after]) else 1  # "2>" "file", or "2>&1" in one word
        if printed and ([s for s in statements if s][-1] not in FAILS or words[after : after + 1] in (["|"], ["||"])):
            found.append(" ".join(words[i : k + 2]))
    return found


GATES = [
    pytest.param(path, name, source, shell, id=f"{os.path.relpath(path, ROOT)}:{name}")
    for path in DOCS
    for name, source, shell in functions(path)
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
    assert {name for _, name, _, _ in (gate.values for gate in GATES)} >= {"closed", "keyless"}


def test_functions_are_found_in_every_form_sh_and_bash_allow(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text(
        "```sh\na()\n{\n  echo STOP\n}\nb () { echo STOP; }\n```\n\n"
        "```bash\nfunction c {\n  echo STOP\n}\nfunction d() { echo STOP; }\n```\n"
    )
    assert [(name, shell) for name, _, shell in functions(str(doc))] == [("a", "sh"), ("b", "sh"), ("c", "bash"), ("d", "bash")]
    assert sum(definitions(tokens(block)) for _, block in blocks(str(doc))) == 4


def test_every_fence_that_may_hold_shell_is_read(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text(
        "``` sh\na\n```\n\n  ~~~bash\n  b\n  ~~~\n\n```\nc\n```\n\n````shell\nd\n````\n\n```text\ne\n```\n"
        "\n```sh\nf\n`````\n\n~~~\ng\n~~~~\n"
    )
    assert blocks(str(doc)) == [("sh", "a\n"), ("bash", "  b\n"), ("", "c\n"), ("shell", "d\n"), ("sh", "f\n"), ("", "g\n")]


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_function_a_doc_defines_is_found(path):
    assert len(functions(path)) == sum(definitions(tokens(block)) for _, block in blocks(path))


@pytest.mark.parametrize("path,name,source,shell", GATES)
def test_a_gate_succeeds_only_on_the_status_it_waits_for(fakes, tmp_path, path, name, source, shell):
    waits_for = set(re.findall(r'= "?(\d{3})\b', source))
    assert len(waits_for) == 1, f"{name} compares against {waits_for or 'no status'}; a gate waits for one"
    defined = "".join(f"{s}\n" for _, s, block_shell in functions(path) if block_shell == shell)
    env = {**os.environ, "PATH": f"{fakes}:{os.environ['PATH']}"}
    passed = set()
    for answer in ANSWERS:
        result = subprocess.run(
            [shell, "-c", f"{defined}{name} example.invalid"],
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
        ('[ "$(curl -sS -o /dev/null -w \'%{http_code}\' -X DELETE "$u")" = 204 ]', 1),
        ("curl -sS --request=PUT https://x/z", 1),
        ("curl -sSX DELETE https://x", 1),
        ("cloudflared access curl https://x -sSXPATCH", 1),
        ("curl -sS -X DELETE --data '-f' https://x", 1),
        ('curl -sS -X "$method" https://x', 1),
        ("curl --cookie --fail -X DELETE https://x", 1),
        ("curl --user-agent -f -X DELETE https://x", 1),
        ("curl -A -f -X DELETE https://x", 1),
        ("curl -sSfX DELETE https://x\ncurl -H 'X-f: 1' -fsS -X PUT https://x", 0),
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
        ('y="$(check || echo STOP)"', 1),
        ('check || { >&2 echo "STOP: failed"; }', 1),
        ("check || >&2 echo STOP", 1),
        ("check || printf 'STOP\\n'", 1),
        ("check || { echo STOP; return 1; } || true", 1),
        ('check || ( echo "STOP: failed" )', 1),
        ("check || { echo STOP; false; } | tee /dev/null", 1),
        ("check || ( echo STOP; exit 1 ) | cat", 1),
        ("check || if true; then echo STOP; fi", 1),
        ('check || { echo "STOP: failed"; false; } 2>&1 | tee /dev/null', 1),
        ("check || { echo STOP; false; } 2>/dev/null || true", 1),
        ("check || ( echo STOP; exit 1 ) > /tmp/log 2>&1 | cat", 1),
        ("check 2>&1 || { echo STOP; false; }\ncheck || ( echo STOP; exit 1 )", 0),
        ('check || { echo "STOP: a; b"; false; }\nx() { check || { echo STOP; return 1; }; }', 0),
        ("check || { echo STOP; exit 1; }\ncheck || exit 1", 0),
    ],
)
def test_the_branch_check_finds_failure_branches_that_exit_0(shell, found):
    assert len(open_failures(shell)) == found


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_failure_branch_ends_in_failure(path):
    assert open_failures(shell_in(path)) == []
