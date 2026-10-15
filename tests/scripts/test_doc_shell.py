"""Checks the shell the README and docs give operators (CODING_STANDARDS rules 6, 7 and 8).

Fenced blocks are found with markdown-it (CommonMark), and shell is read from
shfmt's syntax tree. A gate is a doc function that prints STOP when its check
fails. Each gate runs under bash in a bash block or a heredoc fed to bash, and
under sh otherwise, against fake curl and cloudflared on PATH, which answer with
one status and apply the flags the docs use as curl 8 does, and must succeed only
on the status it waits for. Every curl call the -f check accepts, in its test cases
and the docs, runs through the fakes too, so the fake reads each form the check does.
"""

import functools
import glob
import json
import os
import re
import subprocess
import sys

import pytest
from markdown_it import MarkdownIt

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = [os.path.join(ROOT, "README.md"), *sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True))]
MARKDOWN = MarkdownIt("commonmark")
SHELLS = ("", "sh", "bash", "shell", "zsh")  # an untagged block may hold shell, so it is read too
PLACEHOLDER = re.compile(r"<([A-Za-z](?:[\w ./:@+-]*\w)?)>")  # <port>, <key file>, <host:port>, <a@b.c>: a value typed there
COMPOUND = ("IfClause", "CaseClause", "WhileClause", "ForClause")
ANSWERS = ("200", "302", "401", "403", "404", "500", "refused")
PRINTS = ("echo", "printf")
PSQL_VARIABLE = re.compile(r"(?<!:):(?:['\"]?[A-Za-z_]|\{\?)")  # :name, :'name', :"name", :{?name}
FAILS = (["false"], ["return", "1"], ["exit", "1"])

# Answers $FAKE_ANSWER. Refuses any option the docs do not use, so a new flag
# turns the test red instead of being ignored.
FAKE_CURL = f"""#!{sys.executable}
import os, re, sys
takes = {{"-o": "o", "--output": "o", "-w": "w", "--write-out": "w", "-X": "X", "--request": "X", "-H": "H", "--header": "H", "-d": "d", "--data": "d", "--data-binary": "d"}}
switches = {{"-s": "s", "-S": "S", "-f": "f", "--fail": "f", "--fail-with-body": "F"}}
args, flags, values, urls = sys.argv[1:], set(), {{}}, []
while args:
    arg = args.pop(0)
    if arg in takes:
        values[takes[arg]] = args.pop(0)
    elif arg.startswith("--request="):
        values["X"] = arg[len("--request="):]
    elif arg in switches:
        flags.add(switches[arg])
    elif arg in ("-h", "--help"):  # curl prints its help and sends nothing
        sys.exit(0)
    elif re.fullmatch(r"-[sSf]*(X.*)?", arg) and len(arg) > 2:  # a cluster: -sSf, -fX DELETE, -sSXDELETE
        cluster, x, method = arg[1:].partition("X")
        flags.update(cluster)
        if x:
            values["X"] = method or args.pop(0)
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
else:
    if flags & {{"f", "F"}} and int(answer) >= 400:
        error, status = f"(22) The requested URL returned error: {{answer}}", 22
    if not status or "F" in flags:  # -f writes no body on an HTTP error; --fail-with-body does
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
        found = [(re.match(r"[\w+-]*", t.info.strip())[0].lower(), t.content) for t in MARKDOWN.parse(fh.read()) if t.type == "fence"]
    return [(language, text) for language, text in found if language in SHELLS]


def shell_in(path):
    """A doc's shell blocks, then its inline commands that call curl or psql, as (bash or sh, text)."""
    with open(path) as fh:
        spans = [c.content for t in MARKDOWN.parse(fh.read()) if t.type == "inline" for c in t.children if c.type == "code_inline"]
    return [("bash" if language == "bash" else "sh", text) for language, text in blocks(path)] + [("sh", s) for s in spans if "curl" in s or "psql" in s]


@functools.cache
def syntax_tree(text, shell):
    """shfmt's syntax tree for shell text, read as bash or POSIX sh. A placeholder such as <port> reads as
    $port_, a value nobody knows yet, of the same length, so the tree's offsets still point into the text."""
    readable = PLACEHOLDER.sub(lambda m: f"${m[1].replace(' ', '_')}_", text)
    result = subprocess.run(
        ["shfmt", "-ln", "bash" if shell == "bash" else "posix", "--to-json"], input=readable.encode(), capture_output=True, check=False
    )
    if result.returncode:
        raise ValueError(f"shfmt cannot read this as {shell} (tag a block that is not shell, e.g. text): {result.stderr.decode()}{text}")
    return json.loads(result.stdout)


def nodes(tree, kind=None):
    """The nodes of a syntax tree, or those of one Type, a parent before its children."""
    if isinstance(tree, list):
        for item in tree:
            yield from nodes(item, kind)
    elif isinstance(tree, dict):
        if kind is None or tree.get("Type") == kind:
            yield tree
        yield from nodes(list(tree.values()), kind)


def span(text, node):
    """The text a node covers (shfmt counts UTF-8 bytes)."""
    return text.encode()[node["Pos"]["Offset"] : node["End"]["Offset"]].decode()


# shortcut: shell in a quoted string (sh -c '…', ssh host '…') is not read; read it when a doc runs commands that way.
def scripts(text, shell, dialect=None):
    """Shell text as (text, syntax tree, the shell that runs it), then each heredoc body in it that reads as
    shell (a script fed to ssh or sh). A body is read as bash, which takes all sh syntax too, and runs in
    bash when the command it is fed to names bash, else in sh."""
    found = [(text, tree := syntax_tree(text, dialect or shell), shell)]
    for stmt in nodes(tree):
        for redirect in (r for r in stmt.get("Redirs") or [] if r.get("Hdoc")):
            body = span(text, redirect["Hdoc"]).rpartition("\n")[0]  # the span ends with the closing delimiter
            receiver = words(stmt["Cmd"]) if stmt.get("Cmd", {}).get("Type") == "CallExpr" else []
            try:
                found += scripts(body, "bash" if "bash" in map(os.path.basename, receiver) else "sh", "bash")
            except ValueError:  # not shell: SQL, JSON or a file's content
                pass
    return found


def unquote(part, quoted=False):
    """A word part as sh reads it: quotes and escapes removed, an expansion read as $ since its value is unknown."""
    if part["Type"] == "Lit":
        return re.sub(r'\\([$`"\\])' if quoted else r"\\(.)", r"\1", part.get("Value", ""))
    if part["Type"] == "SglQuoted":
        return part.get("Value", "")  # '' has no Value
    if part["Type"] == "DblQuoted":
        return "".join(unquote(p, quoted=True) for p in part.get("Parts", []))
    return "$"


def word(node):
    """A word as sh reads it."""
    return "".join(unquote(part) for part in node["Parts"])


def words(call):
    """A simple command's words as sh reads them."""
    return [word(w) for w in call.get("Args", [])]


def prints(command):
    """Whether a command prints with echo or printf, wherever the word sits (command echo, time echo)."""
    return bool(set(PRINTS) & set(command))


def commands(text, shell="sh"):
    """Each simple command in shell text, including those in $(...) and heredoc bodies, as its words."""
    return [words(call) for _, tree, _ in scripts(text, shell) for call in nodes(tree, "CallExpr")]


def functions(path):
    """Each shell function a doc defines, as (name, source, the shell that runs it, scope). The scope is
    None for a block, whose functions the operator's shell keeps for later blocks, or the heredoc body that
    defines it, which runs in a shell of its own."""
    found = []
    for language, text in blocks(path):
        shell = "bash" if language == "bash" else "sh"
        for script, tree, runs in scripts(text, shell):
            scope = None if script is text else script
            found += [(decl["Name"]["Value"], span(script, decl), runs, scope) for decl in nodes(tree, "FuncDecl")]
    return found


def waits_for(source, shell):
    """The statuses a gate compares against: [ "$code" = 401 ] or [[ $code == 401 ]]."""
    pairs = [(c[i], c[i + 1]) for c in commands(source, shell) for i in range(len(c) - 1)]
    pairs += [(test["Op"], word(test["Y"])) for _, tree, _ in scripts(source, shell) for test in nodes(tree, "BinaryTest")]
    return {status for op, status in pairs if op in ("=", "==") and re.fullmatch(r"\d{3}", status)}


def options_with_an_argument(*command, pattern):
    """The options a tool's own help lists as taking an argument, so the word after one is its value, not an option."""
    help_text = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    return {opt for match in re.findall(pattern, help_text, re.MULTILINE) for opt in match if opt}


# curl shows the argument as <file>, or as [protocol://]host for --proxy; psql as --dbname=DBNAME.
CURL_ARGS = options_with_an_argument("curl", "--help", "all", pattern=r"^\s*(?:(-\w), )?(--[\w.-]+) [<\[]")
PSQL_ARGS = options_with_an_argument("psql", "--help", pattern=r"^\s+(-\w), (--[\w-]+)=(?:, (--[\w-]+)=)?")


def options(args, takes):
    """A command's arguments as (option, value) pairs, read as the tool reads them: -sSX DELETE is -s, -S and
    -X DELETE, and an option in takes consumes its argument. An operand comes back as (None, operand)."""
    found, rest = [], list(args)
    while rest:
        arg = rest.pop(0)
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            found.append((name, value if eq else rest.pop(0) if name in takes and rest else None))
        elif re.match(r"-[a-zA-Z0-9]", arg):
            for n, c in enumerate(arg[1:], 1):
                if f"-{c}" in takes:
                    found.append((f"-{c}", arg[n + 1 :] or (rest.pop(0) if rest else "")))
                    break
                found.append((f"-{c}", None))
        else:
            found.append((None, arg))
    return found


# shortcut: any word curl but the last starts a call (sudo curl, ssh h curl), so apt-get install curl jq reads as
# curl jq; read the command word when a doc names curl as an argument.
def curl_calls(text, shell="sh"):
    """Each curl call in shell text, as (its text, its words from curl on, or from cloudflared for
    cloudflared access curl). A bare curl, with no arguments, names the tool in prose and is skipped."""
    for script, tree, _ in scripts(text, shell):
        for call in nodes(tree, "CallExpr"):
            command = words(call)
            if "curl" in command[:-1]:
                at = command.index("curl")
                if command[max(at - 2, 0) : at] == ["cloudflared", "access"]:
                    at -= 2
                yield span(script, call), command[at:]


# shortcut: the PUT that -T (upload a file) implies is not modelled; model it when a doc uploads with curl.
def unsafe_calls(text, shell="sh"):
    """curl calls that may PUT, PATCH or DELETE (a method in a variable may) without -f, so an HTTP
    error still exits 0. Options are read as curl reads them: -sSX DELETE is -s -S -X DELETE."""
    unsafe = []
    for call, command in curl_calls(text, shell):
        given = options(command[command.index("curl") + 1 :], CURL_ARGS)
        fails = any(name in ("-f", "--fail", "--fail-with-body") for name, _ in given)
        method = next((value for name, value in reversed(given) if name in ("-X", "--request")), None)
        if method and (method.upper() in ("PUT", "PATCH", "DELETE") or "$" in method) and not fails:
            unsafe.append(call)
    return unsafe


def refusals(fakes, cwd, text, shell="sh"):
    """The curl calls the -f check accepts that the fake curl or cloudflared refuses when answering 200, each
    with the fake's complaint: a form the check reads that the fake does not model."""
    unsafe = unsafe_calls(text, shell)
    env = {**os.environ, "PATH": f"{fakes}:{os.environ['PATH']}", "FAKE_ANSWER": "200"}
    found = []
    for call, command in curl_calls(text, shell):
        if call not in unsafe:
            run = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=30)
            if run.returncode or "fake " in run.stderr:
                found.append((call, run.stderr))
    return found


def parents(tree):
    """Each node's parent node, by id."""
    found = {}
    for node in nodes(tree):
        for value in node.values():
            for child in value if isinstance(value, list) else [value]:
                if isinstance(child, dict):
                    found[id(child)] = node
    return found


def status_lost(node, parent):
    """Whether what encloses a command discards its failure: ! or & on it, a | or || it is the left side
    of, or an if or loop condition, through any group, subshell, time or && around it. A later statement in
    the same list is the shortcut below."""
    child = node
    while (up := parent.get(id(child))) is not None:
        if up.get("Negated") or up.get("Background") or (up.get("Type") == "BinaryCmd" and up["X"] is child and up["Op"] != "&&"):
            return True
        if up.get("Type") in ("IfClause", "WhileClause") and any(child is stmt for stmt in up.get("Cond", [])):
            return True
        if up.get("Type") in ("Block", "Subshell") and up["Stmts"][-1] is not child:
            return False
        if up.get("Type") not in (None, "BinaryCmd", "Block", "Subshell", "TimeClause"):
            return False  # a function body, $(...), an if's or a loop's body: its status goes to whoever reads it
        child = up
    return False


def fed(script, node):
    """What the commands under node write: echo and printf words, and heredoc and here-string bodies."""
    text = [w for command in map(words, nodes(node, "CallExpr")) if prints(command) for w in command]
    for stmt in nodes(node):
        for redirect in stmt.get("Redirs") or []:
            if redirect.get("Hdoc") or redirect.get("Op") == "<<<":  # an expansion in either reads as $
                text.append(word(redirect.get("Hdoc") or redirect["Word"]))
    return text


def piped_into(script, node, parent):
    """What a pipe feeds a command, through any group, subshell or list around it."""
    while (up := parent.get(id(node))) is not None:
        if up.get("Type") == "BinaryCmd" and up["Op"] in ("|", "|&"):
            return fed(script, up["X"]) if up["Y"] is node else []
        if up.get("Type") not in (None, "Block", "Subshell", "BinaryCmd"):
            return []
        node = up
    return []


# shortcut: psql's syntax is read with regexes, so a :name or <a b> in an SQL comment or string counts (fails red),
# an abbreviated --comm is not resolved, and SQL from < file is not read; parse the SQL when a doc needs one of these.
def pasted_values(text, shell="sh"):
    """psql calls whose SQL takes a value other than as a psql variable (-v name=... and :'name' in SQL read
    from stdin): a shell expansion or <placeholder> in the SQL from -c, a heredoc, a here-string or what a pipe
    feeds in, or a psql variable in -c, which psql substitutes only in what it reads. Words are read as sh
    reads them, so an expansion, a backtick or a <placeholder> shows as $, and a literal $ counts too."""
    found = []
    for script, tree, _ in scripts(text, shell):
        parent = parents(tree)
        for call in nodes(tree, "CallExpr"):
            command = words(call)
            at = next((i for i, w in enumerate(command) if os.path.basename(w) == "psql"), None)
            if at is None:
                continue
            inline = [value for name, value in options(command[at + 1 :], PSQL_ARGS) if name in ("-c", "--command")]
            sql = inline + fed(script, parent[id(call)]) + piped_into(script, parent[id(call)], parent)
            if any("$" in s for s in sql) or any(PSQL_VARIABLE.search(s) for s in inline):
                found.append(span(script, call))
    return found


# shortcut: a status reset by a later command (|| { …; false; }; true) is not seen; gate tests catch it in a gate, so check what follows a branch when a doc writes one outside.
def open_failures(text, shell="sh"):
    """Failure branches that print (|| echo …, || { echo …; }, || ( echo … )) but exit 0: the branch
    does not end in false, return 1 or exit 1 (not negated or in the background), or what encloses it
    discards its status (status_lost). A compound command after || (if, case, a loop) is refused: write the
    branch as { …; }."""
    found = []
    for script, tree, _ in scripts(text, shell):
        parent = parents(tree)
        for node in (node for node in nodes(tree, "BinaryCmd") if node["Op"] == "||"):
            branch = node["Y"]["Cmd"]  # a | after a group binds to it, so a pipeline is the branch
            printed = any(prints(words(call)) for call in nodes(branch, "CallExpr"))
            last = branch.get("Stmts", [{}])[-1]
            fails = (
                branch["Type"] in ("Block", "Subshell")
                and not (node["Y"].get("Negated") or last.get("Negated") or last.get("Background"))
                and last.get("Cmd", {}).get("Type") == "CallExpr"
                and words(last["Cmd"]) in FAILS
            )
            if branch["Type"] in COMPOUND or (printed and (not fails or status_lost(node, parent))):
                found.append(span(script, node))
    return found


def is_gate(source, shell):
    """Whether a function prints STOP when its check fails, in a heredoc body too."""
    return any(prints(c) and any(w.startswith("STOP") for w in c) for c in commands(source, shell))


GATES = [
    pytest.param(path, name, source, shell, scope, id=f"{os.path.relpath(path, ROOT)}:{name}")
    for path in DOCS
    for name, source, shell, scope in functions(path)
    if is_gate(source, shell)
]


@pytest.fixture(scope="module")
def fakes(tmp_path_factory):
    bin_dir = tmp_path_factory.mktemp("bin")
    for name, body in (("curl", FAKE_CURL), ("cloudflared", FAKE_CLOUDFLARED)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    return bin_dir


def test_the_runbook_gates_are_found():
    assert {gate.values[1] for gate in GATES} >= {"closed", "keyless"}


def test_functions_are_found_in_every_form_sh_and_bash_allow(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text(
        "```sh\na()\n{\n  echo STOP\n}\nb () { echo STOP; }\ne ( ) { echo STOP; }; f() ( echo STOP )\n"
        "ssh h sh <<'EOF'\nk() {\n  echo STOP\n}\nEOF\npct exec 1 -- /bin/bash <<'EOF'\nm() { [[ -n $1 ]] || echo STOP; }\nEOF\n```\n\n"
        "```bash\nfunction c {\n  echo STOP\n}\nfunction d() { echo STOP; }\n```\n"
    )
    found = functions(str(doc))
    assert [(name, shell) for name, _, shell, _ in found] == [
        ("a", "sh"), ("b", "sh"), ("e", "sh"), ("f", "sh"), ("k", "sh"), ("m", "bash"), ("c", "bash"), ("d", "bash"),
    ]
    assert found[4:] == [  # a heredoc body runs in a shell of its own, the one the command it is fed to names
        ("k", "k() {\n  echo STOP\n}", "sh", "k() {\n  echo STOP\n}"),
        ("m", "m() { [[ -n $1 ]] || echo STOP; }", "bash", "m() { [[ -n $1 ]] || echo STOP; }"),
        ("c", "function c {\n  echo STOP\n}", "bash", None),
        ("d", "function d() { echo STOP; }", "bash", None),
    ]


@pytest.mark.parametrize(
    "source,gate",
    [
        ('g() { c || echo "STOP: failed"; }', True),
        ("g() {\n  ssh h sh <<'EOF'\nc || echo 'STOP: failed'\nEOF\n}", True),
        ("g() {\n  ssh h bash <<'EOF'\n[[ -n $x ]] || echo 'STOP: failed'\nEOF\n}", True),
        ("g() { echo OK; }", False),
    ],
)
def test_a_gate_is_a_function_that_prints_stop(source, gate):
    assert is_gate(source, "sh") == gate


@pytest.mark.parametrize(
    "args,answer,result",
    [
        (["-sS", "--fail-with-body", "-X", "DELETE"], "500", (22, "answer 500\n")),
        (["-fX", "DELETE"], "500", (22, "")),
        (["-sSfX", "DELETE"], "500", (22, "")),
        (["-sSXDELETE"], "500", (0, "answer 500\n")),
        (["--request", "DELETE", "--fail"], "500", (22, "")),
        (["--request=DELETE", "--fail"], "500", (22, "")),
        (["--output", "/dev/null", "--write-out", "%{http_code}", "--header", "X: 1", "-X", "DELETE"], "500", (0, "500")),
    ],
)
def test_the_fake_curl_reads_options_as_curl_does(fakes, args, answer, result):
    run = subprocess.run(
        [fakes / "curl", *args, "https://example.invalid"],
        env={**os.environ, "FAKE_ANSWER": answer}, capture_output=True, text=True, check=False,
    )
    assert (run.returncode, run.stdout) == result, run.stderr


def test_a_block_is_read_in_its_own_dialect(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text("```sh\nfunction c { echo STOP; }\n```\n")
    with pytest.raises(ValueError, match="cannot read this as sh"):
        functions(str(doc))


def test_every_fence_that_may_hold_shell_is_read(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_bytes(
        b"``` sh\na\n```\n\n  ~~~bash\n  b\n  ~~~\n\n```\nc\n```\n\n````shell\nd\n````\n\n```text\ne\n```\n"
        b"\n```sh\nf\n`````\n\n~~~\ng\n~~~~\n\r\n```sh\r\nh\r\n```\r\n\n```bash{1,3}\ni\n```\n"
    )
    assert blocks(str(doc)) == [
        ("sh", "a\n"), ("bash", "b\n"), ("", "c\n"), ("shell", "d\n"), ("sh", "f\n"), ("", "g\n"), ("sh", "h\n"), ("bash", "i\n"),
    ]


@pytest.mark.parametrize(
    "shell,source,status",
    [
        ("sh", 'g() { [ "$(c)" = "302" ] || echo STOP; }', {"302"}),
        ("bash", "g() { [[ $c == 401 ]] || echo STOP; }", {"401"}),
        ("sh", "g() {\n  ssh h sh <<'EOF'\n[ \"$(c)\" = 302 ] || echo STOP\nEOF\n}", {"302"}),
    ],
)
def test_a_gate_waits_for_the_status_it_compares_against(shell, source, status):
    assert waits_for(source, shell) == status


@pytest.mark.parametrize("path,name,source,shell,scope", GATES)
def test_a_gate_succeeds_only_on_the_status_it_waits_for(fakes, tmp_path, path, name, source, shell, scope):
    status = waits_for(source, shell)
    assert len(status) == 1, f"{name} compares against {status or 'no status'}; a gate waits for one"
    defined = "".join(f"{s}\n" for _, s, sh, sc in functions(path) if (sh, sc) == (shell, scope))
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
    assert passed == status


F_CHECK_CASES = [
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
    ("curl -x -f -X DELETE https://x", 1),
    ("curl -4X DELETE https://x", 1),
    ("curl -sS -X <METHOD> https://x", 1),
    ("ssh h <<'EOF'\ncurl -X DELETE https://x\nEOF", 1),
    ("psql <<'SQL'\nselect 1 from (t);\nSQL\ncurl -f -X DELETE https://x", 0),
    ("bash <<'EOF'\narr=(a b)\ncurl -X DELETE https://example.invalid\nEOF", 1),
    ("curl -sSfX DELETE https://x\ncurl -H 'X-f: 1' -fsS -X PUT https://x", 0),
    ("curl -sS -f -X PUT https://x/z\ncurl -fsS -X DELETE https://x\ncurl --fail -X PATCH https://x", 0),
    ('curl -sS -o /dev/null -w "%{http_code}" https://x/health', 0),
    (
        (
            "curl -sS --fail-with-body --request DELETE https://x\ncurl --request=PUT --fail --output /dev/null "
            "--write-out '%{http_code}' --header 'X: 1' --data-binary @- https://x\ncurl -fXDELETE -d x --data y https://x"
        ),
        0,
    ),
]


@pytest.mark.parametrize("shell,found", F_CHECK_CASES)
def test_the_f_check_finds_state_changing_calls_without_it(shell, found):
    assert len(unsafe_calls(shell)) == found


@pytest.mark.parametrize(
    "shell,refused",
    [(shell, []) for shell, _ in F_CHECK_CASES]
    + [("curl --user-agent x -f -X DELETE https://x", ["--user-agent"]), ("cloudflared access curl https://x --proxy http://p -sSf", ["--proxy"])],
)
def test_the_fakes_run_every_curl_call_the_f_check_accepts(fakes, tmp_path, shell, refused):
    complaints = [complaint for _, complaint in refusals(fakes, tmp_path, shell)]
    assert complaints == [f"fake curl: unsupported option {option}\n" for option in refused]


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_state_changing_call_fails_on_an_http_error(path):
    assert [call for shell, text in shell_in(path) for call in unsafe_calls(text, shell)] == []


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_the_fakes_run_every_curl_call_in_the_docs(fakes, tmp_path, path):
    assert [r for shell, text in shell_in(path) for r in refusals(fakes, tmp_path, text, shell)] == []


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
        ("check || { echo STOP; false; } && next || true", 1),
        ("check <host> || echo STOP", 1),
        ("check <key_file.pem> || echo STOP", 1),
        ("check || command echo STOP", 1),
        ("check || { echo STOP; ! false; }", 1),
        ("check || { echo STOP; false & }", 1),
        ("check || { echo STOP; false; } &", 1),
        ("check || { echo STOP; false; } >/dev/null &", 1),
        ("(check || { echo STOP; false; }) &\nwait", 1),
        ("! (check || { echo STOP; false; })", 1),
        ("(check || { echo STOP; false; }) | cat", 1),
        ("(check || { echo STOP; false; }) && next || true", 1),
        ("(check || { echo STOP; false; }) || true", 1),
        ("cat | (check || { echo STOP; false; })\n{ check || { echo STOP; return 1; }; } && next", 0),
        ("ssh h bash <<'EOF'\n[[ -n $x ]]\ncheck || echo STOP\nEOF", 1),
        ("if check || { echo STOP; false; }; then :; fi", 1),
        ("while check || { echo STOP; false; }; do :; done", 1),
        ("bash <<'EOF'\ntime (check || { echo STOP; false; }) || true\nEOF", 1),
        ("if check; then check || { echo STOP; false; }; fi", 0),
        ("check || ! { echo STOP; false; }", 1),
        ("ssh h <<'EOF'\ncheck || echo STOP\nEOF", 1),
        ("check 2>&1 || { echo STOP; false; }\ncheck || ( echo STOP; exit 1 )", 0),
        ('check || { echo "STOP: a; b"; false; }\nx() { check || { echo STOP; return 1; }; }', 0),
        ("check || { echo STOP; exit 1; }\ncheck || exit 1", 0),
    ],
)
def test_the_branch_check_finds_failure_branches_that_exit_0(shell, found):
    assert len(open_failures(shell)) == found


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_failure_branch_ends_in_failure(path):
    assert [branch for shell, text in shell_in(path) for branch in open_failures(text, shell)] == []


@pytest.mark.parametrize(
    "shell,found",
    [
        ("pg psql -d hindsight -Atc \"select id from agent_keys.keys where email = '<email>'\"", 1),
        ('pg psql -d hindsight -Atc "select status, count(*) from <schema>.async_operations group by 1"', 1),
        ("psql -X -c \"select 1 where email = '$email'\"", 1),
        ("pg psql -At -v email=\"$email\" -c \"select 1 where email = :'email'\"", 1),
        ('psql --command="select count(*) from :\\"schema\\".async_operations"', 1),
        ("echo \"select 1 where email = '<email>'\" | pg psql -d hindsight", 1),
        ("printf '%s\\n' \"select 1 where email = '$email'\" | psql", 1),
        ("pg psql -d hindsight <<'SQL'\nselect 1 where email = '<email>';\nSQL", 1),
        ("cat <<'SQL' | pg psql -d hindsight\nselect id from agent_keys.keys where email = '<email>';\nSQL", 1),
        ("cat <<EOF | psql\nselect 1 where email = '$email';\nEOF", 1),
        ("pg psql -d hindsight <<SQL\nselect 1 where email = '`cat email.txt`';\nSQL", 1),
        ("{ cat <<SQL\nselect 1 where email = '`cat email.txt`';\nSQL\n} | pg psql -d hindsight", 1),
        ("pg psql -d hindsight -Atc \"select id from agent_keys.keys where email = '<owner@example.com>'\"", 1),
        ("echo \"select 1 where email = '<first+tag@example.com>'\" | pg psql -d hindsight", 1),
        ("bash <<'EOF'\npg psql -d hindsight -At <<< \"select 1 where email = '<email>'\"\nEOF", 1),
        ("{ echo \"select 1 where email = '<email>'\"; } | pg psql -d hindsight", 1),
        ("( echo \"select 1 where email = '$email'\" ) | psql", 1),
        ("echo \"select 1 where email = '<email>'\" | tee /dev/stderr | pg psql -d hindsight", 1),
        ("\"$d/bin/psql\" -d hindsight -Atc \"select 1 where email = '<email>'\"", 1),
        ("psql -v id=\"$id\" -Atc 'select 1 where id = :id'", 1),
        ("psql -Atc 'select :{?e}'", 1),
        ("cat \"$file\" | pg psql -d hindsight\necho '' | psql -Atc 'select 1'", 0),
        (
            (
                "read -r -p 'Email: ' email &&\n  echo \"select id from agent_keys.keys where email = :'email'\" |\n"
                "  pg psql -X -d hindsight -At -v email=\"$email\""
            ),
            0,
        ),
        ("pg psql -d hindsight -Atc 'select role, email from agent_keys.allowlist order by 1, 2'", 0),
        ('pg psql -X -d hindsight -v schema="$schema" -v operator="$operator" < /root/purge-schema.sql', 0),
        ("pg psql -U \"$user\" -h <host> -Atc 'select x::text from t'", 0),
        ("echo \"$x\" | grep y", 0),
    ],
)
def test_the_sql_check_finds_values_pasted_into_sql(shell, found):
    assert len(pasted_values(shell)) == found


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_sql_value_is_a_psql_variable(path):
    assert [sql for shell, text in shell_in(path) for sql in pasted_values(text, shell)] == []
