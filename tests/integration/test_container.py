"""End-to-end checks against the built image, run from the host with Docker.

IMAGE names the image under test (default hindsight-agent-keys:test). The tests
start the real container on Hindsight's mock LLM, so they need no credentials.
"""

import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from markdown_it import MarkdownIt

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IMAGE = os.environ.get("IMAGE", "hindsight-agent-keys:test")
# The stock image this one is built FROM, read from the Dockerfile pin.
UPSTREAM = subprocess.run(
    [os.path.join(ROOT, "scripts", "upstream-ref.sh")], capture_output=True, text=True, check=True
).stdout.strip()
LEGACY = secrets.token_urlsafe(32)
PEPPER = secrets.token_urlsafe(32)
BANK = "ci-bank"
STARTUP_SECONDS = 420
RUN = secrets.token_hex(4)
PYTHON = "/app/api/.venv/bin/python"

# A stand-in Cloudflare Access team: the container serves its signing keys to itself.
ACCESS_PORT = 8999
TEAM = f"http://127.0.0.1:{ACCESS_PORT}"
AUD = "ci-access-aud"
ACCESS_HOST = "keys.example.test"
BYPASS_HOST = "hindsight-api.example.test"
# Delegated Requests: the delegation application and WorkPlane's application, on the same team.
DELEGATION_HOST = "delegation.example.test"
DELEGATION_AUD = "ci-delegation-aud"
WORKPLANE_AUD = "ci-workplane-aud"
DELEGATE_ID = "ci-workplane.access"
ADMINS = ["alice@example.test", "bob@example.test", "carol@example.test", "dave@example.test", "erin@example.test"]
ALICE, BOB, CAROL, DAVE, ERIN = ADMINS

# Routines that only a migration of `public` installs; upstream #5400 leaves them missing.
PUBLIC_ROUTINES = {"banks_needing_consolidation", "mental_models_with_cron", "schemas_with_expired_rows"}


def docker(*args, check=True, timeout=600):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(port, method, path, key=None, body=None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    if key is not None:
        req.add_header("Authorization", f"Bearer {key}")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=60) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def mcp(port, key, payload, path="/mcp/"):
    headers = {"Accept": "application/json, text/event-stream"}
    status, text = http(port, "POST", path, key=key, body=payload, headers=headers)
    messages = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:")]
    if not messages and text.strip().startswith("{"):
        messages = [json.loads(text)]
    return status, messages


def call_tool(port, key, path, tool, **arguments):
    """Call an MCP tool on the endpoint at `path` and return its JSON answer."""
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    status, messages = mcp(port, key, call, path)
    assert status == 200, messages
    return json.loads(messages[-1]["result"]["content"][0]["text"])


def wait_healthy(port, container):
    deadline = time.time() + STARTUP_SECONDS
    while time.time() < deadline:
        state = docker("inspect", "-f", "{{.State.Running}}", container, check=False).stdout.strip()
        if state != "true":
            logs = docker("logs", "--tail", "60", container, check=False)
            pytest.fail(f"{container} stopped during startup:\n{logs.stdout}\n{logs.stderr}")
        try:
            if http(port, "GET", "/health")[0] == 200:
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(3)
    pytest.fail(f"{container} was not healthy within {STARTUP_SECONDS}s")


def start(image, name, volume, env):
    port = free_port()
    args = ["run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:8888", "-v", f"{volume}:/home/hindsight/.pg0"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    docker(*args, image)
    wait_healthy(port, name)
    return port


def in_container(container, script):
    """Run Python inside the container against its pg0 database; returns parsed JSON output."""
    out = docker("exec", container, PYTHON, "-c", script)
    return json.loads(out.stdout.strip().splitlines()[-1])


DB_QUERY = """
import asyncio, json
import asyncpg
from pg0 import Pg0
async def main():
    conn = await asyncpg.connect(Pg0(name="hindsight").info().uri)
    try:
        rows = await conn.fetch(QUERY)
        print(json.dumps([dict(r) for r in rows], default=str))
    finally:
        await conn.close()
asyncio.run(main())
"""


def query(container, sql):
    return in_container(container, f"QUERY = {sql!r}\n{DB_QUERY}")


ACCESS_TOKEN = """
import json, os, time, urllib.request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
pem, certs = "/tmp/access-key.pem", "/tmp/access/cdn-cgi/access/certs"
if not os.path.exists(pem):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.makedirs(os.path.dirname(certs), exist_ok=True)
    with open(certs, "w") as f:
        json.dump({"keys": [{**RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), "kid": "ci", "use": "sig"}]}, f)
    with open(pem, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
try:
    urllib.request.urlopen(TEAM + "/cdn-cgi/access/certs", timeout=2).close()
    serving = True
except OSError:
    serving = False
with open(pem, "rb") as f:
    key = serialization.load_pem_private_key(f.read(), None)
now = int(time.time())
claims = {"iss": TEAM, "aud": [AUD], "iat": now, "exp": now + 600, **CLAIMS}
claims = {k: v for k, v in claims.items() if v is not None}
print(json.dumps({"serving": serving, "token": jwt.encode(claims, key, algorithm="RS256", headers={"kid": "ci"})}))
"""


def access_token(container, **claims):
    """A JWT as Access would issue it; a claim set to None is left out."""
    script = f"TEAM = {TEAM!r}\nAUD = {AUD!r}\nCLAIMS = {claims!r}\n{ACCESS_TOKEN}"
    out = in_container(container, script)
    if not out["serving"]:
        # Started on first use and again after a restart.
        docker("exec", "-d", container, PYTHON, "-m", "http.server", str(ACCESS_PORT),
               "--bind", "127.0.0.1", "--directory", "/tmp/access")
        deadline = time.time() + 30
        while not out["serving"]:
            assert time.time() < deadline, "the stand-in Access team did not start"
            time.sleep(0.5)
            out = in_container(container, script)
    return out["token"]


def key_page(hindsight, method, path, email, host=ACCESS_HOST, body=None, headers=None):
    """A request from a person signed in through Access, as the key page's script sends it."""
    sent = {"Host": host, "Cf-Access-Jwt-Assertion": access_token(hindsight["name"], email=email)}
    if method != "GET":
        sent |= {"X-Agent-Keys": "1", "Origin": f"https://{ACCESS_HOST}"}
    return http(hindsight["port"], method, path, body=body, headers={**sent, **(headers or {})})


def delegated(hindsight, method, path, email, body=None, delegate=None, person=None):
    """A Delegated Request: WorkPlane's service-token JWT, as Access forwards it, and the person's own JWT.
    `delegate` and `person` override that credential's claims; None drops one."""
    service = {"common_name": DELEGATE_ID, "sub": "", "aud": [DELEGATION_AUD], **(delegate or {})}
    signed_in = {"email": email, "aud": [WORKPLANE_AUD], **(person or {})}
    sent = {
        "Host": DELEGATION_HOST,
        "Cf-Access-Jwt-Assertion": access_token(hindsight["name"], **service),
        "X-Delegated-Access-Jwt": access_token(hindsight["name"], **signed_in),
    }
    return http(hindsight["port"], method, path, body=body, headers=sent)


def personal_key(hindsight, email, name="ci"):
    status, text = key_page(hindsight, "POST", "/ext/keys", email, body={"name": name})
    assert status == 200, text
    return json.loads(text)


def retain_and_wait(port, key, bank, content):
    """Retain asynchronously and wait until the worker has processed it."""
    assert http(port, "PUT", f"/v1/default/banks/{bank}", key=key, body={"mission": "ci"})[0] in (200, 201)
    status, text = http(
        port, "POST", f"/v1/default/banks/{bank}/memories", key=key, body={"items": [{"content": content}], "async": True}
    )
    assert status in (200, 202), text
    operation = json.loads(text)["operation_id"]
    deadline = time.time() + 180
    state = None
    while time.time() < deadline:
        status, text = http(port, "GET", f"/v1/default/banks/{bank}/operations/{operation}", key=key)
        assert status == 200, text
        state = json.loads(text)["status"]
        if state in ("completed", "failed"):
            break
        time.sleep(2)
    return state


@pytest.fixture(scope="module")
def volume():
    name = f"hak-it-{RUN}"
    docker("volume", "create", name)
    yield name
    docker("volume", "rm", "-f", name, check=False)


@pytest.fixture(scope="module")
def hindsight(volume):
    name = f"hak-it-{RUN}"
    env = {
        "HINDSIGHT_API_LLM_PROVIDER": "mock",
        "HINDSIGHT_API_TENANT_LEGACY_KEY": LEGACY,
        "HINDSIGHT_API_TENANT_KEY_PEPPER": PEPPER,
        "HINDSIGHT_API_TENANT_ACCESS_TEAM_DOMAIN": TEAM,
        "HINDSIGHT_API_TENANT_ACCESS_AUD": AUD,
        "HINDSIGHT_API_TENANT_ACCESS_HOST": ACCESS_HOST,
        "HINDSIGHT_API_TENANT_DELEGATION_HOST": DELEGATION_HOST,
        "HINDSIGHT_API_TENANT_DELEGATION_AUD": DELEGATION_AUD,
        "HINDSIGHT_API_TENANT_WORKPLANE_AUD": WORKPLANE_AUD,
        "HINDSIGHT_API_TENANT_DELEGATE_CLIENT_ID": DELEGATE_ID,
        # Mixed case and spaces, as an operator might type them.
        "AGENT_KEYS_ADMIN_EMAILS": " , ".join(e.capitalize() for e in ADMINS),
    }
    try:
        port = start(IMAGE, name, volume, env)
        yield {"name": name, "port": port}
    finally:
        docker("rm", "-f", name, check=False)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("HINDSIGHT_API_TENANT_EXTENSION", "hindsight_api.extensions.builtin.tenant:ApiKeyTenantExtension"),
        ("HINDSIGHT_API_HTTP_EXTENSION", ""),
        ("HINDSIGHT_API_MCP_EXTENSION", ""),
        ("HINDSIGHT_API_MCP_AUTH_TOKEN", "any-token"),
        ("HINDSIGHT_ENABLE_CP", "true"),
        ("HINDSIGHT_API_DATABASE_SCHEMA", "sentinel"),
        ("HINDSIGHT_API_AUDIT_LOG_ACTIONS", ""),
    ],
)
def test_the_container_refuses_to_start_with_an_unsafe_setting(variable, value):
    result = docker("run", "--rm", "-e", f"{variable}={value}", IMAGE, check=False, timeout=180)
    assert result.returncode == 78
    assert variable in result.stderr
    assert "README" in result.stderr
    assert "Hindsight is running" not in result.stdout


@pytest.mark.parametrize("path", ["/app/api/.env", "/app/.env", "/.env"])
def test_the_container_refuses_to_start_with_a_dotenv_file(tmp_path, path):
    dotenv = tmp_path / "dotenv"
    dotenv.write_text("HINDSIGHT_API_TENANT_EXTENSION=hindsight_api.extensions.builtin.tenant:DefaultTenantExtension\n")
    dotenv.chmod(0o644)
    result = docker("run", "--rm", "-v", f"{dotenv}:{path}:ro", IMAGE, check=False, timeout=180)
    assert result.returncode == 78
    assert path in result.stderr


def test_overriding_the_command_does_not_skip_the_guard():
    result = docker(
        "run", "--rm", "-e", "HINDSIGHT_API_MCP_AUTH_TOKEN=any-token", IMAGE, "/app/start-all.sh",
        check=False, timeout=180,
    )
    assert result.returncode == 78
    assert "HINDSIGHT_API_MCP_AUTH_TOKEN" in result.stderr


@pytest.mark.parametrize("key", [None, "not-a-key", "hsk_abc123_" + "x" * 43])
def test_a_missing_or_unknown_key_gets_401_on_the_api(hindsight, key):
    status, _ = http(hindsight["port"], "GET", "/v1/default/banks", key=key)
    assert status == 401


@pytest.mark.parametrize("key", [None, "not-a-key"])
def test_a_missing_or_unknown_key_gets_401_on_mcp(hindsight, key):
    status, _ = mcp(hindsight["port"], key, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert status == 401


def test_an_mcp_get_probe_without_a_session_returns_only_an_empty_object(hindsight):
    # Upstream answers this client handshake probe before authentication; it is
    # the one unauthenticated MCP response, and it carries no data.
    status, text = http(hindsight["port"], "GET", "/mcp/")
    assert (status, json.loads(text)) == (200, {})


@pytest.mark.parametrize("key", [None, "not-a-key"])
def test_an_mcp_get_with_a_session_id_still_needs_a_key(hindsight, key):
    status, _ = http(hindsight["port"], "GET", "/mcp/", key=key, headers={"Mcp-Session-Id": "any-session"})
    assert status == 401


def test_the_legacy_key_keeps_memory_in_public(hindsight):
    port = hindsight["port"]
    assert http(port, "GET", "/v1/default/banks", key=LEGACY)[0] == 200
    state = retain_and_wait(port, LEGACY, BANK, "Alice works at Google.")
    assert state == "completed", "the worker did not process the retain task in public"

    status, text = http(
        port, "POST", f"/v1/default/banks/{BANK}/memories/recall", key=LEGACY, body={"query": "Where does Alice work?"}
    )
    assert status == 200, text
    assert "Alice" in text

    rows = query(hindsight["name"], f"SELECT bank_id FROM public.banks WHERE bank_id = '{BANK}'")
    assert rows == [{"bank_id": BANK}]


def test_the_legacy_key_lists_banks_over_mcp(hindsight):
    port = hindsight["port"]
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}},
    }
    status, messages = mcp(port, LEGACY, init)
    assert status == 200, messages
    http(port, "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_banks", "arguments": {}}}
    status, messages = mcp(port, LEGACY, call)
    assert status == 200, messages
    assert BANK in json.dumps(messages)


def test_a_bank_config_cannot_switch_on_upstream_audit_logging(hindsight):
    # A bank row stored under stock Hindsight, or restored verbatim by transfer/import or clone
    # (engine/transfer/importer.py:1063-1069), can carry audit_log_enabled. Upstream reads it
    # before authenticating (api/http.py:4984-4995, engine/memory_engine.py:3149-3170).
    port, name, bank = hindsight["port"], hindsight["name"], "ci-audit"
    # Inserted as a restore would, so no cached copy of the row hides the stored config.
    query(
        name,
        "INSERT INTO public.banks (bank_id, name, mission, internal_id, config) VALUES"
        f" ('{bank}', '{bank}', '', gen_random_uuid(), '{{\"audit_log_enabled\": true}}') RETURNING bank_id",
    )
    before = query(name, "SELECT count(*) AS n FROM public.audit_log")
    recall = {"query": "Where does Alice work?"}
    assert http(port, "POST", f"/v1/default/banks/{bank}/memories/recall", body=recall)[0] == 401
    assert http(port, "POST", f"/v1/default/banks/{bank}/memories/recall", key=LEGACY, body=recall)[0] == 200
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "recall", "arguments": recall}}
    assert mcp(port, None, call, f"/mcp/{bank}/")[0] == 401
    call_tool(port, LEGACY, f"/mcp/{bank}/", "recall", **recall)
    time.sleep(5)  # upstream writes audit rows in the background
    assert query(name, "SELECT count(*) AS n FROM public.audit_log") == before


def test_public_is_fully_migrated_at_startup(hindsight):
    rows = query(
        hindsight["name"],
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'",
    )
    assert PUBLIC_ROUTINES <= {r["proname"] for r in rows}
    assert query(hindsight["name"], "SELECT count(*) AS n FROM public.alembic_version") == [{"n": 1}]


def test_a_refused_key_is_recorded_with_the_client_ip(hindsight):
    ip = "203.0.113.50"
    status, _ = http(hindsight["port"], "GET", "/v1/default/banks", key="hsk_refusedid_" + "y" * 43, headers={"X-Real-IP": ip})
    assert status == 401
    rows = query(
        hindsight["name"],
        f"SELECT kind, key_id, client_ip FROM agent_keys.events WHERE client_ip = '{ip}'",
    )
    assert rows == [{"kind": "key_refused", "key_id": "refusedid", "client_ip": ip}]


def test_the_key_page_refuses_the_bypass_hostname(hindsight):
    status, text = key_page(hindsight, "GET", "/ext/", ALICE)
    assert status == 200 and ALICE in text
    assert key_page(hindsight, "GET", "/ext/", ALICE, host=BYPASS_HOST)[0] == 404
    assert key_page(hindsight, "POST", "/ext/keys", ALICE, host=BYPASS_HOST, body={"name": "x"})[0] == 404


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": ["another-application"]},
        {"iss": "https://another-team.cloudflareaccess.com"},
        {"email": None, "common_name": "a-service-token"},
        {"exp": int(time.time()) - 60},
    ],
)
def test_the_key_page_refuses_an_access_token_that_fails_validation(hindsight, claims):
    token = access_token(hindsight["name"], **{"email": ALICE, **claims})
    headers = {"Host": ACCESS_HOST, "Cf-Access-Jwt-Assertion": token}
    assert http(hindsight["port"], "GET", "/ext/", headers=headers)[0] == 403


def test_the_key_page_refuses_a_request_without_an_access_token(hindsight):
    assert http(hindsight["port"], "GET", "/ext/", headers={"Host": ACCESS_HOST})[0] == 403


def test_people_not_on_the_key_allowlist_cannot_create_keys(hindsight):
    status, text = key_page(hindsight, "POST", "/ext/keys", "mallory@example.test", body={"name": "x"})
    assert status == 403, text


def test_an_admin_manages_the_key_allowlist(hindsight):
    frank = "frank@example.test"

    def change(email, role, admin=ALICE):
        return key_page(hindsight, "POST", "/ext/admin/people", admin, body={"email": email, "role": role})

    assert key_page(hindsight, "POST", "/ext/access-requests", frank, body={})[0] == 204
    status, text = key_page(hindsight, "GET", "/ext/admin", ALICE)
    assert status == 200 and frank in text and "Asked to join" in text
    assert key_page(hindsight, "GET", "/ext/admin", frank)[0] == 403
    assert change(BOB, "member", admin=frank)[0] == 403

    assert change(frank, "member")[0] == 204
    key = personal_key(hindsight, frank)["key"]
    assert http(hindsight["port"], "GET", "/v1/default/banks", key=key)[0] == 200
    assert change(frank, None)[0] == 204
    assert http(hindsight["port"], "GET", "/v1/default/banks", key=key)[0] == 401
    assert change(BOB, None)[0] == 409

    rows = query(
        hindsight["name"],
        f"SELECT kind, actor FROM agent_keys.events WHERE email = '{frank}' AND key_id = '(none)' ORDER BY id",
    )
    assert [(r["kind"], r["actor"]) for r in rows] == [
        ("access_requested", frank),
        ("access_approved", ALICE),
        ("allowlist_removed", ALICE),
    ]


def test_a_delegate_files_a_key_allowlist_request_for_the_person_signed_in_to_it(hindsight):
    hana, path = "hana@example.test", "/ext/delegated/access-requests"
    # A person's JWT in place of WorkPlane's service token is refused.
    assert delegated(hindsight, "POST", path, hana, body={}, delegate={"email": hana, "common_name": None})[0] == 403
    for _ in range(2):
        status, text = delegated(hindsight, "POST", path, hana, body={})
        assert (status, json.loads(text) if status == 200 else text) == (200, {"email": hana, "role": "requested"})
    rows = query(hindsight["name"], f"SELECT kind, actor, channel, delegate FROM agent_keys.events WHERE email = '{hana}'")
    assert rows == [{"kind": "access_requested", "actor": hana, "channel": "delegated", "delegate": DELEGATE_ID}]


def test_an_older_person_jwt_on_a_delegated_request_does_not_move_the_sign_in(hindsight):
    iris, path = "iris@example.test", "/ext/delegated/access-requests"
    hour_ago = int(time.time()) - 3600

    def last_seen():
        sql = f"SELECT extract(epoch FROM last_seen)::bigint AS at FROM agent_keys.sign_ins WHERE email = '{iris}'"
        return [r["at"] for r in query(hindsight["name"], sql)]

    assert delegated(hindsight, "POST", path, iris, body={}, person={"iat": hour_ago})[0] == 200
    assert last_seen() == [hour_ago]
    assert delegated(hindsight, "POST", path, iris, body={}, person={"iat": hour_ago - 600})[0] == 200
    assert last_seen() == [hour_ago]


@pytest.fixture(scope="module")
def two_people(hindsight):
    return {email: personal_key(hindsight, email)["key"] for email in (ALICE, BOB)}


def team_page(hindsight, method, path, email, body):
    status, text = key_page(hindsight, method, path, email, body=body)
    assert status == 200, text
    return json.loads(text)


@pytest.fixture(scope="module")
def ci_team(hindsight):
    """Alice's Team, with Bob as a member holding a Team key."""
    team = team_page(hindsight, "POST", "/ext/teams", ALICE, {"name": "CI Team"})["team"]
    team_page(hindsight, "POST", f"/ext/teams/{team}/members", ALICE, {"email": BOB, "role": "member"})
    return {"team": team, "key": team_page(hindsight, "POST", f"/ext/teams/{team}/keys", BOB, {"name": "ci"})["key"]}


def test_two_people_and_a_team_each_see_only_their_own_banks(hindsight, two_people, ci_team):
    port = hindsight["port"]
    assert http(port, "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)
    keys = {**two_people, "team": ci_team["key"]}
    own = {ALICE: "alice-private", BOB: "bob-private", "team": "team-shared"}
    for holder, key in keys.items():
        assert http(port, "PUT", f"/v1/default/banks/{own[holder]}", key=key, body={"mission": "ci"})[0] in (200, 201)

    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}},
    }
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_banks", "arguments": {}}}
    for holder, key in keys.items():
        status, text = http(port, "GET", "/v1/default/banks", key=key)
        assert status == 200, text
        assert {b["bank_id"] for b in json.loads(text)["banks"]} == {own[holder]}
        assert mcp(port, key, init)[0] == 200
        status, messages = mcp(port, key, call)
        assert status == 200, messages
        listed = json.dumps(messages)
        assert own[holder] in listed
        assert not [b for b in [*own.values(), BANK] if b != own[holder] and b in listed]

    # Each bank sits in its holder's generated schema, and nothing new reached public.
    schemas = {r["email"]: r["schema"] for r in query(hindsight["name"], "SELECT email, schema FROM agent_keys.people")}
    schemas["team"] = ci_team["team"]
    for holder, bank in own.items():
        assert query(hindsight["name"], f'SELECT bank_id FROM "{schemas[holder]}".banks') == [{"bank_id": bank}]
    public = {r["bank_id"] for r in query(hindsight["name"], "SELECT bank_id FROM public.banks")}
    assert not public & set(own.values())


def test_the_worker_processes_background_tasks_in_a_personal_schema(hindsight, two_people):
    port, key = hindsight["port"], two_people[ALICE]
    state = retain_and_wait(port, key, "alice-memory", "Alice keeps her notes in a red notebook.")
    assert state == "completed", "the worker did not process the retain task in a personal schema"
    status, text = http(
        port, "POST", "/v1/default/banks/alice-memory/memories/recall", key=key, body={"query": "Where are Alice's notes?"}
    )
    assert status == 200, text
    assert "notebook" in text


def test_the_worker_processes_background_tasks_in_a_team_schema(hindsight, ci_team):
    port, key = hindsight["port"], ci_team["key"]
    state = retain_and_wait(port, key, "team-memory", "The CI Team deploys on Tuesdays.")
    assert state == "completed", "the worker did not process the retain task in a Team schema"
    status, text = http(
        port, "POST", "/v1/default/banks/team-memory/memories/recall", key=key, body={"query": "When does the team deploy?"}
    )
    assert status == 200, text
    assert "Tuesday" in text


def test_a_public_team_key_reaches_the_banks_in_public(hindsight, two_people):
    port = hindsight["port"]
    assert http(port, "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)
    key = team_page(hindsight, "POST", "/ext/teams/public/keys", CAROL, {"name": "ci"})["key"]
    status, text = http(port, "GET", "/v1/default/banks", key=key)
    assert status == 200, text
    banks = {b["bank_id"] for b in json.loads(text)["banks"]}
    assert BANK in banks and "alice-private" not in banks


def test_removing_a_member_stops_their_team_key_on_the_next_request(hindsight, ci_team):
    port, team = hindsight["port"], ci_team["team"]
    team_page(hindsight, "POST", f"/ext/teams/{team}/members", ALICE, {"email": CAROL, "role": "member"})
    key = team_page(hindsight, "POST", f"/ext/teams/{team}/keys", CAROL, {"name": "ci"})["key"]
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 200
    team_page(hindsight, "DELETE", f"/ext/teams/{team}/members", ALICE, {"email": CAROL})
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 401
    rows = query(hindsight["name"], f"SELECT kind, email, actor FROM agent_keys.events WHERE team = '{team}' ORDER BY id")
    assert rows[0] == {"kind": "team_created", "email": ALICE, "actor": ALICE}
    assert rows[-1] == {"kind": "member_removed", "email": CAROL, "actor": ALICE}


def test_a_team_keeps_an_owner_and_a_unique_name_and_public_is_reserved(hindsight, ci_team):
    team = ci_team["team"]
    status, text = key_page(hindsight, "DELETE", f"/ext/teams/{team}/members", ALICE, body={"email": ALICE})
    assert status == 409, text
    for name in ("ci team", "Public"):
        status, text = key_page(hindsight, "POST", "/ext/teams", BOB, body={"name": name})
        assert status == 409, text
    status, page = key_page(hindsight, "GET", "/ext/teams", BOB)
    assert status == 200 and "CI Team" in page and f"{ALICE} (owner)" in page and f"{BOB} (member)" in page


MCP_ENDPOINTS = ["/mcp/", f"/mcp/{BANK}/"]


def test_agents_manage_teams_over_both_mcp_endpoints_but_only_an_owner_lets_anyone_in(hindsight, two_people):
    port, key = hindsight["port"], two_people[ALICE]
    multi, single = MCP_ENDPOINTS
    team = call_tool(port, key, multi, "create_team", name="MCP Team")["team"]
    answer = call_tool(port, key, single, "add_team_member", team=team, email=ERIN.upper())
    assert answer == {"team": team, "email": ERIN, "role": "member", "status": "pending"}
    call_tool(port, key, multi, "add_team_member", team=team, email=CAROL, role="owner")
    (listed,) = [t for t in call_tool(port, key, single, "list_teams")["teams"] if t["team"] == team]
    assert listed["members"] == [{"email": ALICE, "role": "owner"}]
    assert listed["requests"] == [
        {"email": CAROL, "role": "owner", "by": ALICE},
        {"email": ERIN, "role": "member", "by": ALICE},
    ]
    team_page(hindsight, "DELETE", f"/ext/teams/{team}/requests", ALICE, {"email": CAROL})

    # Nobody is in the Team until an owner confirms, on the Teams page, the role the request asks for.
    status, text = key_page(hindsight, "POST", f"/ext/teams/{team}/confirmations", ALICE, body={"email": ERIN, "role": "owner"})
    assert status == 409, text
    status, text = key_page(hindsight, "POST", f"/ext/teams/{team}/keys", ERIN, body={"name": "ci"})
    assert status == 403, text
    team_page(hindsight, "POST", f"/ext/teams/{team}/confirmations", ALICE, {"email": ERIN, "role": "member"})
    erin = team_page(hindsight, "POST", f"/ext/teams/{team}/keys", ERIN, {"name": "ci"})["key"]
    assert http(port, "GET", "/v1/default/banks", key=erin)[0] == 200

    assert call_tool(port, key, multi, "remove_team_member", team=team, email=ERIN) == {"team": team, "email": ERIN}
    assert http(port, "GET", "/v1/default/banks", key=erin)[0] == 401
    rows = query(hindsight["name"], f"SELECT kind, email, actor FROM agent_keys.events WHERE team = '{team}' ORDER BY id")
    assert [(r["kind"], r["email"], r["actor"]) for r in rows] == [
        ("team_created", ALICE, ALICE),
        ("member_requested", ERIN, ALICE),
        ("owner_requested", CAROL, ALICE),
        ("owner_declined", CAROL, ALICE),
        ("member_confirmed", ERIN, ALICE),
        ("key_created", ERIN, ERIN),
        ("member_removed", ERIN, ALICE),
    ]


@pytest.mark.parametrize("path", MCP_ENDPOINTS)
def test_team_keys_and_the_legacy_key_cannot_create_teams_or_change_membership_over_mcp(hindsight, ci_team, path):
    port, team = hindsight["port"], ci_team["team"]
    for key in (ci_team["key"], LEGACY):
        for tool, arguments in [
            ("create_team", {"name": "Not allowed"}),
            ("add_team_member", {"team": team, "email": CAROL, "role": "owner"}),
            ("remove_team_member", {"team": team, "email": BOB}),
        ]:
            assert "personal Agent Key" in call_tool(port, key, path, tool, **arguments)["error"]
    assert query(hindsight["name"], "SELECT schema FROM agent_keys.teams WHERE name = 'Not allowed'") == []
    assert query(hindsight["name"], f"SELECT email FROM agent_keys.member_requests WHERE team = '{team}'") == []
    assert {"email": BOB, "role": "member"} in query(
        hindsight["name"], f"SELECT email, role FROM agent_keys.members WHERE team = '{team}'"
    )


def test_a_new_key_is_stored_as_an_hmac_and_its_creation_logged(hindsight):
    created = personal_key(hindsight, CAROL, name="laptop")
    key = created["key"]
    assert key.startswith(f"hsk_{created['id']}_")
    rows = query(hindsight["name"], f"SELECT *, encode(digest, 'hex') AS hex FROM agent_keys.keys WHERE id = '{created['id']}'")
    assert rows[0]["hex"] == hmac.new(PEPPER.encode(), key.encode(), hashlib.sha256).hexdigest()
    assert key.split("_", 2)[2] not in json.dumps(rows)
    assert (rows[0]["email"], rows[0]["name"]) == (CAROL, "laptop")


def test_key_creation_is_logged_with_the_key_id_person_and_client_ip(hindsight):
    ip = "203.0.113.70"
    status, text = key_page(hindsight, "POST", "/ext/keys", ERIN, body={"name": "ci"}, headers={"X-Real-IP": ip})
    assert status == 200, text
    rows = query(hindsight["name"], f"SELECT kind, key_id, email, client_ip FROM agent_keys.events WHERE client_ip = '{ip}'")
    assert rows == [{"kind": "key_created", "key_id": json.loads(text)["id"], "email": ERIN, "client_ip": ip}]


def test_key_creation_is_rate_limited_and_active_keys_are_capped(hindsight):
    def create():
        return key_page(hindsight, "POST", "/ext/keys", DAVE, body={"name": "ci"})

    for _ in range(5):
        assert create()[0] == 200
    status, text = create()
    assert status == 429 and "an hour" in text
    # An hour later the rate allows more, until the cap on active keys.
    query(hindsight["name"], f"UPDATE agent_keys.keys SET created_at = now() - interval '2 hours' WHERE email = '{DAVE}' RETURNING id")
    for _ in range(5):
        assert create()[0] == 200
    status, text = create()
    assert status == 429 and "active keys" in text
    # A revoked key no longer counts against the cap (an hour on again, so only the cap applies).
    rows = query(hindsight["name"], f"UPDATE agent_keys.keys SET created_at = now() - interval '2 hours' WHERE email = '{DAVE}' RETURNING id")
    assert key_page(hindsight, "POST", f"/ext/keys/{rows[0]['id']}/revoke", DAVE, body={})[0] == 200
    assert create()[0] == 200


def test_revoking_a_key_stops_it_within_an_open_mcp_session(hindsight):
    port = hindsight["port"]
    created = personal_key(hindsight, CAROL, name="agent")
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}},
    }
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_banks", "arguments": {}}}
    assert mcp(port, created["key"], init)[0] == 200
    assert mcp(port, created["key"], call)[0] == 200
    ip = "203.0.113.80"
    status, text = key_page(hindsight, "POST", f"/ext/keys/{created['id']}/revoke", CAROL, body={}, headers={"X-Real-IP": ip})
    assert status == 200, text
    # No auth cache: the very next call in the same session is refused.
    assert mcp(port, created["key"], call)[0] == 401
    rows = query(hindsight["name"], f"SELECT kind, key_id, email FROM agent_keys.events WHERE client_ip = '{ip}'")
    assert rows == [{"kind": "key_revoked", "key_id": created["id"], "email": CAROL}]


def test_a_key_needs_its_owner_to_sign_in_every_30_days_and_expires_unless_renewed(hindsight):
    port, name = hindsight["port"], hindsight["name"]
    created = personal_key(hindsight, BOB, name="lifecycle")
    key_id, key = created["id"], created["key"]
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 200
    query(name, f"UPDATE agent_keys.sign_ins SET last_seen = now() - interval '30 days' WHERE email = '{BOB}' RETURNING email")
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 401
    # Any key page request with a fresh Access token is a sign-in, and revives the key.
    assert key_page(hindsight, "GET", "/ext/", BOB)[0] == 200
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 200

    query(name, f"UPDATE agent_keys.keys SET expires_at = now() + interval '1 day' WHERE id = '{key_id}' RETURNING id")
    ip = "203.0.113.81"
    status, text = key_page(hindsight, "POST", f"/ext/keys/{key_id}/renew", BOB, body={}, headers={"X-Real-IP": ip})
    assert status == 200, text
    assert query(name, f"SELECT expires_at > now() + interval '89 days' AS renewed FROM agent_keys.keys WHERE id = '{key_id}'") == [
        {"renewed": True}
    ]
    assert query(name, f"SELECT kind, key_id, email FROM agent_keys.events WHERE client_ip = '{ip}'") == [
        {"kind": "key_renewed", "key_id": key_id, "email": BOB}
    ]

    query(name, f"UPDATE agent_keys.keys SET expires_at = now() WHERE id = '{key_id}' RETURNING id")
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 401
    status, text = key_page(hindsight, "GET", "/ext/keys", BOB)
    assert {k["id"]: k["state"] for k in json.loads(text)}[key_id] == "expired"
    assert key_page(hindsight, "POST", f"/ext/keys/{key_id}/renew", BOB, body={})[0] == 404


def test_revoke_identity_disables_every_key_the_person_holds(hindsight):
    port = hindsight["port"]
    keys = [personal_key(hindsight, ERIN, name=n)["key"] for n in ("one", "two")]
    assert [http(port, "GET", "/v1/default/banks", key=k)[0] for k in keys] == [200, 200]
    ip = "203.0.113.82"
    body = {"email": ERIN.upper()}
    status, text = key_page(hindsight, "POST", "/ext/admin/revoke-identity", ALICE, body=body, headers={"X-Real-IP": ip})
    assert status == 200, text
    assert [http(port, "GET", "/v1/default/banks", key=k)[0] for k in keys] == [401, 401]
    unrevoked = f"SELECT count(*) AS n FROM agent_keys.keys WHERE email = '{ERIN}' AND revoked_at IS NULL"
    assert query(hindsight["name"], unrevoked) == [{"n": 0}]
    assert query(hindsight["name"], f"SELECT kind, email, actor FROM agent_keys.events WHERE client_ip = '{ip}'") == [
        {"kind": "identity_revoked", "email": ERIN, "actor": ALICE}
    ]


# A tool named by $0 (psql) from pg0's own installation, as the operator runs it (docs/cutover.md).
PG0 = 'd=$(ls -d /home/hindsight/.pg0/installation/*/ | tail -1); LD_LIBRARY_PATH="$d/lib" exec "$d/bin/$0" "$@"'


def database_uri(container):
    return in_container(container, "import json\nfrom pg0 import Pg0\nprint(json.dumps(Pg0(name='hindsight').info().uri))")


def purge(container, **variables):
    """Run scripts/purge-schema.sql on stdin, with these psql variables."""
    uri = database_uri(container)
    with open(os.path.join(ROOT, "scripts", "purge-schema.sql")) as script:
        return subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-c", PG0, "psql", "-X", uri,
             *(f"--set={k}={v}" for k, v in variables.items())],
            stdin=script, capture_output=True, text=True, timeout=300, check=False,
        )


def test_a_stale_personal_schema_is_reported_to_admins_and_purged_only_by_the_operator(hindsight, two_people):
    name, gina, operator = hindsight["name"], "gina@example.test", "ops@example.test"
    assert key_page(hindsight, "POST", "/ext/admin/people", ALICE, body={"email": gina, "role": "member"})[0] == 204
    personal_key(hindsight, gina)
    team = team_page(hindsight, "POST", "/ext/teams", gina, {"name": "Gina's Team"})["team"]
    for target in (team, "public"):
        team_page(hindsight, "POST", f"/ext/teams/{target}/keys", gina, {"name": "ci"})
    schema = query(name, f"SELECT schema FROM agent_keys.people WHERE email = '{gina}'")[0]["schema"]

    def reported(expired_days_ago=None, signed_in_days_ago=0):
        """Backdate every key Gina holds and her last sign-in; (schema, owner) rows of the admin page's report."""
        expires = "now() + interval '1 day'" if expired_days_ago is None else f"now() - interval '{expired_days_ago} days'"
        query(name, f"UPDATE agent_keys.keys SET expires_at = {expires} WHERE email = '{gina}' RETURNING id")
        query(name, f"UPDATE agent_keys.sign_ins SET last_seen = now() - interval '{signed_in_days_ago} days'"
                    f" WHERE email = '{gina}' RETURNING email")
        status, text = key_page(hindsight, "GET", "/ext/admin", ALICE)
        assert status == 200, text
        return re.findall(r"<tr><td>([^<]*)</td><td>([^<]*)</td><td>[^<]*</td></tr>", text.partition("Stale personal schemas")[2])

    assert (schema, gina) not in reported()
    assert (schema, gina) not in reported(expired_days_ago=89)
    # Keys that have not expired count from 30 days after their owner's last sign-in.
    assert (schema, gina) not in reported(signed_in_days_ago=119)
    assert (schema, gina) in reported(signed_in_days_ago=121)
    rows = reported(expired_days_ago=91)
    assert (schema, gina) in rows
    # Gina's Team and Public Team keys are just as stale, yet only personal schemas are listed.
    assert all(s.startswith("p_") for s, _ in rows)

    # The script refuses anything the report does not list, and a run without the operator's email.
    alices = query(name, f"SELECT schema FROM agent_keys.people WHERE email = '{ALICE}'")[0]["schema"]
    for refused in (alices, team, "public", f"{schema}'; --"):
        run = purge(name, schema=refused, operator=operator, wait=0)
        assert run.returncode != 0 and "no rows returned for \\gset" in run.stderr, run.stdout + run.stderr
    run = purge(name, schema=schema, wait=0)
    assert run.returncode != 0 and "syntax error" in run.stderr, run.stdout + run.stderr
    assert query(name, f"SELECT schema FROM agent_keys.people WHERE email = '{gina}'") == [{"schema": schema}]
    assert query(name, f"SELECT count(*) AS n FROM pg_namespace WHERE nspname IN ('{alices}', '{team}', '{schema}')") == [{"n": 3}]

    # A schema its owner holds again by the drop step is not dropped.
    owned = f"SELECT schema FROM agent_keys.people WHERE email = '{gina}'"
    with concurrent.futures.ThreadPoolExecutor() as pool:
        running = pool.submit(purge, name, schema=schema, operator=operator, wait=20)
        deadline = time.time() + 60
        while query(name, owned) != [{"schema": None}]:
            assert time.time() < deadline and not running.done(), "step 1 did not unlist the schema"
            time.sleep(0.5)
        query(name, f"UPDATE agent_keys.people SET schema = '{schema}' WHERE email = '{gina}' RETURNING email")
        run = running.result()
    assert run.returncode != 0 and "Unlisted" in run.stdout, run.stdout + run.stderr
    assert "no rows returned for \\gset" in run.stderr, run.stdout + run.stderr
    assert query(name, f"SELECT count(*) AS n FROM pg_namespace WHERE nspname = '{schema}'") == [{"n": 1}]

    run = purge(name, schema=schema, operator=operator, wait=0)
    assert run.returncode == 0, run.stdout + run.stderr
    assert query(name, f"SELECT count(*) AS n FROM pg_namespace WHERE nspname = '{schema}'") == [{"n": 0}]
    assert query(name, f"SELECT count(*) AS n FROM agent_keys.keys WHERE schema = '{schema}' AND revoked_at IS NULL") == [{"n": 0}]
    assert query(name, "SELECT key_id, email, actor, team FROM agent_keys.events WHERE kind = 'schema_purged'") == [
        {"key_id": "(none)", "email": gina, "actor": operator, "team": schema}
    ]
    assert (schema, gina) not in reported(expired_days_ago=91)
    # Gina's next personal key gets a new schema.
    personal_key(hindsight, gina)
    assert query(name, f"SELECT schema FROM agent_keys.people WHERE email = '{gina}'")[0]["schema"] not in (None, schema)


def doc_block(path, containing):
    """The one fenced block in a doc that contains this text, exactly as the doc writes it."""
    with open(os.path.join(ROOT, path)) as fh:
        found = [t.content for t in MarkdownIt("commonmark").parse(fh.read()) if t.type == "fence" and containing in t.content]
    assert len(found) == 1, f"{path}: {len(found)} blocks contain {containing!r}"
    return found[0]


def run_doc(container, block, answers, **env):
    """Run a doc's shell block on the host as an operator who types answers at its prompts, with these shell
    variables set and the runbook's pg helper reaching this container's database."""
    uri = urllib.parse.urlsplit(database_uri(container))
    pg_env = {"PGHOST": uri.hostname, "PGPORT": str(uri.port), "PGUSER": uri.username, "PGPASSWORD": uri.password}
    pg = f'pg() {{ docker exec -i -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD {container} sh -c {shlex.quote(PG0)} "$@"; }}'
    return subprocess.run(
        ["sh", "-c", f"{pg}\n{block}"], input=answers, env={**os.environ, **pg_env, **env},
        capture_output=True, text=True, timeout=120, check=False,
    )


def test_the_operating_guides_check_lists_every_key_of_a_revoked_identity_as_revoked(hindsight):
    owner = "o'connor@example.test"  # a valid address that breaks SQL with the value pasted in
    assert key_page(hindsight, "POST", "/ext/admin/people", ALICE, body={"email": owner, "role": "member"})[0] == 204
    for name in ("one", "two"):
        personal_key(hindsight, owner, name=name)
    status, text = key_page(hindsight, "POST", "/ext/admin/revoke-identity", ALICE, body={"email": owner})
    assert status == 200, text
    run = run_doc(hindsight["name"], doc_block("docs/operating.md", "where email = :'email'"), f"{owner}\n")
    assert run.returncode == 0, run.stdout + run.stderr
    rows = [line.split("|") for line in run.stdout.splitlines()]
    assert len(rows) == 2 and all(revoked_at for *_, revoked_at in rows), run.stdout


def test_the_readmes_purge_recovery_puts_the_schema_back_on_the_list_once(hindsight):
    name, owner = hindsight["name"], "d'arcy@example.test"
    assert key_page(hindsight, "POST", "/ext/admin/people", ALICE, body={"email": owner, "role": "member"})[0] == 204
    personal_key(hindsight, owner)
    quoted = owner.replace("'", "''")
    owned = f"SELECT schema FROM agent_keys.people WHERE email = '{quoted}'"
    schema = query(name, owned)[0]["schema"]
    # As a purge leaves it when it stops after step 1.
    query(name, f"UPDATE agent_keys.people SET schema = NULL WHERE email = '{quoted}' RETURNING email")
    block = doc_block("README.md", "read -r -p 'Owner email: ' owner")
    run = run_doc(name, block, f"{owner}\n", schema=schema)
    assert (run.returncode, run.stdout.splitlines()) == (0, [owner, "UPDATE 1"]), run.stderr
    assert query(name, owned) == [{"schema": schema}]
    # Once the owner holds a schema, it returns no row and changes nothing.
    run = run_doc(name, block, f"{owner}\n", schema=schema)
    assert (run.returncode, run.stdout.splitlines()) == (0, ["UPDATE 0"]), run.stderr
    # Nor does it list a schema that step 3 dropped before the connection failed.
    query(name, f"UPDATE agent_keys.people SET schema = NULL WHERE email = '{quoted}' RETURNING email")
    query(name, f"DROP SCHEMA {schema} CASCADE")
    run = run_doc(name, block, f"{owner}\n", schema=schema)
    assert (run.returncode, run.stdout.splitlines()) == (0, ["UPDATE 0"]), run.stderr
    assert query(name, owned) == [{"schema": None}]


def test_the_bundled_ui_is_not_listening(hindsight):
    probe = (
        "import json, socket\n"
        "s = socket.socket()\n"
        "try:\n"
        "    s.connect(('127.0.0.1', 9999)); print(json.dumps('open'))\n"
        "except OSError:\n"
        "    print(json.dumps('closed'))\n"
    )
    assert in_container(hindsight["name"], probe) == "closed"


def test_a_restart_reuses_the_event_log(hindsight):
    def refuse_from(ip):
        status, _ = http(hindsight["port"], "GET", "/v1/default/banks", key="not-a-key", headers={"X-Real-IP": ip})
        assert status == 401

    refuse_from("203.0.113.61")
    docker("restart", hindsight["name"])
    wait_healthy(hindsight["port"], hindsight["name"])
    refuse_from("203.0.113.62")
    rows = query(
        hindsight["name"],
        "SELECT client_ip FROM agent_keys.events WHERE client_ip IN ('203.0.113.61', '203.0.113.62') ORDER BY id",
    )
    assert [r["client_ip"] for r in rows] == ["203.0.113.61", "203.0.113.62"]


def test_concurrent_delegated_creations_stop_at_the_workplane_cap(hindsight):
    port, name, kim = hindsight["port"], hindsight["name"], "kim@example.test"
    # On the Key Allowlist, and not an admin.
    assert key_page(hindsight, "POST", "/ext/admin/people", ALICE, body={"email": kim, "role": "member"})[0] == 204
    own = personal_key(hindsight, kim)
    # 23 WorkPlane keys created two hours ago, so the hourly limit lets every creation below through: only the cap refuses.
    query(
        name,
        "INSERT INTO agent_keys.keys (id, digest, name, email, schema, kind, expires_at, via, created_at)"
        f" SELECT 'old' || n, decode('00', 'hex'), 'old', email, schema, 'personal', now() + interval '1 day',"
        f" '{DELEGATE_ID}', now() - interval '2 hours' FROM agent_keys.people, generate_series(1, 23) n"
        f" WHERE email = '{kim}' RETURNING id",
    )
    # Minted once, so the creations below reach the server together.
    sent = {
        "Host": DELEGATION_HOST,
        "Cf-Access-Jwt-Assertion": access_token(name, common_name=DELEGATE_ID, sub="", aud=[DELEGATION_AUD]),
        "X-Delegated-Access-Jwt": access_token(name, email=kim, aud=[WORKPLANE_AUD]),
    }

    def create(n, body=None):
        headers = {**sent, "Idempotency-Key": f"ci-{n}"}
        return http(port, "POST", "/ext/delegated/keys", body=body or {"name": f"wp{n}"}, headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(create, range(8)))
    assert sorted(status for status, _ in answers) == [200, 200] + [429] * 6, answers
    active = f"SELECT count(*) AS n FROM agent_keys.keys WHERE email = '{kim}' AND via IS NOT NULL AND revoked_at IS NULL"
    assert query(name, active) == [{"n": 25}]
    # A retry returns the key it created, without the key, even at the cap; another body is refused.
    n, created = next((n, json.loads(text)) for n, (status, text) in enumerate(answers) if status == 200)
    status, text = create(n)
    assert (status, json.loads(text)) == (200, {"id": created["id"], "name": created["name"]})
    assert create(n, {"name": "another"})[0] == 409
    # 24 hours on, the same idempotency key is a new creation, which the cap refuses.
    query(name, f"UPDATE agent_keys.idempotency SET created_at = now() - interval '24 hours' WHERE email = '{kim}' RETURNING key")
    assert create(n)[0] == 429
    # Delegated list, renew and revoke reach only the WorkPlane keys, and the key page counts its own apart.
    status, text = http(port, "GET", "/ext/delegated/keys", headers=sent)
    assert status == 200, text
    assert [k["id"] for k in json.loads(text) if k["via"] != DELEGATE_ID or k["id"] == own["id"]] == []
    for action in ("renew", "revoke"):
        assert http(port, "POST", f"/ext/delegated/keys/{own['id']}/{action}", body={}, headers=sent)[0] == 404
    personal_key(hindsight, kim)


def test_the_kill_switch_revokes_every_key_created_via_workplane_and_no_other(hindsight):
    port, name, lee = hindsight["port"], hindsight["name"], "lee@example.test"
    assert key_page(hindsight, "POST", "/ext/admin/people", ALICE, body={"email": lee, "role": "member"})[0] == 204
    own = personal_key(hindsight, lee)["key"]
    sent = {
        "Host": DELEGATION_HOST,
        "Cf-Access-Jwt-Assertion": access_token(name, common_name=DELEGATE_ID, sub="", aud=[DELEGATION_AUD]),
        "X-Delegated-Access-Jwt": access_token(name, email=lee, aud=[WORKPLANE_AUD]),
        "Idempotency-Key": "kill-switch",
    }
    status, text = http(port, "POST", "/ext/delegated/keys", body={"name": "wp"}, headers=sent)
    assert status == 200, text
    workplane = json.loads(text)["key"]
    assert [http(port, "GET", "/v1/default/banks", key=k)[0] for k in (own, workplane)] == [200, 200]
    # A WorkPlane key revoked before the kill switch keeps its revocation time and is not counted.
    status, text = http(port, "POST", "/ext/delegated/keys", body={"name": "earlier"}, headers={**sent, "Idempotency-Key": "ks-2"})
    earlier = json.loads(text)["id"]
    assert http(port, "POST", f"/ext/delegated/keys/{earlier}/revoke", body={}, headers=sent)[0] == 200
    revoked_at = f"SELECT revoked_at::text AS at FROM agent_keys.keys WHERE id = '{earlier}'"
    before = query(name, revoked_at)
    # Earlier tests in this container leave other people's WorkPlane keys active; the kill switch takes them all.
    active = query(name, "SELECT count(*)::int AS n FROM agent_keys.keys WHERE via IS NOT NULL AND revoked_at IS NULL")[0]["n"]
    assert active >= 1
    ip = "203.0.113.83"
    status, text = key_page(hindsight, "POST", "/ext/admin/revoke-workplane-keys", ALICE, body={}, headers={"X-Real-IP": ip})
    assert (status, json.loads(text)) == (200, {"revoked": active}), text
    assert query(name, revoked_at) == before
    assert [http(port, "GET", "/v1/default/banks", key=k)[0] for k in (own, workplane)] == [200, 401]
    run = run_doc(name, doc_block("docs/operating.md", "where via is not null and revoked_at is null"), "")
    assert (run.returncode, run.stdout) == (0, "0\n"), run.stdout + run.stderr
    assert query(name, f"SELECT kind, email, actor, channel FROM agent_keys.events WHERE client_ip = '{ip}'") == [
        {"kind": "workplane_keys_revoked", "email": None, "actor": ALICE, "channel": "ext"}
    ]


def test_stock_hindsight_starts_on_the_same_database(hindsight, volume, ci_team):
    assert http(hindsight["port"], "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)
    # The database also holds a personal and a Team schema, which stock Hindsight neither lists nor migrates.
    personal_key(hindsight, ERIN)
    for prefix in ("p", "t"):
        found = query(hindsight["name"], f"SELECT nspname FROM pg_namespace WHERE nspname LIKE '{prefix}\\_%'")
        assert found, f"no {prefix}_ schema to start stock Hindsight against"
    docker("rm", "-f", hindsight["name"])
    name = f"hak-it-stock-{RUN}"
    env = {
        "HINDSIGHT_API_LLM_PROVIDER": "mock",
        "HINDSIGHT_API_TENANT_EXTENSION": "hindsight_api.extensions.builtin.tenant:ApiKeyTenantExtension",
        "HINDSIGHT_API_TENANT_API_KEY": LEGACY,
        "HINDSIGHT_ENABLE_CP": "false",
    }
    try:
        port = start(UPSTREAM, name, volume, env)
        status, text = http(port, "GET", "/v1/default/banks", key=LEGACY)
        assert status == 200, text
        assert BANK in text
    finally:
        docker("rm", "-f", name, check=False)
