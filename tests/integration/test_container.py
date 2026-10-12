"""End-to-end checks against the built image, run from the host with Docker.

IMAGE names the image under test (default hindsight-agent-keys:test). The tests
start the real container on Hindsight's mock LLM, so they need no credentials.
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

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


def mcp(port, key, payload):
    headers = {"Accept": "application/json, text/event-stream"}
    status, text = http(port, "POST", "/mcp/", key=key, body=payload, headers=headers)
    messages = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:")]
    if not messages and text.strip().startswith("{"):
        messages = [json.loads(text)]
    return status, messages


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
        ("HINDSIGHT_API_MCP_AUTH_TOKEN", "any-token"),
        ("HINDSIGHT_ENABLE_CP", "true"),
        ("HINDSIGHT_API_DATABASE_SCHEMA", "sentinel"),
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


@pytest.fixture(scope="module")
def two_people(hindsight):
    return {email: personal_key(hindsight, email)["key"] for email in (ALICE, BOB)}


def test_two_peoples_keys_each_see_only_their_own_banks(hindsight, two_people):
    port = hindsight["port"]
    assert http(port, "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)
    own = {ALICE: "alice-private", BOB: "bob-private"}
    for email, key in two_people.items():
        assert http(port, "PUT", f"/v1/default/banks/{own[email]}", key=key, body={"mission": "ci"})[0] in (200, 201)

    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}},
    }
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_banks", "arguments": {}}}
    for email, key in two_people.items():
        status, text = http(port, "GET", "/v1/default/banks", key=key)
        assert status == 200, text
        assert {b["bank_id"] for b in json.loads(text)["banks"]} == {own[email]}
        assert mcp(port, key, init)[0] == 200
        status, messages = mcp(port, key, call)
        assert status == 200, messages
        listed = json.dumps(messages)
        other = own[BOB] if email == ALICE else own[ALICE]
        assert own[email] in listed
        assert other not in listed and BANK not in listed

    # Each bank sits in its owner's generated schema, and nothing new reached public.
    people = {r["email"]: r["schema"] for r in query(hindsight["name"], "SELECT email, schema FROM agent_keys.people")}
    for email, bank in own.items():
        assert query(hindsight["name"], f'SELECT bank_id FROM "{people[email]}".banks') == [{"bank_id": bank}]
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
    created = personal_key(hindsight, CAROL, name="lifecycle")
    key_id, key = created["id"], created["key"]
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 200
    query(name, f"UPDATE agent_keys.sign_ins SET last_seen = now() - interval '30 days' WHERE email = '{CAROL}' RETURNING email")
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 401
    # Any key page request with a fresh Access token is a sign-in, and revives the key.
    assert key_page(hindsight, "GET", "/ext/", CAROL)[0] == 200
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 200

    query(name, f"UPDATE agent_keys.keys SET expires_at = now() + interval '1 day' WHERE id = '{key_id}' RETURNING id")
    ip = "203.0.113.81"
    status, text = key_page(hindsight, "POST", f"/ext/keys/{key_id}/renew", CAROL, body={}, headers={"X-Real-IP": ip})
    assert status == 200, text
    assert query(name, f"SELECT expires_at > now() + interval '89 days' AS renewed FROM agent_keys.keys WHERE id = '{key_id}'") == [
        {"renewed": True}
    ]
    assert query(name, f"SELECT kind, key_id, email FROM agent_keys.events WHERE client_ip = '{ip}'") == [
        {"kind": "key_renewed", "key_id": key_id, "email": CAROL}
    ]

    query(name, f"UPDATE agent_keys.keys SET expires_at = now() WHERE id = '{key_id}' RETURNING id")
    assert http(port, "GET", "/v1/default/banks", key=key)[0] == 401
    status, text = key_page(hindsight, "GET", "/ext/keys", CAROL)
    assert {k["id"]: k["state"] for k in json.loads(text)}[key_id] == "expired"
    assert key_page(hindsight, "POST", f"/ext/keys/{key_id}/renew", CAROL, body={})[0] == 404


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


def test_stock_hindsight_starts_on_the_same_database(hindsight, volume):
    assert http(hindsight["port"], "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)
    # The database also holds a personal schema, which stock Hindsight neither lists nor migrates.
    personal_key(hindsight, ERIN)
    personal = query(hindsight["name"], "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'p\\_%'")
    assert personal, "no personal schema to start stock Hindsight against"
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
