"""End-to-end checks against the built image, run from the host with Docker.

IMAGE names the image under test (default hindsight-agent-keys:test). The tests
start the real container on Hindsight's mock LLM, so they need no credentials.
"""

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
BANK = "ci-bank"
STARTUP_SECONDS = 420
RUN = secrets.token_hex(4)

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
    out = docker("exec", container, "/app/api/.venv/bin/python", "-c", script)
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


@pytest.fixture(scope="module")
def volume():
    name = f"hak-it-{RUN}"
    docker("volume", "create", name)
    yield name
    docker("volume", "rm", "-f", name, check=False)


@pytest.fixture(scope="module")
def hindsight(volume):
    name = f"hak-it-{RUN}"
    env = {"HINDSIGHT_API_LLM_PROVIDER": "mock", "HINDSIGHT_API_TENANT_LEGACY_KEY": LEGACY}
    try:
        port = start(IMAGE, name, volume, env)
        yield {"name": name, "port": port}
    finally:
        docker("rm", "-f", name, check=False)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("HINDSIGHT_API_TENANT_EXTENSION", "hindsight_api.extensions.builtin.tenant:ApiKeyTenantExtension"),
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


def test_the_legacy_key_keeps_memory_in_public(hindsight):
    port = hindsight["port"]
    assert http(port, "GET", "/v1/default/banks", key=LEGACY)[0] == 200
    assert http(port, "PUT", f"/v1/default/banks/{BANK}", key=LEGACY, body={"mission": "ci"})[0] in (200, 201)

    status, text = http(
        port,
        "POST",
        f"/v1/default/banks/{BANK}/memories",
        key=LEGACY,
        body={"items": [{"content": "Alice works at Google."}], "async": True},
    )
    assert status in (200, 202), text
    operation = json.loads(text)["operation_id"]

    deadline = time.time() + 180
    state = None
    while time.time() < deadline:
        status, text = http(port, "GET", f"/v1/default/banks/{BANK}/operations/{operation}", key=LEGACY)
        assert status == 200, text
        state = json.loads(text)["status"]
        if state in ("completed", "failed"):
            break
        time.sleep(2)
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
