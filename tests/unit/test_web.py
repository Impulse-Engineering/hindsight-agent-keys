"""The key pages answer only on the Access-protected hostname, only to a signed-in person."""

from types import SimpleNamespace

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.web import AgentKeysHttpExtension

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
HOST = "keys.example.test"
BYPASS = "hindsight-api.example.test"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", "alice@example.com")


def pages(team, **overrides):
    config = {"key_pepper": PEPPER, "access_team_domain": team.url, "access_aud": team.aud, "access_host": HOST}
    config = {k: v for k, v in {**config, **overrides}.items() if v is not None}
    events = RecordedEvents()
    ext = AgentKeysTenantExtension(config, store=MemoryStore(), events=events)
    ext.set_context(Migrations())
    app = FastAPI()
    # Mounted as upstream mounts an HTTP extension (api/http.py:5301-5316).
    app.include_router(AgentKeysHttpExtension({}).get_router(SimpleNamespace(tenant_extension=ext)), prefix="/ext")
    return TestClient(app), ext, events


def signed_in(team, host=HOST, **claims):
    return {"Host": host, "Cf-Access-Jwt-Assertion": team.token(**claims)}


def json_post(team, host=HOST):
    return {**signed_in(team, host), "Content-Type": "application/json", "X-Agent-Keys": "1", "Origin": f"https://{HOST}"}


def test_a_signed_in_person_gets_the_key_page(team):
    client, _, _ = pages(team)
    resp = client.get("/ext/", headers=signed_in(team, email="Alice@Example.com"))
    assert resp.status_code == 200
    assert "alice@example.com" in resp.text


def test_the_page_escapes_the_email(team):
    client, _, _ = pages(team)
    resp = client.get("/ext/", headers=signed_in(team, email="<b>x</b>@example.com"))
    assert "<b>x</b>" not in resp.text
    assert "&lt;b&gt;x&lt;/b&gt;@example.com" in resp.text


@pytest.mark.parametrize("host", [BYPASS, f"{HOST}.{BYPASS}", "", "127.0.0.1:8888"])
def test_the_key_pages_refuse_any_other_hostname(team, host):
    client, _, _ = pages(team)
    assert client.get("/ext/", headers=signed_in(team, host)).status_code == 404
    assert client.post("/ext/keys", json={"name": "x"}, headers=json_post(team, host)).status_code == 404


def test_the_hostname_is_matched_without_case_or_port(team):
    client, _, _ = pages(team)
    assert client.get("/ext/", headers=signed_in(team, "Keys.Example.TEST:443")).status_code == 200


@pytest.mark.parametrize("missing", ["access_team_domain", "access_aud", "access_host"])
def test_without_full_access_configuration_the_key_pages_refuse_everything(team, missing):
    client, _, _ = pages(team, **{missing: None})
    assert client.get("/ext/", headers=signed_in(team)).status_code == 404


@pytest.mark.parametrize("token", [None, "", "not-a-jwt"])
def test_the_key_pages_refuse_a_missing_or_invalid_access_token(team, token):
    client, _, _ = pages(team)
    headers = {"Host": HOST} if token is None else {"Host": HOST, "Cf-Access-Jwt-Assertion": token}
    assert client.get("/ext/", headers=headers).status_code == 403


def test_the_key_pages_refuse_a_token_without_an_email(team):
    client, _, _ = pages(team)
    assert client.get("/ext/", headers=signed_in(team, email=None)).status_code == 403


async def test_a_new_key_is_shown_once_and_works(team):
    client, ext, events = pages(team)
    resp = client.post("/ext/keys", json={"name": "laptop"}, headers={**json_post(team), "X-Real-IP": "203.0.113.7"})
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["name"] == "laptop"
    assert body["key"].startswith(f"hsk_{body['id']}_")
    tenant = await ext.authenticate(RequestContext(api_key=body["key"]))
    assert tenant.schema_name.startswith("p_")
    assert [(r["kind"], r["email"], r["client_ip"]) for r in events.rows] == [
        ("key_created", "alice@example.com", "203.0.113.7")
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": None},
        {"X-Agent-Keys": None},
        {"X-Agent-Keys": "0"},
        {"Origin": None},
        {"Origin": "https://evil.example"},
        {"Origin": f"http://{HOST}"},
        {"Origin": f"https://{BYPASS}"},
    ],
)
def test_a_state_change_without_json_the_custom_header_and_a_matching_origin_is_refused(team, change):
    client, _, events = pages(team)
    headers = {k: v for k, v in {**json_post(team), **change}.items() if v is not None}
    resp = client.post("/ext/keys", content=b'{"name": "laptop"}', headers=headers)
    assert resp.status_code == 403
    assert events.rows == []


def test_someone_not_on_the_key_allowlist_cannot_create_a_key(team):
    client, _, events = pages(team)
    headers = {**json_post(team), "Cf-Access-Jwt-Assertion": team.token(email="mallory@example.com")}
    resp = client.post("/ext/keys", json={"name": "laptop"}, headers=headers)
    assert resp.status_code == 403
    assert "Key Allowlist" in resp.json()["detail"]
    assert events.rows == []


@pytest.mark.parametrize("name", ["", "   ", "x" * 101])
def test_a_key_needs_a_short_name(team, name):
    client, _, _ = pages(team)
    assert client.post("/ext/keys", json={"name": name}, headers=json_post(team)).status_code == 422


def test_the_key_pages_are_not_in_the_public_api_schema(team):
    client, _, _ = pages(team)
    assert not [path for path in client.app.openapi()["paths"] if path.startswith("/ext")]
