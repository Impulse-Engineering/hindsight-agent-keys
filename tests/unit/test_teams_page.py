"""The Teams page: people create Teams, manage their members and create Team keys."""

import json

import pytest
from hindsight_api.models import RequestContext
from test_web import BYPASS, HOST, json_post, pages, signed_in

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"


@pytest.fixture(autouse=True)
def allowlist(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", f"{ALICE},{BOB}")


def as_person(team, email, host=HOST):
    return {**json_post(team, host), "Cf-Access-Jwt-Assertion": team.token(email=email)}


def create_team(client, team, name="Platform", email=ALICE):
    resp = client.post("/ext/teams", json={"name": name}, headers=as_person(team, email))
    assert resp.status_code == 200, resp.text
    return resp.json()["team"]


def test_a_person_creates_a_team_and_sees_it_on_the_teams_page(team):
    client, _, events = pages(team)
    created = create_team(client, team, name="<Platform> $email")
    page = client.get("/ext/teams", headers=signed_in(team, email=ALICE))
    assert page.status_code == 200
    assert created in page.text and "&lt;Platform&gt; $email" in page.text and "<Platform>" not in page.text
    assert [r["kind"] for r in events.rows] == ["team_created"]


def test_owners_add_change_and_remove_members_by_email(team):
    client, _, _ = pages(team)
    created = create_team(client, team)
    url = f"/ext/teams/{created}/members"
    assert client.post(url, json={"email": " Carol@Example.com ", "role": "owner"}, headers=as_person(team, ALICE)).status_code == 200
    assert client.post(url, json={"email": BOB, "role": "member"}, headers=as_person(team, CAROL)).status_code == 200
    resp = client.request("DELETE", url, json={"email": BOB}, headers=as_person(team, CAROL))
    assert resp.status_code == 200, resp.text
    page = client.get("/ext/teams", headers=signed_in(team, email=CAROL)).text
    assert ALICE in page and CAROL in page and BOB not in page


@pytest.mark.parametrize(
    "body", [{"email": "not-an-email", "role": "member"}, {"email": CAROL, "role": "admin"}, {"email": CAROL}]
)
def test_a_member_needs_an_email_and_a_role(team, body):
    client, _, _ = pages(team)
    created = create_team(client, team)
    assert client.post(f"/ext/teams/{created}/members", json=body, headers=as_person(team, ALICE)).status_code == 422


def test_refusals_answer_with_their_status_and_reason(team):
    client, _, _ = pages(team)
    created = create_team(client, team)
    resp = client.post(f"/ext/teams/{created}/members", json={"email": CAROL, "role": "owner"}, headers=as_person(team, CAROL))
    assert resp.status_code == 403 and "owners" in resp.json()["detail"]
    resp = client.post("/ext/teams", json={"name": "public"}, headers=as_person(team, ALICE))
    assert resp.status_code == 409 and "reserved" in resp.json()["detail"]
    resp = client.request("DELETE", f"/ext/teams/{created}/members", json={"email": ALICE}, headers=as_person(team, ALICE))
    assert resp.status_code == 409 and "owner" in resp.json()["detail"]


async def test_members_create_team_keys_shown_once(team):
    client, ext, _ = pages(team)
    created = create_team(client, team)
    resp = client.post(f"/ext/teams/{created}/keys", json={"name": "ci"}, headers=as_person(team, ALICE))
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["key"].startswith(f"hsk_{body['id']}_")
    assert (await ext.authenticate(RequestContext(api_key=body["key"]))).schema_name == created


async def test_people_on_the_key_allowlist_create_public_team_keys(team):
    client, ext, _ = pages(team)
    resp = client.post("/ext/teams/public/keys", json={"name": "ci"}, headers=as_person(team, BOB))
    assert resp.status_code == 200, resp.text
    assert (await ext.authenticate(RequestContext(api_key=resp.json()["key"]))).schema_name == "public"
    assert client.post("/ext/teams/public/keys", json={"name": "ci"}, headers=as_person(team, CAROL)).status_code == 403


STATE_CHANGES = [
    ("POST", "/ext/teams", {"name": "Platform"}),
    ("POST", "/ext/teams/public/keys", {"name": "ci"}),
    ("POST", "/ext/teams/t_0000000000000000/members", {"email": CAROL, "role": "member"}),
    ("DELETE", "/ext/teams/t_0000000000000000/members", {"email": CAROL}),
]


@pytest.mark.parametrize(("method", "path", "body"), STATE_CHANGES)
@pytest.mark.parametrize("change", [{"Content-Type": "text/plain"}, {"X-Agent-Keys": None}, {"Origin": "https://evil.example"}])
def test_team_changes_without_json_the_custom_header_and_a_matching_origin_are_refused(team, method, path, body, change):
    client, _, events = pages(team)
    headers = {k: v for k, v in {**as_person(team, ALICE), **change}.items() if v is not None}
    assert client.request(method, path, content=json.dumps(body).encode(), headers=headers).status_code == 403
    assert events.rows == []


def test_the_teams_page_refuses_the_bypass_hostname(team):
    client, _, _ = pages(team)
    assert client.get("/ext/teams", headers=signed_in(team, BYPASS)).status_code == 404
    assert client.post("/ext/teams", json={"name": "x"}, headers=as_person(team, ALICE, BYPASS)).status_code == 404
