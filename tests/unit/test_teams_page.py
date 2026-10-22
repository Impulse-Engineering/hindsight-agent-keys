"""The Teams page: people create Teams, manage their members and create Team keys."""

import json

import pytest
from hindsight_api.models import RequestContext
from test_web import BYPASS, HOST, json_post, pages, signed_in

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"
DAVE = "dave@example.com"
ERIN = "erin@example.com"


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
    # Owners manage a Team only while they are on the Key Allowlist.
    assert client.post("/ext/admin/people", json={"email": CAROL, "role": "member"}, headers=as_person(team, ALICE)).status_code == 204
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
    resp = client.post(f"/ext/teams/{created}/members", json={"email": BOB, "role": "owner"}, headers=as_person(team, CAROL))
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


async def test_owners_and_admins_confirm_pending_requests_on_the_teams_page(team):
    client, ext, events = pages(team)
    created = create_team(client, team)
    await ext.set_member(ALICE, created, DAVE, "member", None)
    await ext.request_member(ALICE, created, "<b>c</b>@example.com", "owner", None)
    page = client.get("/ext/teams", headers=signed_in(team, email=DAVE)).text
    assert "&lt;b&gt;c&lt;/b&gt;@example.com as owner, asked by alice@example.com" in page and "<b>c</b>" not in page
    url = f"/ext/teams/{created}/confirmations"
    body = {"email": "<b>c</b>@example.com", "role": "owner"}
    resp = client.post(url, json=body, headers=as_person(team, DAVE))
    assert resp.status_code == 403 and "owners" in resp.json()["detail"]
    assert client.post(url, json=body, headers=as_person(team, BOB)).status_code == 200
    assert (await ext.teams(ALICE))[0]["members"][0] == {"email": "<b>c</b>@example.com", "role": "owner"}
    assert events.rows[-1]["kind"] == "owner_confirmed"
    resp = client.post(url, json=body, headers=as_person(team, BOB))
    assert resp.status_code == 404, resp.text


async def test_confirm_sends_the_role_the_page_showed_and_is_refused_if_the_request_changed(team):
    client, ext, _ = pages(team)
    created = create_team(client, team)
    await ext.request_member(ALICE, created, CAROL, "member", None)
    page = client.get("/ext/teams", headers=signed_in(team, email=ALICE)).text
    assert '<input type="hidden" name="role" value="member">' in page
    await ext.request_member(ALICE, created, CAROL, "owner", None)
    url = f"/ext/teams/{created}/confirmations"
    resp = client.post(url, json={"email": CAROL, "role": "member"}, headers=as_person(team, ALICE))
    assert resp.status_code == 409 and "reload" in resp.json()["detail"]
    assert (await ext.teams(ALICE))[0]["members"] == [{"email": ALICE, "role": "owner"}]


async def test_declining_a_pending_request_on_the_teams_page_keeps_the_person_in_the_team(team):
    client, ext, _ = pages(team)
    created = create_team(client, team)
    await ext.set_member(ALICE, created, CAROL, "member", None)
    await ext.request_member(ALICE, created, CAROL, "owner", None)
    url = f"/ext/teams/{created}/requests"
    resp = client.request("DELETE", url, json={"email": CAROL}, headers=as_person(team, ALICE))
    assert resp.status_code == 200, resp.text
    (shown,) = await ext.teams(ALICE)
    assert (shown["members"][1], shown["requests"]) == ({"email": CAROL, "role": "member"}, [])
    assert client.request("DELETE", url, json={"email": CAROL}, headers=as_person(team, ALICE)).status_code == 404


STATE_CHANGES = [
    ("POST", "/ext/teams", {"name": "Platform"}),
    ("POST", "/ext/teams/public/keys", {"name": "ci"}),
    ("POST", "/ext/teams/t_0000000000000000/members", {"email": CAROL, "role": "member"}),
    ("DELETE", "/ext/teams/t_0000000000000000/members", {"email": CAROL}),
    ("POST", "/ext/teams/t_0000000000000000/confirmations", {"email": CAROL, "role": "member"}),
    ("DELETE", "/ext/teams/t_0000000000000000/requests", {"email": CAROL}),
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


OWNER_REQUESTS = [
    pytest.param("POST", "members", {"email": ERIN, "role": "member"}, id="add a member"),
    pytest.param("DELETE", "members", {"email": DAVE}, id="remove a member"),
    pytest.param("POST", "confirmations", {"email": ERIN, "role": "member"}, id="approve a request"),
    pytest.param("DELETE", "requests", {"email": ERIN}, id="decline a request"),
    pytest.param("POST", "keys", {"name": "ci"}, id="create a Team key"),
]


@pytest.mark.parametrize(("method", "path", "body"), OWNER_REQUESTS)
async def test_an_owner_off_the_key_allowlist_is_refused_on_the_teams_page_until_added_back(team, method, path, body):
    client, ext, _ = pages(team)
    created = create_team(client, team)
    admin = as_person(team, ALICE)
    members = f"/ext/teams/{created}/members"

    def allowlist(role):
        return client.post("/ext/admin/people", json={"email": CAROL, "role": role}, headers=admin).status_code

    assert allowlist("member") == 204
    assert client.post(members, json={"email": CAROL, "role": "owner"}, headers=admin).status_code == 200
    assert client.post(members, json={"email": DAVE, "role": "member"}, headers=admin).status_code == 200
    await ext.request_member(ALICE, created, ERIN, "member", None)
    before = await ext.teams(ALICE)
    assert allowlist(None) == 204
    resp = client.request(method, f"/ext/teams/{created}/{path}", json=body, headers=as_person(team, CAROL))
    assert resp.status_code == 403 and "Key Allowlist" in resp.json()["detail"]
    assert await ext.teams(ALICE) == before
    assert await ext.list_keys(CAROL) == []
    # The same request is well formed: added back, the owner's call goes through.
    assert allowlist("member") == 204
    resp = client.request(method, f"/ext/teams/{created}/{path}", json=body, headers=as_person(team, CAROL))
    assert resp.status_code == 200, resp.text
