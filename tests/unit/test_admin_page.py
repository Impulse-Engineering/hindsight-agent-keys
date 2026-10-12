"""Admins manage the Key Allowlist at /ext/admin; anyone signed in can ask to join from /ext/."""

import pytest
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext
from test_web import json_post, pages, signed_in

ADMIN = "alice@example.com"
MALLORY = "mallory@example.com"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


def as_person(team, email):
    return {**json_post(team), "Cf-Access-Jwt-Assertion": team.token(email=email)}


def set_role(client, team, email, role, actor=ADMIN):
    return client.post("/ext/admin/people", json={"email": email, "role": role}, headers=as_person(team, actor))


def test_someone_not_on_the_list_asks_to_join_and_an_admin_approves(team):
    client, _, events = pages(team)
    assert "Ask an admin" in client.get("/ext/", headers=signed_in(team, email=MALLORY)).text
    resp = client.post("/ext/access-requests", headers={**as_person(team, MALLORY), "X-Real-IP": "203.0.113.9"})
    assert resp.status_code == 204, resp.text
    assert "waiting for an admin" in client.get("/ext/", headers=signed_in(team, email=MALLORY)).text

    page = client.get("/ext/admin", headers=signed_in(team, email=ADMIN))
    assert page.status_code == 200
    assert MALLORY in page.text and "Asked to join" in page.text

    assert set_role(client, team, " Mallory@Example.COM ", "member").status_code == 204
    assert client.post("/ext/keys", json={"name": "laptop"}, headers=as_person(team, MALLORY)).status_code == 200
    assert [(r["kind"], r["email"], r["actor"], r["client_ip"]) for r in events.rows][:2] == [
        ("access_requested", MALLORY, MALLORY, "203.0.113.9"),
        ("access_approved", MALLORY, ADMIN, None),
    ]


async def test_an_admin_removes_someone_and_their_keys_stop(team):
    client, ext, _ = pages(team)
    set_role(client, team, MALLORY, "member")
    key = client.post("/ext/keys", json={"name": "laptop"}, headers=as_person(team, MALLORY)).json()["key"]
    assert set_role(client, team, MALLORY, None).status_code == 204
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=key))
    assert MALLORY not in client.get("/ext/admin", headers=signed_in(team, email=ADMIN)).text
    assert client.post("/ext/keys", json={"name": "desktop"}, headers=as_person(team, MALLORY)).status_code == 403


@pytest.mark.parametrize("role", [None, "requested", "member", "demoted"])
def test_people_without_admin_rights_cannot_reach_any_admin_action(team, role):
    client, _, events = pages(team)
    if role == "requested":
        client.post("/ext/access-requests", headers=as_person(team, MALLORY))
    elif role == "member":
        set_role(client, team, MALLORY, "member")
    elif role == "demoted":
        set_role(client, team, MALLORY, "admin")
        set_role(client, team, MALLORY, "member")
    before = list(events.rows)
    assert "/ext/admin" not in client.get("/ext/", headers=signed_in(team, email=MALLORY)).text
    assert client.get("/ext/admin", headers=signed_in(team, email=MALLORY)).status_code == 403
    for target, new in [(MALLORY, "admin"), ("carol@example.com", "member"), (ADMIN, None)]:
        assert set_role(client, team, target, new, actor=MALLORY).status_code == 403
    assert events.rows == before


def test_a_granted_admin_manages_the_list(team):
    client, _, _ = pages(team)
    assert set_role(client, team, MALLORY, "admin").status_code == 204
    assert "/ext/admin" in client.get("/ext/", headers=signed_in(team, email=MALLORY)).text
    assert client.get("/ext/admin", headers=signed_in(team, email=MALLORY)).status_code == 200
    assert set_role(client, team, "carol@example.com", "member", actor=MALLORY).status_code == 204


@pytest.mark.parametrize("role", [None, "member"])
def test_the_bootstrap_admins_cannot_be_changed_from_the_page(team, role):
    client, _, _ = pages(team)
    set_role(client, team, MALLORY, "admin")
    resp = set_role(client, team, ADMIN.upper(), role, actor=MALLORY)
    assert resp.status_code == 409
    assert "AGENT_KEYS_ADMIN_EMAILS" in resp.json()["detail"]
    assert client.get("/ext/admin", headers=signed_in(team, email=ADMIN)).status_code == 200


@pytest.mark.parametrize("body", [{"email": "not-an-email", "role": "member"}, {"email": MALLORY, "role": "owner"}, {"email": MALLORY}])
def test_a_change_needs_an_email_and_a_known_role(team, body):
    client, _, _ = pages(team)
    assert client.post("/ext/admin/people", json=body, headers=as_person(team, ADMIN)).status_code == 422


def test_the_admin_page_escapes_emails(team):
    client, _, _ = pages(team)
    client.post("/ext/access-requests", headers=as_person(team, '<b>x</b>"@example.com'))
    text = client.get("/ext/admin", headers=signed_in(team, email=ADMIN)).text
    assert "<b>x</b>" not in text
    assert "&lt;b&gt;x&lt;/b&gt;&quot;@example.com" in text
