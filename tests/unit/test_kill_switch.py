"""Admin controls over WorkPlane: the kill switch on /ext/admin, and the admin exception for Delegated Requests."""

import pytest
from conftest import DELEGATE_ID, delegated_app, delegated_headers
from test_delegated_keys import create, on_the_key_page

ADMIN = "admin@example.com"
ALICE = "alice@example.com"
BOB = "bob@example.com"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


async def test_an_admin_revokes_every_key_created_via_workplane_on_the_admin_page_and_nothing_else(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    workplane = [create(client, team, email=email).json()["key"] for email in (ALICE, BOB)]
    own = client.post("/ext/keys", json={"name": "own"}, headers=on_the_key_page(team)).json()["key"]
    assert "Revoke every key created via WorkPlane" in client.get("/ext/admin", headers=on_the_key_page(team, ADMIN)).text
    resp = client.post("/ext/admin/revoke-workplane-keys", headers=on_the_key_page(team, ADMIN))
    assert (resp.status_code, resp.json()) == (200, {"revoked": 2})
    assert [await ext.principal(key) for key in workplane] == [None, None]
    assert (await ext.principal(own)).email == ALICE
    assert [(r["kind"], r["email"], r["actor"], r["channel"]) for r in events.rows][-1] == (
        "workplane_keys_revoked", None, ADMIN, "ext"
    )


async def test_the_kill_switch_is_refused_to_everyone_but_an_admin_on_the_key_pages(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    key = create(client, team).json()["key"]
    before = list(events.rows)
    assert client.post("/ext/admin/revoke-workplane-keys", headers=on_the_key_page(team)).status_code == 403
    # Not by Delegated Request, even for an admin: a compromised Delegate must not be the one to switch itself off.
    for path in ("/ext/delegated/admin/revoke-workplane-keys", "/ext/delegated/revoke-workplane-keys"):
        assert client.post(path, headers=delegated_headers(team, ADMIN)).status_code in (404, 405)
    assert (await ext.principal(key)).email == ALICE
    assert events.rows == before


async def test_an_admin_revokes_a_persons_keys_of_either_origin_through_workplane(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    keys = [create(client, team).json()["key"]]
    keys.append(client.post("/ext/keys", json={"name": "own"}, headers=on_the_key_page(team)).json()["key"])
    revoke = {"json": {"email": " Alice@Example.com "}, "headers": {**delegated_headers(team, ADMIN), "X-Real-IP": "203.0.113.7"}}
    resp = client.post("/ext/delegated/admin/revoke-identity", **revoke)
    assert (resp.status_code, resp.json()) == (200, {"revoked": 2})
    assert [await ext.principal(key) for key in keys] == [None, None]
    # The admin is the actor, the person the target, and WorkPlane the Delegate, on the delegated channel.
    assert [(r["kind"], r["email"], r["actor"], r["channel"], r["delegate"], r["client_ip"]) for r in events.rows][-1] == (
        "identity_revoked", ALICE, ADMIN, "delegated", DELEGATE_ID, "203.0.113.7"
    )
    # A repeat revokes nothing more.
    assert client.post("/ext/delegated/admin/revoke-identity", **revoke).json() == {"revoked": 0}


def change_role(client, team, email, role, actor=ADMIN):
    return client.post("/ext/delegated/admin/people", json={"email": email, "role": role}, headers=delegated_headers(team, actor))


def test_an_admin_changes_key_allowlist_roles_through_workplane(team):
    client, _, events = delegated_app(team)
    client.post("/ext/delegated/access-requests", headers=delegated_headers(team, ALICE))
    for role in ("member", "admin", "member", None):
        resp = change_role(client, team, " Alice@Example.com ", role)
        assert (resp.status_code, resp.json()) == (200, {"email": ALICE, "role": role})
    # A repeat answers the current role and records nothing; the bootstrap admins stay as the secret sets them.
    assert change_role(client, team, ALICE, None).json() == {"email": ALICE, "role": None}
    assert change_role(client, team, ADMIN, None).status_code == 409
    assert [(r["kind"], r["email"], r["actor"], r["channel"], r["delegate"]) for r in events.rows][1:] == [
        (kind, ALICE, ADMIN, "delegated", DELEGATE_ID)
        for kind in ("access_approved", "admin_granted", "admin_removed", "allowlist_removed")
    ]


@pytest.mark.parametrize("role", [None, "requested", "member"])
def test_a_non_admin_delegated_request_to_any_admin_route_is_refused(team, role):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({BOB: "member", **({ALICE: role} if role else {})})
    create(client, team, email=BOB)
    before = list(events.rows)
    routes = [(m, r.path) for r in client.app.routes if r.path.startswith("/ext/delegated/admin/") for m in r.methods]
    assert {p for _, p in routes} >= {"/ext/delegated/admin/people", "/ext/delegated/admin/revoke-identity"}
    for method, path in routes:
        resp = client.request(method, path, json={"email": BOB, "role": "admin"}, headers=delegated_headers(team, ALICE))
        assert resp.status_code == 403, (path, resp.text)
    assert ext._store.roles.get(BOB) == "member"
    assert [k["revoked_at"] for k in ext._store.keys.values()] == [None]
    assert events.rows == before
