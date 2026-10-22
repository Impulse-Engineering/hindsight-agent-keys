"""A Delegate (WorkPlane) creates Teams and Team keys for the signed-in person, and an owner or admin adds and
removes members, all with the person's rights: what the key pages and MCP refuse a person, it refuses too."""

import asyncio

import pytest
from conftest import (
    ACCESS_HOST,
    DELEGATE_ID,
    Migrations,
    delegated_app,
    delegated_headers,
)
from test_delegated_keys import on_the_key_page
from test_delegation import logged

from hindsight_agent_keys.store import Refused

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"
ADMIN = "admin@example.com"
TEAMS = "/ext/delegated/teams"
KEYS = "/ext/delegated/keys"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


def send(client, team, method, path, body=None, email=ALICE, **headers):
    """A Delegated Request for `email`; extra headers (an Idempotency-Key) are added."""
    return client.request(method, path, json=body, headers={**delegated_headers(team, email), **headers})


def team_key(client, team, schema, name="workplane", idempotency_key="k1", email=ALICE):
    return send(client, team, "POST", f"{TEAMS}/{schema}/keys", {"name": name}, email, **{"Idempotency-Key": idempotency_key})


async def test_a_delegate_creates_a_team_and_a_workplane_marked_team_key_for_the_person(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    made = send(client, team, "POST", TEAMS, {"name": "Platform"})
    assert made.status_code == 200, made.text
    schema = made.json()["team"]
    assert made.json() == {"team": schema, "name": "Platform"}
    resp = team_key(client, team, schema)
    assert resp.status_code == 200, resp.text
    created = resp.json()
    assert (created["name"], resp.headers["cache-control"]) == ("workplane", "no-store")
    principal = await ext.principal(created["key"])
    assert (principal.kind, principal.schema, principal.email) == ("team", schema, ALICE)
    listed = send(client, team, "GET", KEYS).json()
    assert [(k["id"], k["via"]) for k in listed] == [(created["id"], DELEGATE_ID)]
    assert logged(events) == [
        ("team_created", ALICE, ALICE, "delegated", DELEGATE_ID),
        ("key_created", ALICE, ALICE, "delegated", DELEGATE_ID),
    ]
    assert [r["team"] for r in events.rows] == [schema, schema]


@pytest.mark.parametrize(
    ("role", "member", "public"),
    [(None, True, False), ("requested", True, False), ("member", False, False), (None, False, True), ("requested", False, True)],
    ids=[
        "off the Key Allowlist, though a member",
        "only asked to join, though a member",
        "listed, but not in the Team",
        "off the Key Allowlist, for the Public Team",
        "only asked to join, for the Public Team",
    ],
)
async def test_a_team_key_needs_a_person_on_the_key_allowlist_who_is_in_the_team(team, role, member, public):
    client, ext, events = delegated_app(team)
    ext._store.roles[CAROL] = "member"
    schema = await ext.create_team(CAROL, "Platform", None)
    if member:
        await ext.set_member(CAROL, schema, ALICE, "member", None)
    if role:
        ext._store.roles[ALICE] = role
    before = len(events.rows)
    resp = team_key(client, team, "public" if public else schema)
    assert resp.status_code == 403, resp.text
    assert (ext._store.keys, len(events.rows)) == ({}, before)


async def test_a_listed_person_gets_a_workplane_marked_public_team_key_without_being_a_member(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    resp = team_key(client, team, "public")
    assert resp.status_code == 200, resp.text
    principal = await ext.principal(resp.json()["key"])
    assert (principal.kind, principal.schema, principal.email) == ("team", "public", ALICE)
    assert [(k["id"], k["via"]) for k in send(client, team, "GET", KEYS).json()] == [(resp.json()["id"], DELEGATE_ID)]
    assert logged(events) == [("key_created", ALICE, ALICE, "delegated", DELEGATE_ID)]


async def test_team_keys_count_with_the_persons_other_workplane_keys_and_not_with_their_own(team):
    client, ext, _ = delegated_app(team, workplane_active_keys="2")
    ext._store.roles[ALICE] = "member"
    schema = send(client, team, "POST", TEAMS, {"name": "Platform"}).json()["team"]
    personal = send(client, team, "POST", KEYS, {"name": "personal"}, **{"Idempotency-Key": "a"})
    assert (personal.status_code, team_key(client, team, schema, idempotency_key="b").status_code) == (200, 200)
    resp = team_key(client, team, schema, idempotency_key="c")
    assert (resp.status_code, resp.json()["detail"]) == (429, "You already hold 2 active keys created via WorkPlane.")
    # The key page's own limit is untouched: it still creates a Team key.
    await ext.create_team_key(ALICE, schema, "own", None)
    assert [k["via"] for k in ext._store.keys.values()] == [DELEGATE_ID, DELEGATE_ID, None]


async def test_an_owner_and_an_admin_add_and_remove_members_directly_and_each_change_is_recorded(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    schema = await ext.create_team(ALICE, "Platform", None)
    events.rows.clear()
    members = f"{TEAMS}/{schema}/members"
    # The target is the body's email, trimmed and lower-cased; the actor is always the JWT's person.
    added = send(client, team, "POST", members, {"email": " Bob@Example.com ", "role": "member"})
    assert (added.status_code, added.json()) == (200, {"team": schema, "email": BOB, "role": "member"})
    # An admin needs no place in the Team.
    assert send(client, team, "POST", members, {"email": CAROL, "role": "owner"}, ADMIN).status_code == 200
    assert {m["email"]: m["role"] for m in (await ext.teams(ALICE))[0]["members"]} == {ALICE: "owner", BOB: "member", CAROL: "owner"}
    key = team_key(client, team, schema, email=BOB).json()["key"]
    assert (await ext.principal(key)).email == BOB
    removed = send(client, team, "DELETE", members, {"email": BOB})
    assert (removed.status_code, removed.json()) == (200, {"team": schema, "email": BOB})
    assert send(client, team, "DELETE", members, {"email": CAROL}, ADMIN).status_code == 200
    assert [m["email"] for m in (await ext.teams(ALICE))[0]["members"]] == [ALICE]
    # A removed member's Team key is refused on its next request.
    assert await ext.principal(key) is None
    assert logged(events) == [
        ("member_added", BOB, ALICE, "delegated", DELEGATE_ID),
        ("owner_added", CAROL, ADMIN, "delegated", DELEGATE_ID),
        ("key_created", BOB, BOB, "delegated", DELEGATE_ID),
        ("member_removed", BOB, ALICE, "delegated", DELEGATE_ID),
        ("member_removed", CAROL, ADMIN, "delegated", DELEGATE_ID),
    ]
    assert {r["team"] for r in events.rows} == {schema}


DAVE = "dave@example.com"
ERIN = "erin@example.com"
FRANK = "frank@example.com"


@pytest.mark.parametrize(
    "actor", [BOB, CAROL, DAVE, ERIN], ids=["a member", "someone outside the Team", "only asked to join", "an owner off the Key Allowlist"]
)
async def test_anyone_but_an_owner_or_admin_is_refused_a_direct_add_or_removal(team, actor):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member", CAROL: "member", DAVE: "requested", ERIN: "member"})
    schema = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, schema, BOB, "member", None)
    await ext.set_member(ALICE, schema, ERIN, "owner", None)
    del ext._store.roles[ERIN]
    before = (dict(ext._store.team_roles), len(events.rows))
    members = f"{TEAMS}/{schema}/members"
    # A non-owner adding themselves is no direct add either: a Join Request is #1001.
    for method, body in [("POST", {"email": FRANK, "role": "member"}), ("POST", {"email": actor, "role": "owner"}), ("DELETE", {"email": BOB})]:
        assert send(client, team, method, members, body, actor).status_code == 403, body
    assert (ext._store.team_roles, len(events.rows)) == before


async def test_a_repeated_add_or_removal_answers_the_current_state_and_records_nothing_new(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    schema = await ext.create_team(ALICE, "Platform", None)
    events.rows.clear()
    members = f"{TEAMS}/{schema}/members"
    for body in ({"email": BOB, "role": "member"}, {"email": BOB, "role": "owner"}):
        for _ in range(2):
            resp = send(client, team, "POST", members, body)
            assert (resp.status_code, resp.json()) == (200, {"team": schema, "email": BOB, "role": body["role"]})
    assert (await ext.teams(ALICE))[0]["members"] == [{"email": ALICE, "role": "owner"}, {"email": BOB, "role": "owner"}]
    for _ in range(2):
        resp = send(client, team, "DELETE", members, {"email": BOB})
        assert (resp.status_code, resp.json()) == (200, {"team": schema, "email": BOB})
    # Someone who was never in the Team is removed from it all the same, and nothing is recorded.
    assert send(client, team, "DELETE", members, {"email": CAROL}).status_code == 200
    # Changing a role is a change, so it is recorded again; a repeat is not.
    assert [r[0] for r in logged(events)] == ["member_added", "owner_added", "member_removed"]


async def test_a_repeated_team_creation_answers_the_team_the_person_owns(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member", CAROL: "member"})
    first = send(client, team, "POST", TEAMS, {"name": "Platform"}).json()
    again = send(client, team, "POST", TEAMS, {"name": " platform "})
    # The current state: the Team's stored name, not the spelling this request used.
    assert (again.status_code, again.json()) == (200, first)
    assert (ext.context.schemas, [r["kind"] for r in events.rows]) == ([first["team"]], ["team_created"])
    # Only an owner of that Team gets it back: a member, or anyone else, finds the name taken.
    await ext.set_member(ALICE, first["team"], BOB, "member", None)
    for email in (BOB, CAROL):
        resp = send(client, team, "POST", TEAMS, {"name": "Platform"}, email)
        assert (resp.status_code, resp.json()["detail"]) == (409, "A Team with that name exists.")
    assert ext.context.schemas == [first["team"]]


async def test_a_retry_after_an_unrecorded_change_answers_the_current_state_and_records_nothing(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    # Each change is stored but its event is not (the event log failed, or the process stopped between them).
    events.fail = True
    schema = send(client, team, "POST", TEAMS, {"name": "Platform"}).json()["team"]
    members = f"{TEAMS}/{schema}/members"
    for method, email in (("POST", BOB), ("POST", CAROL), ("DELETE", CAROL)):
        assert send(client, team, method, members, {"email": email, "role": "member"}).status_code == 200
    events.fail = False
    assert send(client, team, "POST", TEAMS, {"name": "Platform"}).json()["team"] == schema
    for method, email in (("POST", BOB), ("DELETE", CAROL)):
        assert send(client, team, method, members, {"email": email, "role": "member"}).status_code == 200
    assert events.rows == []
    assert [m["email"] for m in (await ext.teams(ALICE))[0]["members"]] == [ALICE, BOB]


async def test_team_creation_keeps_the_teams_pages_terms(team):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    for n in range(10):
        await ext.create_team(ALICE, f"Team {n}", None)
    resp = send(client, team, "POST", TEAMS, {"name": "One more"})
    assert (resp.status_code, resp.json()["detail"]) == (429, "You can create at most 10 Teams.")
    # The name of a Team they own is still answered at the limit; the Public Team's name is reserved.
    assert send(client, team, "POST", TEAMS, {"name": "team 3"}).json() == {"team": ext.context.schemas[3], "name": "Team 3"}
    assert send(client, team, "POST", TEAMS, {"name": "Public"}).status_code == 409
    assert len(ext.context.schemas) == 10


@pytest.mark.parametrize(
    "body", [{"email": "not-an-email", "role": "member"}, {"email": BOB, "role": "admin"}, {"email": BOB}], ids=str
)
async def test_a_member_change_needs_an_email_and_a_role_of_member_or_owner(team, body):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    schema = await ext.create_team(ALICE, "Platform", None)
    before = len(events.rows)
    assert send(client, team, "POST", f"{TEAMS}/{schema}/members", body).status_code == 422
    assert ([m["email"] for m in await ext._store.members(schema)], len(events.rows)) == ([ALICE], before)


class SlowMigrations(Migrations):
    """Yields while migrating, as the real migration does, so concurrent creations interleave."""

    async def run_migration(self, schema):
        await asyncio.sleep(0)
        await super().run_migration(schema)


async def test_concurrent_creations_of_one_name_migrate_once_and_the_loser_finds_the_team(team):
    _, ext, events = delegated_app(team)
    ext.set_context(SlowMigrations())
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    delegated = [ext.create_team(ALICE, "Platform", None, delegated_repeat=True) for _ in range(4)]
    stranger = ext.create_team(BOB, "platform", None, delegated_repeat=True)
    *answers, refused = await asyncio.gather(*delegated, stranger, return_exceptions=True)
    # The owner's repeats all answer the winner's Team; anyone else finds the name taken. One schema, one event.
    (schema,) = ext.context.schemas
    assert answers == [schema] * 4
    assert (type(refused), refused.status) == (Refused, 409)
    assert [r["kind"] for r in events.rows] == ["team_created"]
    # The key page and MCP get no repeat shortcut, but the loser still leaves no schema behind.
    first, second = await asyncio.gather(
        ext.create_team(ALICE, "Support", None), ext.create_team(ALICE, "support", None), return_exceptions=True
    )
    assert (isinstance(first, str), (type(second), second.status)) == (True, (Refused, 409))
    assert len(ext.context.schemas) == 2


async def test_a_repeated_team_key_creation_returns_the_same_id_without_the_key(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    first, other = (send(client, team, "POST", TEAMS, {"name": name}).json()["team"] for name in ("Platform", "Support"))
    created = team_key(client, team, first, idempotency_key="onboarding").json()
    again = team_key(client, team, first, idempotency_key="onboarding")
    assert (again.status_code, again.json()) == (200, {"id": created["id"], "name": "workplane"})
    # The same idempotency key for another name, or another Team, is another request.
    assert team_key(client, team, first, name="another", idempotency_key="onboarding").status_code == 409
    assert team_key(client, team, other, idempotency_key="onboarding").status_code == 409
    assert [k["id"] for k in ext._store.keys.values()] == [created["id"]]
    assert [r["kind"] for r in events.rows] == ["team_created"] * 2 + ["key_created"]


@pytest.mark.parametrize("idempotency_key", [None, "", "k" * 201])
async def test_a_team_key_creation_needs_an_idempotency_key(team, idempotency_key):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    schema = await ext.create_team(ALICE, "Platform", None)
    before = len(events.rows)
    headers = {k: v for k, v in {**delegated_headers(team), "Idempotency-Key": idempotency_key}.items() if v is not None}
    assert client.post(f"{TEAMS}/{schema}/keys", json={"name": "workplane"}, headers=headers).status_code == 422
    assert (ext._store.keys, len(events.rows)) == ({}, before)


@pytest.mark.parametrize("bobs_key_from", ["a Delegated Request", "the key page"])
async def test_no_member_lists_renews_or_revokes_another_members_team_key_from_any_channel(team, bobs_key_from):
    client, ext, _ = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    schema = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, schema, BOB, "member", None)
    mine = team_key(client, team, schema).json()["id"]
    if bobs_key_from == "the key page":
        created = client.post(f"/ext/teams/{schema}/keys", json={"name": "bobs"}, headers=on_the_key_page(team, BOB)).json()
    else:
        created = team_key(client, team, schema, email=BOB, idempotency_key="b").json()
    bobs, bobs_key = created["id"], created["key"]
    # The owner and an admin hold no claim on a member's Team key; the admin revokes an identity instead.
    for email in (ALICE, ADMIN):
        for path, headers in ((KEYS, delegated_headers(team, email)), ("/ext/keys", on_the_key_page(team, email))):
            listed = [k["id"] for k in client.get(path, headers=headers).json()]
            assert listed == ([mine] if email == ALICE else []), path
            for action in ("renew", "revoke"):
                assert client.post(f"{path}/{bobs}/{action}", json={}, headers=headers).status_code == 404, (path, action)
    assert (await ext.principal(bobs_key)).email == BOB


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", TEAMS, {"name": "Another"}),
        ("POST", f"{TEAMS}/{{team}}/keys", {"name": "workplane"}),
        ("POST", f"{TEAMS}/{{team}}/members", {"email": BOB, "role": "member"}),
        ("DELETE", f"{TEAMS}/{{team}}/members", {"email": ALICE}),
    ],
    ids=["create a Team", "create a Team key", "add a member", "remove a member"],
)
@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"Cf-Access-Jwt-Assertion": None}, 403),
        ({"X-Delegated-Access-Jwt": None}, 403),
        ({"Host": ACCESS_HOST}, 404),
    ],
    ids=["no Delegate", "no person", "the key page's hostname"],
)
async def test_every_team_route_needs_both_credentials_and_the_delegation_host(team, method, path, body, change, status):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    # Alice owns a Team and could make every one of these requests, so a refusal is the credentials' doing.
    schema = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, schema, BOB, "member", None)
    headers = {k: v for k, v in {**delegated_headers(team), "Idempotency-Key": "k1", **change}.items() if v is not None}
    before = (dict(ext._store.teams_by_schema), dict(ext._store.team_roles), dict(ext._store.keys))
    assert client.request(method, path.format(team=schema), json=body, headers=headers).status_code == status
    assert (ext._store.teams_by_schema, ext._store.team_roles, ext._store.keys) == before


async def test_the_body_and_identity_headers_cannot_name_another_person_for_a_team_or_its_key(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    naming_bob = {"Cf-Access-Authenticated-User-Email": BOB, "Idempotency-Key": "k1"}
    made = send(client, team, "POST", TEAMS, {"name": "Platform", "email": BOB}, **naming_bob)
    schema = made.json()["team"]
    created = send(client, team, "POST", f"{TEAMS}/{schema}/keys", {"name": "workplane", "email": BOB}, **naming_bob)
    assert created.status_code == 200, created.text
    assert (await ext.principal(created.json()["key"])).email == ALICE
    assert ext._store.team_roles == {(schema, ALICE): "owner"}
    assert [(r["kind"], r["email"], r["actor"]) for r in events.rows] == [("team_created", ALICE, ALICE), ("key_created", ALICE, ALICE)]
