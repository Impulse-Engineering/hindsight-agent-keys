"""Teams share one schema between named people; their owners manage who is in them."""

import re

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.store import Refused

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"
DAVE = "dave@example.com"


@pytest.fixture(autouse=True)
def allowlist(monkeypatch):
    # Until the Key Allowlist is stored it is the bootstrap admins, so Alice and Bob are
    # both on it and admins; Carol and Dave are neither.
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", f"{ALICE},{BOB}")


def extension():
    store, migrations, events = MemoryStore(), Migrations(), RecordedEvents()
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER}, store=store, events=events)
    ext.set_context(migrations)
    return ext, store, migrations, events


async def test_a_person_on_the_key_allowlist_creates_a_team_and_is_its_first_owner():
    ext, _, migrations, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    assert re.fullmatch(r"t_[0-9a-f]{16}", team)
    assert migrations.schemas == [team]
    assert [t.schema for t in await ext.list_tenants()] == ["public", team]
    assert await ext.teams(ALICE) == [
        {"team": team, "name": "Platform", "role": "owner", "members": [{"email": ALICE, "role": "owner"}]}
    ]


@pytest.mark.parametrize("name", ["public", "Public", "PUBLIC"])
async def test_public_is_a_reserved_team_name(name):
    ext, store, migrations, _ = extension()
    with pytest.raises(Refused) as refusal:
        await ext.create_team(ALICE, name, None)
    assert refusal.value.status == 409
    assert (store.teams_by_schema, migrations.schemas) == ({}, [])


async def test_team_names_are_unique_whatever_their_case_and_a_taken_name_creates_no_schema():
    ext, _, migrations, _ = extension()
    await ext.create_team(ALICE, "Platform", None)
    with pytest.raises(Refused) as refusal:
        await ext.create_team(BOB, "platform", None)
    assert refusal.value.status == 409
    assert [t["name"] for t in await ext.teams(BOB)] == ["Platform"]
    assert len(migrations.schemas) == 1


async def test_people_not_on_the_key_allowlist_cannot_create_a_team():
    ext, store, migrations, _ = extension()
    with pytest.raises(Refused) as refusal:
        await ext.create_team(CAROL, "Platform", None)
    assert refusal.value.status == 403
    assert (store.teams_by_schema, migrations.schemas) == ({}, [])


def roles(teams, team):
    return {m["email"]: m["role"] for t in teams if t["team"] == team for m in t["members"]}


async def test_owners_add_and_remove_members_and_owners_by_email_before_they_have_signed_in():
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    # Carol has never signed in and is not on the Key Allowlist; as an owner she still manages the Team.
    await ext.set_member(ALICE, team, CAROL, "owner", None)
    await ext.set_member(CAROL, team, DAVE, "member", None)
    assert roles(await ext.teams(DAVE), team) == {ALICE: "owner", CAROL: "owner", DAVE: "member"}
    await ext.set_member(CAROL, team, DAVE, "owner", None)
    await ext.remove_member(DAVE, team, CAROL, None)
    assert roles(await ext.teams(ALICE), team) == {ALICE: "owner", DAVE: "owner"}
    assert await ext.teams(CAROL) == []


@pytest.mark.parametrize("actor", [DAVE, CAROL])
async def test_members_who_are_not_owners_and_outsiders_cannot_change_members(actor):
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, team, DAVE, "member", None)
    with pytest.raises(Refused) as refusal:
        await ext.set_member(actor, team, actor, "owner", None)
    assert refusal.value.status == 403
    with pytest.raises(Refused):
        await ext.remove_member(actor, team, ALICE, None)
    assert roles(await ext.teams(ALICE), team) == {ALICE: "owner", DAVE: "member"}


async def test_a_team_always_keeps_at_least_one_owner():
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    with pytest.raises(Refused) as refusal:
        await ext.remove_member(ALICE, team, ALICE, None)
    assert refusal.value.status == 409
    with pytest.raises(Refused) as refusal:
        await ext.set_member(ALICE, team, ALICE, "member", None)
    assert refusal.value.status == 409
    await ext.set_member(ALICE, team, CAROL, "owner", None)
    await ext.remove_member(ALICE, team, ALICE, None)
    assert roles(await ext.teams(CAROL), team) == {CAROL: "owner"}


async def test_admins_manage_any_team_and_see_every_team():
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    assert [(t["team"], t["role"]) for t in await ext.teams(BOB)] == [(team, None)]
    await ext.set_member(BOB, team, CAROL, "owner", None)
    await ext.remove_member(BOB, team, ALICE, None)
    assert roles(await ext.teams(BOB), team) == {CAROL: "owner"}


async def test_changing_the_members_of_a_team_that_does_not_exist_is_refused():
    ext, _, _, _ = extension()
    with pytest.raises(Refused) as refusal:
        await ext.set_member(BOB, "t_0000000000000000", CAROL, "member", None)
    assert refusal.value.status == 404


async def test_team_and_membership_changes_are_logged_with_who_made_them():
    ext, _, _, events = extension()
    team = await ext.create_team(ALICE, "Platform", "203.0.113.7")
    await ext.set_member(ALICE, team, CAROL, "owner", None)
    await ext.set_member(ALICE, team, DAVE, "member", None)
    await ext.remove_member(CAROL, team, DAVE, None)
    assert [(r["kind"], r["key_id"], r["email"], r["team"], r.get("member")) for r in events.rows] == [
        ("team_created", "(none)", ALICE, team, None),
        ("owner_added", "(none)", ALICE, team, CAROL),
        ("member_added", "(none)", ALICE, team, DAVE),
        ("member_removed", "(none)", CAROL, team, DAVE),
    ]
    assert events.rows[0]["client_ip"] == "203.0.113.7"


async def schema_of(ext, key):
    return (await ext.authenticate(RequestContext(api_key=key))).schema_name


async def refused(ext, key):
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=key))


async def test_members_create_team_keys_that_reach_only_the_teams_schema():
    ext, store, migrations, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, team, BOB, "member", None)
    key_id, key = await ext.create_team_key(BOB, team, "ci", None)
    assert key.startswith(f"hsk_{key_id}_")
    assert await schema_of(ext, key) == team
    principal = await ext.principal(key)
    assert (principal.kind, principal.email, principal.schema) == ("team", BOB, team)
    # A Team key needs no personal schema.
    assert migrations.schemas == [team]
    _, personal = await ext.create_personal_key(BOB, "laptop", None)
    assert await schema_of(ext, personal) == store.people[BOB] != team


async def test_removing_a_member_stops_their_team_keys_on_the_next_request():
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, team, BOB, "member", None)
    _, key = await ext.create_team_key(BOB, team, "ci", None)
    assert await schema_of(ext, key) == team
    await ext.remove_member(ALICE, team, BOB, None)
    await refused(ext, key)


async def test_only_members_on_the_key_allowlist_create_team_keys():
    ext, _, _, _ = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, team, CAROL, "owner", None)
    # Bob is an admin but not a member; Carol is an owner but not on the Key Allowlist.
    for email in (BOB, CAROL):
        with pytest.raises(Refused) as refusal:
            await ext.create_team_key(email, team, "ci", None)
        assert refusal.value.status == 403


async def test_everyone_on_the_key_allowlist_creates_public_team_keys_that_reach_public():
    ext, _, migrations, _ = extension()
    _, key = await ext.create_team_key(BOB, "public", "ci", None)
    assert await schema_of(ext, key) == "public"
    assert (await ext.principal(key)).kind == "team"
    assert migrations.schemas == []
    with pytest.raises(Refused) as refusal:
        await ext.create_team_key(CAROL, "public", "ci", None)
    assert refusal.value.status == 403


async def test_team_key_creation_is_logged_with_the_team():
    ext, _, _, events = extension()
    team = await ext.create_team(ALICE, "Platform", None)
    key_id, _ = await ext.create_team_key(ALICE, team, "ci", "203.0.113.7")
    assert events.rows[-1] == {
        "kind": "key_created", "key_id": key_id, "client_ip": "203.0.113.7", "email": ALICE, "team": team
    }
