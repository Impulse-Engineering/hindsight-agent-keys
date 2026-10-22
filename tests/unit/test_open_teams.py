"""Open Teams (#1002): an admin opens or closes a Team, on the Teams page or by Delegated Request, and anyone on the Key
Allowlist joins an Open Team with a live session, never over MCP."""

import pytest
from conftest import delegated_headers
from test_delegation import logged
from test_join_requests import (
    ADMIN,
    ALICE,
    BOB,
    CAROL,
    DAVE,
    ERIN,
    PENDING,
    World,
    event,
)
from test_web import signed_in

LIVE = ["ext", "delegated"]


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


@pytest.fixture
async def world(team):
    return await World(team).start()


def set_open(world, channel, email, opened, team=None):
    return world.send(channel, "POST", f"/teams/{team or world.schema}/open", {"open": opened}, email)


@pytest.mark.parametrize("channel", LIVE)
async def test_only_an_admin_opens_and_closes_a_team_and_a_repeat_records_nothing(world, channel):
    # The Team's owner, a member, someone outside it and someone off the Key Allowlist may not.
    for person in (ALICE, BOB, CAROL, ERIN):
        assert set_open(world, channel, person, True)[0] == 403
    assert world.events.rows == []
    for opened in (True, True, False, False):
        assert set_open(world, channel, ADMIN, opened) == (200, {"team": world.schema, "open": opened})
    assert logged(world.events) == [event(channel, "team_opened", None, ADMIN), event(channel, "team_closed", None, ADMIN)]
    assert [r["team"] for r in world.events.rows] == [world.schema] * 2


def join(world, channel, email, team=None):
    return world.send(channel, "POST", f"/teams/{team or world.schema}/join", {}, email)


@pytest.mark.parametrize("channel", LIVE)
async def test_anyone_on_the_key_allowlist_joins_an_open_team_and_a_repeat_changes_nothing(world, channel):
    await world.ext.set_open(ADMIN, world.schema, True, None)
    world.events.rows.clear()
    for _ in range(2):
        assert join(world, channel, CAROL) == (200, {"team": world.schema, "email": CAROL, "role": "member"})
    # Someone in the Team already keeps their role.
    assert join(world, channel, ALICE) == (200, {"team": world.schema, "email": ALICE, "role": "owner"})
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "member"}
    assert logged(world.events) == [event(channel, "member_joined", CAROL, CAROL)]
    assert [r["team"] for r in world.events.rows] == [world.schema]
    await world.ext.create_team_key(CAROL, world.schema, "ci", None)
    # Off the Key Allowlist, nobody joins.
    assert join(world, channel, ERIN)[0] == 403
    assert ERIN not in await world.members()


@pytest.mark.parametrize("channel", LIVE)
async def test_closing_keeps_the_members_and_a_join_then_files_a_join_request_as_one_for_a_missing_team_answers(team, world, channel):
    nowhere = await World(team).start(with_team=False)
    await world.ext.set_open(ADMIN, world.schema, True, None)
    assert join(world, channel, CAROL)[0] == 200
    assert set_open(world, channel, ADMIN, False) == (200, {"team": world.schema, "open": False})
    world.events.rows.clear()
    asked = {"email": DAVE, "role": "member", **PENDING}
    assert join(world, channel, DAVE) == (200, {"team": world.schema, **asked})
    assert join(nowhere, channel, DAVE) == (200, {"team": nowhere.schema, **asked})
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "member"}
    assert await world.requests() == [{"email": DAVE, "role": "member", "by": DAVE}]
    assert logged(world.events) == [event(channel, "join_requested", DAVE, DAVE)]
    assert (nowhere.ext._store.requests, nowhere.events.rows) == ({}, [])
    # An owner lets him in, as for any Join Request.
    confirmed = world.send(channel, "POST", f"/teams/{world.schema}/confirmations", {"email": DAVE, "role": "member"}, ALICE)
    assert confirmed[0] == 200
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "member", DAVE: "member"}


@pytest.mark.parametrize("channel", LIVE)
@pytest.mark.parametrize("remover", [ALICE, ADMIN], ids=["owner", "admin"])
async def test_an_owner_or_an_admin_removes_a_member_who_joined_and_they_may_rejoin(world, channel, remover):
    await world.ext.set_open(ADMIN, world.schema, True, None)
    assert join(world, channel, CAROL)[0] == 200
    _, key = await world.ext.create_team_key(CAROL, world.schema, "ci", None)
    assert world.send(channel, "DELETE", f"/teams/{world.schema}/members", {"email": CAROL}, remover)[0] == 200
    # Her Team key stops on its next request; removal does not stick, so a rejoin brings it back.
    assert await world.ext.principal(key) is None
    world.events.rows.clear()
    assert join(world, channel, CAROL) == (200, {"team": world.schema, "email": CAROL, "role": "member"})
    assert (await world.ext.principal(key)).schema == world.schema
    assert logged(world.events) == [event(channel, "member_joined", CAROL, CAROL)]


@pytest.mark.parametrize("channel", LIVE)
async def test_the_public_team_is_unchanged(world, channel):
    # It has no owners or members, so it cannot be opened or closed, and a join stores nothing.
    for opened in (True, False):
        assert set_open(world, channel, ADMIN, opened, team="public")[0] == 404
        # Anyone else is refused first, so the answer does not tell them whether a Team exists.
        assert {set_open(world, channel, ALICE, opened, team=t)[0] for t in ("public", "t_0000000000000000")} == {403}
    assert join(world, channel, CAROL, team="public") == (200, {"team": "public", "email": CAROL, "role": "member", **PENDING})
    assert (world.ext._store.requests, world.events.rows, await world.ext.open_teams(CAROL)) == ({}, [], [])
    assert not [t for t, _ in world.ext._store.team_roles if t == "public"]
    # Everyone on the Key Allowlist still creates a Public Team key.
    await world.ext.create_team_key(CAROL, "public", "ci", None)


async def test_open_teams_are_listed_to_everyone_on_the_key_allowlist_and_other_teams_are_not(world):
    guild = await world.ext.create_team(DAVE, "Guild", None)
    await world.ext.set_open(ADMIN, guild, True, None)
    await world.ext.join_team(CAROL, guild, None)

    def listed(email):
        resp = world.client.get("/ext/delegated/open-teams", headers=delegated_headers(world.team, email))
        assert resp.status_code == 200, resp.text
        return resp.json()

    def page(email):
        return world.client.get("/ext/teams", headers=signed_in(world.team, email=email)).text

    # Platform is closed: only its members see it, on the page, as before.
    assert listed(BOB) == [{"team": guild, "name": "Guild", "role": None}]
    assert listed(CAROL) == [{"team": guild, "name": "Guild", "role": "member"}]
    assert listed(ERIN) == []
    bobs, carols, erins = page(BOB), page(CAROL), page(ERIN)
    assert f'data-url="/ext/teams/{guild}/join"' in bobs and "Platform" in bobs
    assert "Guild" in carols and f'data-url="/ext/teams/{guild}/join"' not in carols and "Platform" not in carols
    assert "Guild" not in erins
    # An admin's page offers to open a closed Team and to close an open one.
    admins = page(ADMIN)
    assert f'data-url="/ext/teams/{world.schema}/open" data-method="POST">\n<input type="hidden" name="open" value="true">' in admins
    assert f'data-url="/ext/teams/{guild}/open" data-method="POST">\n<input type="hidden" name="open" value="false">' in admins


@pytest.mark.parametrize("channel", LIVE)
async def test_a_join_leaves_the_persons_own_open_request_in_place(world, channel):
    # Carol asked, while the Team was closed, to be an owner; joining makes her a member and leaves that to an owner.
    assert (await world.add(channel, CAROL, CAROL, "owner"))[1]["status"] == "pending"
    await world.ext.set_open(ADMIN, world.schema, True, None)
    assert join(world, channel, CAROL) == (200, {"team": world.schema, "email": CAROL, "role": "member"})
    assert await world.requests() == [{"email": CAROL, "role": "owner", "by": CAROL}]
    confirmed = world.send(channel, "POST", f"/teams/{world.schema}/confirmations", {"email": CAROL, "role": "owner"}, ALICE)
    assert confirmed[0] == 200
    assert (await world.members())[CAROL] == "owner"


async def test_only_an_admin_is_offered_to_open_or_close_a_team_on_the_teams_page(world):
    await world.ext.set_open(ADMIN, world.schema, True, None)
    form = f'data-url="/ext/teams/{world.schema}/open"'
    # The owner, a member, and a member taken off the Key Allowlist see the Team but no form to open or close it.
    viewers = {ALICE: True, BOB: True}
    for email in viewers:
        viewers[email] = form in world.client.get("/ext/teams", headers=signed_in(world.team, email=email)).text
    world.ext._store.roles.pop(BOB)
    off_list = world.client.get("/ext/teams", headers=signed_in(world.team, email=BOB)).text
    assert (viewers, form in off_list, "Open it" in off_list) == ({ALICE: False, BOB: False}, False, False)
    assert form in world.client.get("/ext/teams", headers=signed_in(world.team, email=ADMIN)).text


@pytest.mark.parametrize("step", ["open", "close", "join"])
async def test_a_change_stored_before_its_event_failed_is_not_recorded_by_a_delegates_repeat(world, step):
    """The event log fails after the store committed: the change stands with no event row, and the Delegate's repeat,
    answered from the current state, records nothing, so the row is never written (README, "Delegated Requests")."""
    if step != "open":
        await world.ext.set_open(ADMIN, world.schema, True, None)
    world.events.rows.clear()
    world.events.fail = True
    send = {"open": lambda: set_open(world, "delegated", ADMIN, True), "close": lambda: set_open(world, "delegated", ADMIN, False),
            "join": lambda: join(world, "delegated", CAROL)}[step]
    first = send()
    assert first[0] == 200, first
    stored = (world.schema in world.ext._store.opened, await world.members())
    assert stored == {
        "open": (True, {ALICE: "owner", BOB: "member"}),
        "close": (False, {ALICE: "owner", BOB: "member"}),
        "join": (True, {ALICE: "owner", BOB: "member", CAROL: "member"}),
    }[step]
    assert world.events.rows == []
    world.events.fail = False
    assert send() == first
    assert (world.events.rows, (world.schema in world.ext._store.opened, await world.members())) == ([], stored)


async def test_no_mcp_tool_joins_or_opens_a_team_and_asking_over_mcp_for_an_open_team_only_files_a_join_request(world):
    await world.ext.set_open(ADMIN, world.schema, True, None)
    names = {tool.name for tool in await world.mcp.list_tools()}
    assert not {n for n in names if "open" in n or n.startswith("join")}
    assert (await world.add("mcp", CAROL, CAROL))[1] == {"team": world.schema, "email": CAROL, "role": "member", **PENDING}
    assert (await world.ask("mcp", DAVE, "Platform"))[1] == {"name": "Platform", **PENDING}
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert [r["email"] for r in await world.requests()] == [CAROL, DAVE]
