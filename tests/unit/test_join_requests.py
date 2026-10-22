"""Anyone on the Key Allowlist asks to join a Team they are not in, by name, on the Teams page, over MCP or by
Delegated Request. An owner or an admin answers with a live session (the Teams page or a Delegated Request), never over MCP."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from conftest import DELEGATE_ID, delegated_app, delegated_headers
from fastmcp import FastMCP
from hindsight_api.api import mcp as upstream_mcp
from test_delegation import logged
from test_teams_page import as_person
from test_web import signed_in

from hindsight_agent_keys.store import Refused
from hindsight_agent_keys.tools import AgentKeysMcpExtension

ADMIN = "admin@example.com"
ALICE = "alice@example.com"  # owns Platform
BOB = "bob@example.com"  # a member of Platform
CAROL = "carol@example.com"  # listed, not in Platform
DAVE = "dave@example.com"  # listed, not in Platform
ERIN = "erin@example.com"  # not on the Key Allowlist
CHANNELS = ["ext", "delegated", "mcp"]
PENDING = {"status": "pending"}


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


class World:
    """One extension reached on all three channels: the Teams page (`ext`), Delegated Requests and MCP."""

    def __init__(self, team):
        self.team = team
        self.client, self.ext, self.events = delegated_app(team)
        self.mcp = FastMCP("test")
        AgentKeysMcpExtension({}).register_tools(self.mcp, SimpleNamespace(tenant_extension=self.ext))
        self.keys = {}

    async def start(self, with_team=True):
        self.ext._store.roles.update(dict.fromkeys((ALICE, BOB, CAROL, DAVE), "member"))
        self.ext._store.sign_ins.update(dict.fromkeys((ALICE, BOB, CAROL, DAVE), datetime.now(UTC)))
        for email in (ALICE, BOB, CAROL, DAVE):
            self.keys[email] = (await self.ext.create_personal_key(email, "agent", None))[1]
        self.schema = "t_0000000000000000"
        if with_team:
            self.schema = await self.ext.create_team(ALICE, "Platform", None)
            await self.ext.set_member(ALICE, self.schema, BOB, "member", None)
        self.events.rows.clear()
        return self

    def send(self, channel, method, path, body, email):
        """The Teams page's script, or a Delegate, sending `body` as `email`; returns (status, answer)."""
        if channel == "ext":
            resp = self.client.request(method, f"/ext{path}", json=body, headers=as_person(self.team, email))
        else:
            resp = self.client.request(method, f"/ext/delegated{path}", json=body, headers=delegated_headers(self.team, email))
        return resp.status_code, resp.json()

    async def tool(self, caller, tool, /, **arguments):
        token = upstream_mcp._current_api_key.set(self.keys[caller])
        try:
            answer = (await self.mcp.call_tool(tool, arguments)).structured_content
        finally:
            upstream_mcp._current_api_key.reset(token)
        # A refusal over MCP is an error answer, with no status of its own.
        return (403 if "error" in answer else 200), answer

    async def ask(self, channel, email, name):
        if channel == "mcp":
            return await self.tool(email, "request_to_join_team", name=name)
        return self.send(channel, "POST", "/join-requests", {"name": name}, email)

    async def add(self, channel, email, member, role="member", team=None):
        team = team or self.schema
        if channel == "mcp":
            return await self.tool(email, "add_team_member", team=team, email=member, role=role)
        return self.send(channel, "POST", f"/teams/{team}/members", {"email": member, "role": role}, email)

    async def requests(self):
        return (await self.ext.teams(ALICE))[0]["requests"]

    async def members(self):
        return {m["email"]: m["role"] for m in (await self.ext.teams(ALICE))[0]["members"]}


@pytest.fixture
async def world(team):
    return await World(team).start()


def event(channel, kind, whom, who):
    """An event as `logged` lists it, recorded on `channel`."""
    return kind, whom, who, channel, DELEGATE_ID if channel == "delegated" else None


def joined(world, channel, person):
    """The Join Request event on `channel`, for the Team, and nothing else."""
    return logged(world.events) == [event(channel, "join_requested", person, person)] and [r["team"] for r in world.events.rows] == [world.schema]


@pytest.mark.parametrize("channel", CHANNELS)
async def test_a_listed_person_asks_to_join_a_team_by_name_and_nobody_gains_access_yet(world, channel):
    assert await world.ask(channel, CAROL, " PLATFORM ") == (200, {"name": "PLATFORM", **PENDING})
    assert await world.requests() == [{"email": CAROL, "role": "member", "by": CAROL}]
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert joined(world, channel, CAROL)
    with pytest.raises(Refused):
        await world.ext.create_team_key(CAROL, world.schema, "ci", None)


@pytest.mark.parametrize("name", ["Platform", "platform", " PLATFORM\t", "pLaTfOrM \n"])
async def test_the_name_is_matched_after_trimming_and_lower_casing(world, name):
    await world.ext.request_to_join(CAROL, name, None)
    assert await world.requests() == [{"email": CAROL, "role": "member", "by": CAROL}]


@pytest.mark.parametrize("channel", CHANNELS)
async def test_the_reply_is_the_same_whether_the_team_exists_and_a_request_for_a_missing_team_is_not_stored(team, world, channel):
    nowhere = await World(team).start(with_team=False)
    asked = await world.ask(channel, CAROL, "Platform")
    # Someone who is in the Team already asks too: a no-op with the same reply.
    members_ask = await world.ask(channel, BOB, "Platform")
    missing = await nowhere.ask(channel, CAROL, "Platform")
    assert asked == members_ask == missing == (200, {"name": "Platform", **PENDING})
    assert await world.requests() == [{"email": CAROL, "role": "member", "by": CAROL}]
    assert (nowhere.ext._store.requests, nowhere.events.rows) == ({}, [])
    assert joined(world, channel, CAROL)


@pytest.mark.parametrize("channel", ["ext", "delegated"])
@pytest.mark.parametrize("role", [None, "requested"])
async def test_only_people_on_the_key_allowlist_ask_to_join_whether_or_not_the_team_exists(world, channel, role):
    world.ext._store.roles.pop(ERIN, None)
    if role:
        world.ext._store.roles[ERIN] = role
    answers = {name: await world.ask(channel, ERIN, name) for name in ("Platform", "Nonesuch")}
    assert {status for status, _ in answers.values()} == {403}
    assert {reply["detail"] for _, reply in answers.values()} == {"You are not on the Key Allowlist."}
    assert (await world.requests(), world.events.rows) == ([], [])


@pytest.mark.parametrize("channel", CHANNELS)
async def test_filing_again_returns_the_open_request_and_an_earlier_request_for_the_person_stays(world, channel):
    first = await world.ask(channel, CAROL, "Platform")
    assert await world.ask(channel, CAROL, "Platform") == first
    # An owner asked for Dave to join as an owner; his own request does not replace it.
    await world.ext.request_member(ALICE, world.schema, DAVE, "owner", None)
    world.events.rows.clear()
    assert await world.ask(channel, DAVE, "Platform") == first
    assert await world.requests() == [
        {"email": CAROL, "role": "member", "by": CAROL},
        {"email": DAVE, "role": "owner", "by": ALICE},
    ]
    assert world.events.rows == []


@pytest.mark.parametrize("channel", CHANNELS)
async def test_a_non_owners_direct_add_of_themselves_becomes_a_join_request(team, world, channel):
    nowhere = await World(team).start(with_team=False)
    sent = await world.add(channel, CAROL, CAROL)
    assert sent == (200, {"team": world.schema, "email": CAROL, "role": "member", **PENDING})
    assert await world.requests() == [{"email": CAROL, "role": "member", "by": CAROL}]
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert joined(world, channel, CAROL)
    # A plain member's is a no-op with the same reply, and so is one for a Team that does not exist.
    assert await world.add(channel, BOB, BOB) == (200, {"team": world.schema, "email": BOB, "role": "member", **PENDING})
    nothing = await nowhere.add(channel, CAROL, CAROL)
    assert nothing == (200, {"team": nowhere.schema, "email": CAROL, "role": "member", **PENDING})
    assert (await world.requests(), nowhere.ext._store.requests) == ([{"email": CAROL, "role": "member", "by": CAROL}], {})


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("role", ["member", "owner"])
async def test_a_non_owner_asks_only_for_themselves(world, channel, role):
    status, _ = await world.add(channel, CAROL, DAVE, role)
    assert status == 403
    assert (await world.requests(), await world.members(), world.events.rows) == ([], {ALICE: "owner", BOB: "member"}, [])


@pytest.mark.parametrize("channel", CHANNELS)
async def test_a_non_owner_adding_themselves_as_an_owner_files_a_join_request_for_that_role(team, world, channel):
    nowhere = await World(team).start(with_team=False)
    asked = {"team": world.schema, "email": CAROL, "role": "owner", **PENDING}
    assert await world.add(channel, CAROL, CAROL, "owner") == (200, asked)
    assert await world.requests() == [{"email": CAROL, "role": "owner", "by": CAROL}]
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert joined(world, channel, CAROL)
    # An owner confirms the role that was asked for, and no other.
    answer = ("POST", f"/teams/{world.schema}/confirmations")
    assert world.send("delegated", *answer, {"email": CAROL, "role": "member"}, ALICE)[0] == 409
    assert world.send("delegated", *answer, {"email": CAROL, "role": "owner"}, ALICE)[0] == 200
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "owner"}
    # A member asking to be an owner is a request for someone already in the Team: a no-op, with the same reply. So is
    # one for a Team that does not exist.
    world.events.rows.clear()
    assert await world.add(channel, BOB, BOB, "owner") == (200, {**asked, "email": BOB})
    nothing = await nowhere.add(channel, DAVE, DAVE, "owner")
    assert nothing == (200, {"team": nowhere.schema, "email": DAVE, "role": "owner", **PENDING})
    assert (await world.requests(), nowhere.ext._store.requests, world.events.rows) == ([], {}, [])
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "owner"}


async def test_a_non_owner_off_the_key_allowlist_adding_themselves_as_an_owner_is_refused(world):
    world.ext._store.roles[DAVE] = "requested"
    for channel in ("ext", "delegated"):
        assert (await world.add(channel, DAVE, DAVE, "owner"))[0] == 403
    assert (await world.requests(), world.events.rows) == ([], [])


@pytest.mark.parametrize("channel", ["ext", "delegated"])
async def test_an_owners_or_admins_add_is_direct_and_settles_the_persons_open_join_request(world, channel):
    await world.ask(channel, CAROL, "Platform")
    await world.ask(channel, DAVE, "Platform")
    world.events.rows.clear()
    assert await world.add(channel, ALICE, CAROL, "owner") == (200, {"team": world.schema, "email": CAROL, "role": "owner"})
    # An admin needs no place in the Team, and adds themselves as directly as anyone.
    assert await world.add(channel, ADMIN, ADMIN) == (200, {"team": world.schema, "email": ADMIN, "role": "member"})
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "owner", ADMIN: "member"}
    # Carol's request is settled, so confirming it later cannot turn her back into a member; Dave's stays.
    assert await world.requests() == [{"email": DAVE, "role": "member", "by": DAVE}]
    assert logged(world.events) == [event(channel, "owner_added", CAROL, ALICE), event(channel, "member_added", ADMIN, ADMIN)]


async def test_a_delegate_approves_and_declines_join_requests_for_an_owner_or_an_admin_and_a_repeat_changes_nothing(world):
    for person in (CAROL, DAVE):
        await world.ask("delegated", person, "Platform")
    world.events.rows.clear()
    team = f"/teams/{world.schema}"
    for _ in range(2):
        approved = world.send("delegated", "POST", f"{team}/confirmations", {"email": CAROL, "role": "member"}, ALICE)
        assert approved == (200, {"team": world.schema, "email": CAROL, "role": "member"})
        declined = world.send("delegated", "DELETE", f"{team}/requests", {"email": DAVE}, ADMIN)
        assert declined == (200, {"team": world.schema, "email": DAVE})
    assert (await world.members(), await world.requests()) == ({ALICE: "owner", BOB: "member", CAROL: "member"}, [])
    assert logged(world.events) == [
        event("delegated", "member_confirmed", CAROL, ALICE),
        event("delegated", "member_declined", DAVE, ADMIN),
    ]
    await world.ext.create_team_key(CAROL, world.schema, "ci", None)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [("POST", "confirmations", {"email": CAROL, "role": "member"}), ("DELETE", "requests", {"email": CAROL})],
    ids=["approve", "decline"],
)
@pytest.mark.parametrize("actor", [BOB, CAROL, ERIN], ids=["a member", "the person asking", "off the Key Allowlist"])
async def test_only_an_owner_or_an_admin_answers_a_join_request(world, method, path, body, actor):
    await world.ask("delegated", CAROL, "Platform")
    world.events.rows.clear()
    status, _ = world.send("delegated", method, f"/teams/{world.schema}/{path}", body, actor)
    assert status == 403
    assert (await world.requests(), await world.members(), world.events.rows) == (
        [{"email": CAROL, "role": "member", "by": CAROL}],
        {ALICE: "owner", BOB: "member"},
        [],
    )


async def test_an_owner_declines_a_join_request_on_the_teams_page_and_the_person_stays_out(world):
    await world.ask("ext", CAROL, "Platform")
    await world.ask("ext", DAVE, "Platform")
    world.events.rows.clear()
    path = f"/teams/{world.schema}/requests"
    assert world.send("ext", "DELETE", path, {"email": CAROL}, BOB)[0] == 403
    assert world.send("ext", "DELETE", path, {"email": CAROL}, ALICE) == (200, {"team": world.schema, "email": CAROL})
    # Declined once, it cannot be declined again; the page, unlike a Delegated Request, does not repeat.
    assert world.send("ext", "DELETE", path, {"email": CAROL}, ALICE)[0] == 404
    assert await world.requests() == [{"email": DAVE, "role": "member", "by": DAVE}]
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert logged(world.events) == [event("ext", "member_declined", CAROL, ALICE)]
    with pytest.raises(Refused):
        await world.ext.create_team_key(CAROL, world.schema, "ci", None)


async def test_a_delegated_approval_needs_a_request_and_the_role_asked_for(world):
    await world.ext.request_member(ALICE, world.schema, DAVE, "owner", None)
    path = f"/teams/{world.schema}/confirmations"
    # Nobody asked for Carol: not a repeat of anything, so 404. Dave's request now asks for another role than the one shown: 409.
    assert world.send("delegated", "POST", path, {"email": CAROL, "role": "member"}, ALICE)[0] == 404
    assert world.send("delegated", "POST", path, {"email": DAVE, "role": "member"}, ALICE)[0] == 409
    assert world.send("delegated", "POST", path, {"email": DAVE, "role": "owner"}, ALICE)[0] == 200
    # Repeating it with the role the person holds is the same request again; with another role it is not.
    assert world.send("delegated", "POST", path, {"email": DAVE, "role": "owner"}, ALICE)[0] == 200
    assert world.send("delegated", "POST", path, {"email": DAVE, "role": "member"}, ALICE)[0] == 404


async def test_the_teams_page_lists_join_requests_for_an_owner_to_confirm_and_offers_to_ask_to_join(team):
    world = await World(team).start()
    await world.ask("ext", CAROL, "Platform")
    page = world.client.get("/ext/teams", headers=signed_in(team, email=ALICE))
    assert 'data-url="/ext/join-requests"' in page.text
    assert f"{CAROL} as member, asked by {CAROL}" in page.text
    answer = world.send("ext", "POST", f"/teams/{world.schema}/confirmations", {"email": CAROL, "role": "member"}, ALICE)
    assert answer[0] == 200
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "member"}


async def test_no_mcp_tool_approves_or_declines_and_an_owners_add_over_mcp_only_asks(world):
    names = {tool.name for tool in await world.mcp.list_tools()}
    assert names == {
        "create_team",
        "list_teams",
        "add_team_member",
        "remove_team_member",
        "request_to_join_team",
        "pending_reviews",
    }
    assert await world.add("mcp", ALICE, CAROL) == (200, {"team": world.schema, "email": CAROL, "role": "member", **PENDING})
    assert await world.members() == {ALICE: "owner", BOB: "member"}
    assert await world.requests() == [{"email": CAROL, "role": "member", "by": ALICE}]


@pytest.mark.parametrize("channel", ["ext", "delegated"])
async def test_a_request_left_for_someone_already_in_the_team_decides_nothing(world, channel):
    """A request an earlier release left for someone now in the Team at that role or above is answered as no request is:
    no decision, no event, no notice and no change to anyone's place. Confirming it does not demote an owner."""
    await world.ext.set_member(ALICE, world.schema, CAROL, "owner", None)
    world.events.rows.clear()
    world.ext._store.requests[world.schema, BOB] = ("member", ALICE)
    world.ext._store.requests[world.schema, CAROL] = ("member", ALICE)
    team = f"/teams/{world.schema}"
    answers = [
        world.send(channel, "POST", f"{team}/confirmations", {"email": CAROL, "role": "member"}, ALICE),
        world.send(channel, "POST", f"{team}/confirmations", {"email": BOB, "role": "member"}, ALICE),
        world.send(channel, "DELETE", f"{team}/requests", {"email": BOB}, ALICE),
    ]
    # A Delegated Request answers no request as a repeat (200) where the person already has the role shown, as ever.
    assert [status for status, _ in answers] == {"ext": [404, 404, 404], "delegated": [404, 200, 200]}[channel]
    assert await world.members() == {ALICE: "owner", BOB: "member", CAROL: "owner"}
    assert world.events.rows == []


async def test_an_owners_request_over_mcp_for_someone_already_in_the_team_at_that_role_or_above_is_a_no_op(world):
    asked = {"team": world.schema, "email": BOB, "role": "member", **PENDING}
    # Bob is a member, and Alice an owner: the same reply, and nothing stored, recorded or announced.
    assert await world.add("mcp", ALICE, BOB) == (200, asked)
    assert await world.add("mcp", ALICE, ALICE) == (200, {**asked, "email": ALICE})
    assert await world.add("mcp", ALICE, ALICE, "owner") == (200, {**asked, "email": ALICE, "role": "owner"})
    assert (await world.requests(), world.events.rows) == ([], [])
    # Asking for a member to become an owner still waits for an owner's answer.
    assert await world.add("mcp", ALICE, BOB, "owner") == (200, {**asked, "role": "owner"})
    assert await world.requests() == [{"email": BOB, "role": "owner", "by": ALICE}]
    assert logged(world.events) == [event("mcp", "owner_requested", BOB, ALICE)]


@pytest.mark.parametrize("step", ["ask", "approve", "decline"])
async def test_a_change_stored_before_its_event_failed_is_not_recorded_by_a_delegates_repeat(world, step):
    """The event log fails after the store committed: the change stands with no event row, and the Delegate's repeat,
    answered from the current state, records nothing, so the row is never written (README, "Delegated Requests")."""
    team = f"/teams/{world.schema}"
    calls = {
        "ask": ("POST", "/join-requests", {"name": "Platform"}, CAROL),
        "approve": ("POST", f"{team}/confirmations", {"email": CAROL, "role": "member"}, ALICE),
        "decline": ("DELETE", f"{team}/requests", {"email": CAROL}, ALICE),
    }
    if step != "ask":
        await world.ask("delegated", CAROL, "Platform")
    world.events.rows.clear()
    world.events.fail = True
    first = world.send("delegated", *calls[step])
    assert first[0] == 200, first
    stored = (await world.requests(), await world.members())
    assert stored == {
        "ask": ([{"email": CAROL, "role": "member", "by": CAROL}], {ALICE: "owner", BOB: "member"}),
        "approve": ([], {ALICE: "owner", BOB: "member", CAROL: "member"}),
        "decline": ([], {ALICE: "owner", BOB: "member"}),
    }[step]
    assert world.events.rows == []
    world.events.fail = False
    assert world.send("delegated", *calls[step]) == first
    assert (world.events.rows, (await world.requests(), await world.members())) == ([], stored)
