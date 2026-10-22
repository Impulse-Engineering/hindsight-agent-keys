"""An agent asks what waits for its person to review and is handed counts and a link, never user-written text."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import ACCESS_HOST, PEPPER, MemoryStore, Migrations, RecordedEvents
from fastmcp import FastMCP
from hindsight_api.api import mcp as upstream_mcp

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.tools import AgentKeysMcpExtension

LEGACY = "legacy-key-0123456789abcdef"
ALICE = "alice@example.com"  # an admin
BOB = "bob@example.com"
CAROL = "carol@example.com"
DAVE = "dave@example.com"
ERIN = "erin@example.com"
FRED = "fred@example.com"
PEOPLE = (ALICE, BOB, CAROL, DAVE)
PAGES = {"access_team_domain": "https://access.example.test", "access_aud": "aud-0123", "access_host": ACCESS_HOST}
LINK = f"https://{ACCESS_HOST}/ext/teams"
TEAMS = ("Zebra Crossing", "Giraffe Club")


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ALICE)


async def world(**config):
    """Carol owns Zebra Crossing, which Dave asked to join and she asked for Fred to join; Bob owns Giraffe Club,
    which Carol asked to join; Erin asked for a place on the Key Allowlist. Every request was filed just now."""
    store = MemoryStore()
    store.sign_ins.update(dict.fromkeys(PEOPLE, datetime.now(UTC)))
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER, "legacy_key": LEGACY, **config}, store=store, events=RecordedEvents())
    ext.set_context(Migrations())
    mcp = FastMCP("test")
    AgentKeysMcpExtension({}).register_tools(mcp, SimpleNamespace(tenant_extension=ext))
    for person in (BOB, CAROL, DAVE):
        await ext.set_role(ALICE, person, "member", None)
    zebra = await ext.create_team(CAROL, TEAMS[0], None)
    giraffe = await ext.create_team(BOB, TEAMS[1], None)
    await ext.request_to_join(DAVE, TEAMS[0], None)
    await ext.request_member(CAROL, zebra, FRED, "member", None)
    await ext.request_to_join(CAROL, TEAMS[1], None)
    await ext.request_access(ERIN, None)
    keys = {p: (await ext.create_personal_key(p, "agent", None))[1] for p in PEOPLE}
    return SimpleNamespace(mcp=mcp, ext=ext, store=store, keys=keys, zebra=zebra, giraffe=giraffe)


async def call(mcp, key, tool):
    # Upstream's MCP middleware puts the request's Bearer key here (api/mcp.py:548).
    token = upstream_mcp._current_api_key.set(key)
    try:
        return (await mcp.call_tool(tool, {})).structured_content
    finally:
        upstream_mcp._current_api_key.reset(token)


async def waiting(w, person):
    answer = await call(w.mcp, w.keys[person], "pending_reviews")
    return answer["join_requests"], answer["access_requests"]


# (requests to join the Teams they own; Key Allowlist requests, for an admin), with every request filed just now:
# an admin owns no Team here, so none of the Teams' requests is yet theirs to hear of.
WAITING = {ALICE: (0, 1), BOB: (1, 0), CAROL: (2, 0), DAVE: (0, 0)}


@pytest.mark.parametrize("person", PEOPLE)
async def test_an_agent_is_told_how_many_requests_wait_for_its_person_as_an_owner_or_an_admin(person):
    w = await world(**PAGES)
    joins, access = WAITING[person]
    assert await call(w.mcp, w.keys[person], "pending_reviews") == {"join_requests": joins, "access_requests": access, "link": LINK}


async def test_an_admin_hears_at_once_of_requests_for_a_team_they_own():
    w = await world(**PAGES)
    await w.ext.create_team(ALICE, "Hippo Hall", None)
    await w.ext.request_to_join(BOB, "Hippo Hall", None)
    assert await waiting(w, ALICE) == (1, 1)


async def test_an_admin_also_hears_of_requests_for_other_teams_left_waiting_more_than_7_days():
    w = await world(**PAGES)
    now = datetime.now(UTC)
    w.store.requested_at[w.zebra, DAVE] = now - timedelta(days=8)
    w.store.requested_at[w.zebra, FRED] = now - timedelta(days=6, hours=23)
    w.store.requested_at[w.giraffe, CAROL] = now - timedelta(days=30)
    assert await waiting(w, ALICE) == (2, 1)
    # An owner hears of every request for their Teams whatever its age, and no one else of any.
    assert [await waiting(w, p) for p in (BOB, CAROL, DAVE)] == [(1, 0), (2, 0), (0, 0)]


async def test_joining_an_open_team_leaves_nothing_to_review_and_joining_a_closed_one_files_a_request_for_its_owner():
    w = await world(**PAGES)
    gina = "gina@example.com"
    await w.ext.set_role(ALICE, gina, "member", None)
    await w.ext.set_open(ALICE, w.giraffe, True, None)
    assert await w.ext.join_team(gina, w.giraffe, None) == "member"
    assert [await waiting(w, p) for p in (BOB, CAROL)] == [(1, 0), (2, 0)]
    assert await w.ext.join_team(gina, w.zebra, None) is None
    assert [await waiting(w, p) for p in (BOB, CAROL)] == [(1, 0), (3, 0)]


async def test_asking_again_leaves_the_request_as_old_as_it_was():
    w = await world(**PAGES)
    w.store.requested_at[w.zebra, DAVE] = datetime.now(UTC) - timedelta(days=8)
    await w.ext.request_to_join(DAVE, TEAMS[0], None)
    assert await waiting(w, ALICE) == (1, 1)
    # An owner's request for the same person replaces it, and keeps its age too.
    await w.ext.request_member(CAROL, w.zebra, DAVE, "owner", None)
    assert await waiting(w, ALICE) == (1, 1)


async def test_a_bootstrap_admins_leftover_key_allowlist_request_waits_for_no_admin():
    w = await world(**PAGES)
    # Alice asked for a place before she became a bootstrap admin: the admin page hides the row, and nobody can answer it.
    w.store.roles[ALICE] = "requested"
    assert await waiting(w, ALICE) == (0, 1)
    assert [role for email, role in await w.ext.allowlist() if email == ALICE] == ["admin"]


async def test_the_answer_holds_no_team_name_or_email():
    w = await world(**PAGES)
    answer = await call(w.mcp, w.keys[ALICE], "pending_reviews")
    assert set(answer) == {"join_requests", "access_requests", "link"}
    text = json.dumps(answer).lower()
    assert [s for s in (*TEAMS, ALICE, BOB, CAROL, DAVE, ERIN, FRED, "@") if s.lower() in text] == []


async def test_the_description_tells_the_agent_to_call_it_at_session_start_and_tell_its_person():
    w = await world(**PAGES)
    description = {tool.name: tool.description for tool in await w.mcp.list_tools()}["pending_reviews"]
    assert "at the start of every session" in description
    assert "tell your person" in description
    # The link is not always there.
    assert "left out when the key pages are off" in description


async def test_list_teams_also_returns_the_counts():
    w = await world(**PAGES)
    listed = await call(w.mcp, w.keys[CAROL], "list_teams")
    assert listed["pending_reviews"] == {"join_requests": 2, "access_requests": 0, "link": LINK}
    assert [t["name"] for t in listed["teams"]] == [TEAMS[0]]


async def test_with_the_key_pages_off_the_answer_has_no_link():
    w = await world()
    assert await call(w.mcp, w.keys[CAROL], "pending_reviews") == {"join_requests": 2, "access_requests": 0}


@pytest.mark.parametrize("holder", ["team", "public", "legacy", "unknown"])
async def test_a_team_key_and_the_legacy_key_are_refused(holder):
    w = await world(**PAGES)
    keys = {
        "team": (await w.ext.create_team_key(CAROL, w.zebra, "ci", None))[1],
        "public": (await w.ext.create_team_key(CAROL, "public", "ci", None))[1],
        "legacy": LEGACY,
        "unknown": "hsk_unknown_" + "x" * 43,
    }
    answer = await call(w.mcp, keys[holder], "pending_reviews")
    assert "personal Agent Key" in answer["error"]
    assert "join_requests" not in answer
