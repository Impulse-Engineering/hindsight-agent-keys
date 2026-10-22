"""An agent asks what waits for its person to review and is handed counts and a link, never user-written text."""

import json
from datetime import UTC, datetime
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
    which Carol asked to join; Erin asked for a place on the Key Allowlist. Returns (mcp, extension, personal keys)."""
    store = MemoryStore()
    store.sign_ins.update(dict.fromkeys(PEOPLE, datetime.now(UTC)))
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER, "legacy_key": LEGACY, **config}, store=store, events=RecordedEvents())
    ext.set_context(Migrations())
    mcp = FastMCP("test")
    AgentKeysMcpExtension({}).register_tools(mcp, SimpleNamespace(tenant_extension=ext))
    for person in (BOB, CAROL, DAVE):
        await ext.set_role(ALICE, person, "member", None)
    zebra = await ext.create_team(CAROL, TEAMS[0], None)
    await ext.create_team(BOB, TEAMS[1], None)
    await ext.request_to_join(DAVE, TEAMS[0], None)
    await ext.request_member(CAROL, zebra, FRED, "member", None)
    await ext.request_to_join(CAROL, TEAMS[1], None)
    await ext.request_access(ERIN, None)
    return mcp, ext, {p: (await ext.create_personal_key(p, "agent", None))[1] for p in PEOPLE}


async def call(mcp, key, tool):
    # Upstream's MCP middleware puts the request's Bearer key here (api/mcp.py:548).
    token = upstream_mcp._current_api_key.set(key)
    try:
        return (await mcp.call_tool(tool, {})).structured_content
    finally:
        upstream_mcp._current_api_key.reset(token)


# (requests to join Teams they own, or any Team for an admin; Key Allowlist requests, for an admin).
WAITING = {ALICE: (3, 1), BOB: (1, 0), CAROL: (2, 0), DAVE: (0, 0)}


@pytest.mark.parametrize("person", PEOPLE)
async def test_an_agent_is_told_how_many_requests_wait_for_its_person_as_an_owner_or_an_admin(person):
    mcp, _, keys = await world(**PAGES)
    joins, access = WAITING[person]
    assert await call(mcp, keys[person], "pending_reviews") == {"join_requests": joins, "access_requests": access, "link": LINK}


async def test_the_answer_holds_no_team_name_or_email():
    mcp, _, keys = await world(**PAGES)
    answer = await call(mcp, keys[ALICE], "pending_reviews")
    assert set(answer) == {"join_requests", "access_requests", "link"}
    text = json.dumps(answer).lower()
    assert [s for s in (*TEAMS, ALICE, BOB, CAROL, DAVE, ERIN, FRED, "@") if s.lower() in text] == []


async def test_the_description_tells_the_agent_to_call_it_at_session_start_and_tell_its_person():
    mcp, _, _ = await world(**PAGES)
    description = {tool.name: tool.description for tool in await mcp.list_tools()}["pending_reviews"]
    assert "at the start of every session" in description
    assert "tell your person" in description


async def test_list_teams_also_returns_the_counts():
    mcp, _, keys = await world(**PAGES)
    listed = await call(mcp, keys[CAROL], "list_teams")
    assert listed["pending_reviews"] == {"join_requests": 2, "access_requests": 0, "link": LINK}
    assert [t["name"] for t in listed["teams"]] == [TEAMS[0]]


async def test_with_the_key_pages_off_the_answer_has_no_link():
    mcp, _, keys = await world()
    assert await call(mcp, keys[CAROL], "pending_reviews") == {"join_requests": 2, "access_requests": 0}


@pytest.mark.parametrize("holder", ["team", "public", "legacy", "unknown"])
async def test_a_team_key_and_the_legacy_key_are_refused(holder):
    mcp, ext, _ = await world(**PAGES)
    (zebra,) = await ext.teams(CAROL)
    keys = {
        "team": (await ext.create_team_key(CAROL, zebra["team"], "ci", None))[1],
        "public": (await ext.create_team_key(CAROL, "public", "ci", None))[1],
        "legacy": LEGACY,
        "unknown": "hsk_unknown_" + "x" * 43,
    }
    answer = await call(mcp, keys[holder], "pending_reviews")
    assert "personal Agent Key" in answer["error"]
    assert "join_requests" not in answer
