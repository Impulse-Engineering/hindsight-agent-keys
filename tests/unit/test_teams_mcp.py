"""Agents manage Teams over MCP, but adding someone waits for an owner on the Teams page."""

from types import SimpleNamespace

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from fastmcp import FastMCP
from hindsight_api.api import mcp as upstream_mcp
from pydantic import ValidationError

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.tools import AgentKeysMcpExtension

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
LEGACY = "legacy-key-0123456789abcdef"
ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"


@pytest.fixture(autouse=True)
def allowlist(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", f"{ALICE},{BOB}")


def server():
    events = RecordedEvents()
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER, "legacy_key": LEGACY}, store=MemoryStore(), events=events)
    ext.set_context(Migrations())
    mcp = FastMCP("test")
    # Registered as upstream registers an MCP extension's tools (api/mcp.py:201-204).
    AgentKeysMcpExtension({}).register_tools(mcp, SimpleNamespace(tenant_extension=ext))
    return mcp, ext, events


async def call(mcp, key, tool, **arguments):
    # Upstream's MCP middleware puts the request's Bearer key here (api/mcp.py:548).
    token = upstream_mcp._current_api_key.set(key)
    try:
        return (await mcp.call_tool(tool, arguments)).structured_content
    finally:
        upstream_mcp._current_api_key.reset(token)


async def test_with_a_personal_key_an_agent_creates_lists_and_removes_members_of_teams():
    mcp, ext, _ = server()
    _, key = await ext.create_personal_key(ALICE, "agent", None)
    created = await call(mcp, key, "create_team", name="Platform")
    team = created["team"]
    assert created == {"team": team, "name": "Platform"}
    await ext.set_member(ALICE, team, CAROL, "member", None)
    listed = await call(mcp, key, "list_teams")
    assert [(t["team"], t["name"], t["role"]) for t in listed["teams"]] == [(team, "Platform", "owner")]
    assert await call(mcp, key, "remove_team_member", team=team, email=" Carol@Example.com ") == {
        "team": team,
        "email": CAROL,
    }
    assert await ext.teams(CAROL) == []


@pytest.mark.parametrize("role", ["member", "owner"])
async def test_adding_someone_over_mcp_only_asks_an_owner_to_confirm_it(role):
    mcp, ext, events = server()
    _, key = await ext.create_personal_key(ALICE, "agent", None)
    team = (await call(mcp, key, "create_team", name="Platform"))["team"]
    answer = await call(mcp, key, "add_team_member", team=team, email="Carol@Example.com", role=role)
    assert (answer["team"], answer["email"], answer["role"], answer["status"]) == (team, CAROL, role, "pending")
    (shown,) = (await call(mcp, key, "list_teams"))["teams"]
    assert shown["members"] == [{"email": ALICE, "role": "owner"}]
    assert shown["requests"] == [{"email": CAROL, "role": role, "by": ALICE}]
    assert events.rows[-1]["kind"] == f"{role}_requested"
    await ext.confirm_member(ALICE, team, CAROL, None)
    assert {m["email"]: m["role"] for m in (await ext.teams(ALICE))[0]["members"]} == {ALICE: "owner", CAROL: role}


async def test_an_email_that_is_not_one_is_refused():
    mcp, ext, _ = server()
    _, key = await ext.create_personal_key(ALICE, "agent", None)
    team = (await call(mcp, key, "create_team", name="Platform"))["team"]
    with pytest.raises(ValidationError):
        await call(mcp, key, "add_team_member", team=team, email="not-an-email")


async def test_refusals_are_answered_as_errors():
    mcp, ext, _ = server()
    _, alice = await ext.create_personal_key(ALICE, "agent", None)
    # Carol is on the Key Allowlist but no admin, and only a member of the Team.
    await ext.set_role(ALICE, CAROL, "member", None)
    _, carol = await ext.create_personal_key(CAROL, "agent", None)
    team = (await call(mcp, alice, "create_team", name="Platform"))["team"]
    assert "exists" in (await call(mcp, carol, "create_team", name="platform"))["error"]
    await ext.set_member(ALICE, team, CAROL, "member", None)
    assert "owners" in (await call(mcp, carol, "add_team_member", team=team, email=BOB))["error"]
    assert "owners" in (await call(mcp, carol, "remove_team_member", team=team, email=ALICE))["error"]


TOOL_CALLS = [
    ("create_team", {"name": "Another"}),
    ("list_teams", {}),
    ("add_team_member", {"email": CAROL, "role": "owner"}),
    ("remove_team_member", {"email": BOB}),
]


@pytest.mark.parametrize(("tool", "arguments"), TOOL_CALLS)
@pytest.mark.parametrize("holder", ["team", "public", "legacy", "unknown"])
async def test_team_keys_and_the_legacy_key_cannot_use_the_team_tools(tool, arguments, holder):
    mcp, ext, events = server()
    team = await ext.create_team(ALICE, "Platform", None)
    await ext.set_member(ALICE, team, BOB, "member", None)
    keys = {
        "team": (await ext.create_team_key(ALICE, team, "ci", None))[1],
        "public": (await ext.create_team_key(ALICE, "public", "ci", None))[1],
        "legacy": LEGACY,
        "unknown": "hsk_unknown_" + "x" * 43,
    }
    before = (await ext.teams(BOB), len(events.rows))
    answer = await call(mcp, keys[holder], tool, **({"team": team} if "email" in arguments else {}), **arguments)
    assert "personal Agent Key" in answer["error"]
    assert (await ext.teams(BOB), len(events.rows)) == before
