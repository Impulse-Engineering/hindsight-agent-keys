"""Team tools for agents, over MCP.

Upstream registers these on both MCP servers, multi-bank (/mcp/) and single-bank
(/mcp/<bank>/), each with its own instance and no context, so this class holds no
state and reaches everything through the tenant extension. Only a personal Agent Key
may use them, and adding someone, or asking to join a Team, only files a request that an owner on the Key Allowlist,
or an admin, confirms on the Access-protected Teams page or by Delegated Request: an agent never grants anyone
access on its own, and there is no tool that confirms or declines a request.
"""

from typing import Literal

from hindsight_api.api.mcp import get_current_api_key, get_current_extra_headers
from hindsight_api.extensions.mcp import MCPExtension

from hindsight_agent_keys.bodies import Email, Name
from hindsight_agent_keys.extension import acting_via, client_ip
from hindsight_agent_keys.store import Refused


class AgentKeysMcpExtension(MCPExtension):
    def register_tools(self, mcp, memory) -> None:
        async def person() -> str:
            """The email of the person whose personal key made this call; refuses every other key."""
            acting_via("mcp")
            principal = await memory.tenant_extension.principal(get_current_api_key())
            if principal is None or principal.kind != "personal":
                raise Refused(403, "Teams can be managed only with a personal Agent Key.")
            return principal.email

        def ip() -> str | None:
            return client_ip(get_current_extra_headers())

        # Refusals are answered as {"error": ...}, as upstream's own tools answer.

        @mcp.tool()
        async def create_team(name: Name) -> dict:
            """Create a Team, a memory space shared by named people, with you as its first owner.
            Returns the Team's ID, which the other Team tools take."""
            try:
                return {"team": await memory.tenant_extension.create_team(await person(), name, ip()), "name": name}
            except Refused as refusal:
                return {"error": str(refusal)}

        @mcp.tool()
        async def list_teams() -> dict:
            """Your Teams: each with its ID, your role, its members and the requests to add
            people that wait for an owner on the Key Allowlist or an admin. Also `pending_reviews`, the counts
            that the tool of that name returns."""
            try:
                email = await person()
                # Only Teams the caller is in, admins included; admins manage any Team on the page.
                return {
                    "teams": [t for t in await memory.tenant_extension.teams(email) if t["role"]],
                    "pending_reviews": await memory.tenant_extension.pending_reviews(email),
                }
            except Refused as refusal:
                return {"error": str(refusal)}

        @mcp.tool()
        async def request_to_join_team(name: Name) -> dict:
            """Ask to join a Team you are not in, by the Team's name (any case). Needs you on the Key Allowlist.
            The answer is the same whether or not such a Team exists. You gain no access until an owner of the Team,
            or an admin, confirms it, on the Teams page (/ext/teams) or through WorkPlane."""
            try:
                await memory.tenant_extension.request_to_join(await person(), name, ip())
            except Refused as refusal:
                return {"error": str(refusal)}
            return {"name": name, "status": "pending"}

        @mcp.tool()
        async def add_team_member(team: str, email: Email, role: Literal["member", "owner"] = "member") -> dict:
            """Ask for someone to join a Team you own while on the Key Allowlist (or any Team, as an admin),
            as a member or an owner, by email. If you do not own the Team, you may ask only for yourself.
            Nobody gains access until an owner of the Team on the Key Allowlist, or an admin, confirms it, on the Teams page
            (/ext/teams) or through WorkPlane."""
            try:
                await memory.tenant_extension.request_member(await person(), team, email, role, ip())
            except Refused as refusal:
                return {"error": str(refusal)}
            return {"team": team, "email": email, "role": role, "status": "pending"}

        @mcp.tool()
        async def remove_team_member(team: str, email: Email) -> dict:
            """Take someone out of a Team you own while on the Key Allowlist (or any Team, as an admin), by email;
            their Team keys stop working at once."""
            try:
                await memory.tenant_extension.remove_member(await person(), team, email, ip())
            except Refused as refusal:
                return {"error": str(refusal)}
            return {"team": team, "email": email}

        @mcp.tool()
        async def pending_reviews() -> dict:
            """Whether anything waits for your person to review. Call it at the start of every session, and when a count
            is above zero, tell your person and give them the link. `join_requests` counts the requests to join Teams they
            own (every Team, for an admin), reviewed on the Teams page at `link`; `access_requests` counts the people
            who asked for a place on the Key Allowlist (admins only), reviewed on the admin page, /ext/admin, on the same
            host. Counts and the link only: no Team names, emails or other text."""
            try:
                return await memory.tenant_extension.pending_reviews(await person())
            except Refused as refusal:
                return {"error": str(refusal)}
