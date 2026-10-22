"""Delegated Requests, under /ext/delegated: a Delegate (WorkPlane) acting for a person signed in to it.

Server to server, on the delegation application's own hostname. Each request carries two
credentials, each verified on its own: the Delegate's Access service-token JWT, which Access
forwards in Cf-Access-Jwt-Assertion, and the person's own Access JWT for WorkPlane's application
in X-Delegated-Access-Jwt. Identity headers are never read: the person is the second JWT's
email, and a self operation takes no email from the body. Routes call the tenant extension
only, never the store, so every rule and limit the key pages meet applies here too.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from hindsight_agent_keys.access import ACCESS_JWT_HEADER
from hindsight_agent_keys.bodies import (
    FormerMember,
    Member,
    NewKey,
    NewTeam,
    _or_refused,
)
from hindsight_agent_keys.extension import acting_via, client_ip, host_and_json

DELEGATED_JWT_HEADER = "x-delegated-access-jwt"


def delegated_router(memory) -> APIRouter:
    async def delegated_person(request: Request) -> str:
        """The email of the person the Delegate acts for; refuses everything else."""
        keys = memory.tenant_extension
        host, json_body = host_and_json(request.headers)
        if keys.delegation_host is None or host != keys.delegation_host:
            raise HTTPException(404)
        if request.method != "GET" and not json_body:
            raise HTTPException(403, "State changes need JSON.")
        delegate = await keys.delegate(request.headers.get(ACCESS_JWT_HEADER))
        acting_via("delegated", delegate)
        request.state.delegate = delegate
        # Read only for a valid Delegate, so nobody else can record the person's sign-in.
        email = await keys.delegated_email(request.headers.get(DELEGATED_JWT_HEADER)) if delegate else None
        if email is None:
            await keys.refused(client_ip(request.headers), "delegation_refused")
            raise HTTPException(403, "A Delegated Request needs the Delegate's service token and the person's Access JWT.")
        return email

    router = APIRouter(include_in_schema=False, dependencies=[Depends(delegated_person)])

    # Key Allowlist

    @router.post("/access-requests")
    async def request_access(request: Request, email: str = Depends(delegated_person)):
        """Ask the admins to add the person (the new-hire path); returns their role. Repeats change nothing."""
        keys = memory.tenant_extension
        await keys.request_access(email, client_ip(request.headers))
        return {"email": email, "role": await keys.role(email)}

    # Keys (#999)

    @router.post("/keys")
    async def create_key(
        body: NewKey,
        request: Request,
        idempotency_key: Annotated[str, Header(min_length=1, max_length=200)],
        email: str = Depends(delegated_person),
    ):
        """A personal key for the person, marked as created via WorkPlane; the key is shown only in this answer.
        A repeat of the Idempotency-Key with the same body within 24 hours answers the same ID without the key."""
        creation = memory.tenant_extension.create_personal_key(
            email, body.name, client_ip(request.headers), via=request.state.delegate, idempotency_key=idempotency_key
        )
        key_id, key = await _or_refused(creation)
        shown = {"key": key} if key else {}
        return JSONResponse({"id": key_id, "name": body.name, **shown}, headers={"Cache-Control": "no-store"})

    # Only the person's own keys marked as created via WorkPlane, never their key page keys or anyone else's.

    @router.get("/keys")
    async def my_keys(email: str = Depends(delegated_person)):
        """Each with its state and days to expiry."""
        return await memory.tenant_extension.list_keys(email, via_workplane=True)

    @router.post("/keys/{key_id}/renew")
    async def renew_key(key_id: str, request: Request, email: str = Depends(delegated_person)):
        renewal = memory.tenant_extension.renew_key(email, key_id, client_ip(request.headers), via_workplane=True)
        return {"id": key_id, "expires_at": await _or_refused(renewal)}

    @router.post("/keys/{key_id}/revoke")
    async def revoke_key(key_id: str, request: Request, email: str = Depends(delegated_person)):
        """A repeat answers the same: the key is revoked."""
        revocation = memory.tenant_extension.revoke_key(email, key_id, client_ip(request.headers), via_workplane=True)
        await _or_refused(revocation)
        return {"id": key_id, "state": "revoked"}

    # Admin (#1003)

    # Teams (#1000)

    @router.post("/teams")
    async def create_team(body: NewTeam, request: Request, email: str = Depends(delegated_person)):
        """A Team with the person as its first owner. The name of a Team they own answers that Team, creating nothing."""
        creation = memory.tenant_extension.create_team(email, body.name, client_ip(request.headers), repeat_ok=True)
        return {"team": await _or_refused(creation), "name": body.name}

    @router.post("/teams/{team}/keys")
    async def create_team_key(
        team: str,
        body: NewKey,
        request: Request,
        idempotency_key: Annotated[str, Header(min_length=1, max_length=200)],
        email: str = Depends(delegated_person),
    ):
        """A key for a Team the person is in (`public` is the Public Team), marked as created via WorkPlane;
        shown and repeated as a personal key is."""
        creation = memory.tenant_extension.create_team_key(
            email, team, body.name, client_ip(request.headers), via=request.state.delegate, idempotency_key=idempotency_key
        )
        key_id, key = await _or_refused(creation)
        shown = {"key": key} if key else {}
        return JSONResponse({"id": key_id, "name": body.name, **shown}, headers={"Cache-Control": "no-store"})

    # The person must own the Team (on the Key Allowlist) or be an admin. Anyone else is refused (403): a
    # non-owner's add becomes a Join Request in #1001.

    @router.post("/teams/{team}/members")
    async def set_member(team: str, body: Member, request: Request, email: str = Depends(delegated_person)):
        """Add the member, or change their role. A repeat changes nothing."""
        change = memory.tenant_extension.set_member(
            email, team, body.email, body.role, client_ip(request.headers), repeat_ok=True
        )
        await _or_refused(change)
        return {"team": team, "email": body.email, "role": body.role}

    @router.delete("/teams/{team}/members")
    async def remove_member(team: str, body: FormerMember, request: Request, email: str = Depends(delegated_person)):
        """Their Team keys stop on their next request. A repeat changes nothing."""
        removal = memory.tenant_extension.remove_member(email, team, body.email, client_ip(request.headers), repeat_ok=True)
        await _or_refused(removal)
        return {"team": team, "email": body.email}

    # Join Requests (#1001)

    # Open Teams (#1002)

    return router
