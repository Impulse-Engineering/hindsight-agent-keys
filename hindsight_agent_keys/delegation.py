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
from hindsight_agent_keys.bodies import Identity, NewKey, RoleChange, _or_refused
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

    async def delegated_admin(email: str = Depends(delegated_person)) -> str:
        """The admin the Delegate acts for; refuses everyone else."""
        if await memory.tenant_extension.role(email) != "admin":
            raise HTTPException(403, "Only admins can do this.")
        return email

    # Every route under /ext/delegated/admin is for admins only; it is included last, after every
    # section has added its routes. Revoking every key created via WorkPlane is never one of them.
    admin_router = APIRouter(prefix="/admin", dependencies=[Depends(delegated_admin)])

    @admin_router.post("/people")
    async def set_role(body: RoleChange, request: Request, email: str = Depends(delegated_admin)):
        """As /ext/admin/people does; answers the person's role now, a repeat too."""
        keys = memory.tenant_extension
        await _or_refused(keys.set_role(email, body.email, body.role, client_ip(request.headers)))
        return {"email": body.email, "role": await keys.role(body.email)}

    @admin_router.post("/revoke-identity")
    async def revoke_identity(body: Identity, request: Request, email: str = Depends(delegated_admin)):
        """The admin exception: every key the person holds, whoever created it, as /ext/admin/revoke-identity does.
        Answers how many this request revoked and how many of their keys are active now, a repeat too."""
        keys = memory.tenant_extension
        revoked = await _or_refused(keys.revoke_identity(email, body.email, client_ip(request.headers)))
        active = sum(k["state"] == "active" for k in await keys.list_keys(body.email))
        return {"email": body.email, "revoked": revoked, "active": active}

    # Teams (#1000)

    # Join Requests (#1001)

    # Open Teams (#1002)

    router.include_router(admin_router)
    return router
