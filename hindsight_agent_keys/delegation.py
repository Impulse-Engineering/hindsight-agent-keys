"""Delegated Requests, under /ext/delegated: a Delegate (WorkPlane) acting for a person signed in to it.

Server to server, on the delegation application's own hostname. Each request carries two
credentials, each verified on its own: the Delegate's Access service-token JWT, which Access
forwards in Cf-Access-Jwt-Assertion, and the person's own Access JWT for WorkPlane's application
in X-Delegated-Access-Jwt. Identity headers are never read: the person is the second JWT's
email, and a self operation takes no email from the body. Routes call the tenant extension
only, never the store, so every rule and limit the key pages meet applies here too.
"""

from fastapi import APIRouter, Depends, HTTPException, Request

from hindsight_agent_keys.extension import acting_via, client_ip
from hindsight_agent_keys.web import ACCESS_JWT_HEADER

DELEGATED_JWT_HEADER = "x-delegated-access-jwt"


def delegated_router(memory) -> APIRouter:
    async def delegated_person(request: Request) -> str:
        """The email of the person the Delegate acts for; refuses everything else."""
        keys = memory.tenant_extension
        host = (request.headers.get("host") or "").partition(":")[0].lower()
        if keys.delegation_host is None or host != keys.delegation_host:
            raise HTTPException(404)
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if request.method != "GET" and content_type != "application/json":
            raise HTTPException(403, "State changes need JSON.")
        delegate = await keys.delegate(request.headers.get(ACCESS_JWT_HEADER))
        acting_via("delegated", delegate)
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

    # Admin (#1003)

    # Teams (#1000)

    # Join Requests (#1001)

    # Open Teams (#1002)

    return router
