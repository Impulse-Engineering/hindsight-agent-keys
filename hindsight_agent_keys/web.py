"""The key pages under /ext, for people signed in through Cloudflare Access.

Upstream mounts this router with no authentication of its own, so one gate on the
router covers every route: the Access-protected hostname only (agents' bypass
hostname gets 404), a valid Access JWT, and for state changes JSON, a custom header
and a same-origin Origin. The state lives on the tenant extension.
"""

import html
from collections.abc import Awaitable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from hindsight_api.extensions.http import HttpExtension
from pydantic import BaseModel, StringConstraints

from hindsight_agent_keys.extension import client_ip
from hindsight_agent_keys.store import Refused

ACCESS_JWT_HEADER = "cf-access-jwt-assertion"
STATE_CHANGE_HEADER = "x-agent-keys"


class NewKey(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class RoleChange(BaseModel):
    email: Annotated[
        str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    ]
    role: Literal["member", "admin"] | None  # None removes the person, or declines their request


# What the page says about a person's place on the Key Allowlist, by role.
ALLOWLIST_NOTE = {
    None: '<p>You are not on the Key Allowlist. <button id="request-access" type="button">Ask an admin to add you</button></p>',
    "requested": "<p>Your request to join the Key Allowlist is waiting for an admin.</p>",
    "member": "",
    "admin": '<p><a href="/ext/admin">Manage the Key Allowlist</a></p>',
}
ROLE_LABELS = {"requested": "Asked to join", "member": "Member", "admin": "Admin"}
# The admin page's buttons for each role: (new role, label); an empty role removes.
ROLE_ACTIONS = {
    "requested": (("member", "Approve"), ("", "Decline")),
    "member": (("admin", "Grant admin rights"), ("", "Remove")),
    "admin": (("member", "Remove admin rights"), ("", "Remove")),
}


def _allowlist_row(email: str, role: str, bootstrap: bool) -> str:
    shown = html.escape(email)
    actions = "Set in AGENT_KEYS_ADMIN_EMAILS" if bootstrap else " ".join(
        f'<button type="button" data-email="{shown}" data-role="{new}">{label}</button>' for new, label in ROLE_ACTIONS[role]
    )
    return f"<tr><td>{shown}</td><td>{ROLE_LABELS[role]}</td><td>{actions}</td></tr>"


class Identity(BaseModel):
    email: Annotated[
        str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    ]


async def _or_refused(change: Awaitable):
    """The change's result; a refusal becomes its HTTP status with the reason as detail."""
    try:
        return await change
    except Refused as refusal:
        raise HTTPException(refusal.status, str(refusal)) from None


class AgentKeysHttpExtension(HttpExtension):
    def get_router(self, memory) -> APIRouter:
        async def person(request: Request) -> str:
            """The signed-in person's email; refuses everything else."""
            keys = memory.tenant_extension
            host = (request.headers.get("host") or "").partition(":")[0].lower()
            if keys.access_host is None or host != keys.access_host:
                raise HTTPException(404)
            if request.method != "GET" and not (
                request.headers.get("content-type", "").partition(";")[0].strip().lower() == "application/json"
                and request.headers.get(STATE_CHANGE_HEADER) == "1"
                and request.headers.get("origin") == f"https://{keys.access_host}"
            ):
                raise HTTPException(403, "State changes need JSON, the X-Agent-Keys header and this page's origin.")
            email = await keys.access_email(request.headers.get(ACCESS_JWT_HEADER))
            if email is None:
                raise HTTPException(403, "Sign in through Cloudflare Access.")
            return email

        async def admin(email: str = Depends(person)) -> str:
            """The signed-in admin's email; refuses everyone else."""
            if await memory.tenant_extension.role(email) != "admin":
                raise HTTPException(403, "Only admins can manage the Key Allowlist.")
            return email

        router = APIRouter(include_in_schema=False, dependencies=[Depends(person)])
        # Every route under /ext/admin is for admins only.
        admin_router = APIRouter(prefix="/admin", dependencies=[Depends(admin)])

        @router.get("/", response_class=HTMLResponse)
        async def page(email: str = Depends(person)):
            note = ALLOWLIST_NOTE[await memory.tenant_extension.role(email)]
            return PAGE.replace("$allowlist", note).replace("$email", html.escape(email))

        @router.post("/access-requests", status_code=204)
        async def request_access(request: Request, email: str = Depends(person)):
            await memory.tenant_extension.request_access(email, client_ip(request.headers))

        @admin_router.get("", response_class=HTMLResponse)
        async def admin_page():
            keys = memory.tenant_extension
            rows = "\n".join(_allowlist_row(e, r, e in keys.bootstrap_admins) for e, r in await keys.allowlist())
            return ADMIN_PAGE.replace("$rows", rows)

        @admin_router.post("/people")
        async def set_role(body: RoleChange, request: Request, email: str = Depends(admin)):
            try:
                await memory.tenant_extension.set_role(email, body.email, body.role, client_ip(request.headers))
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return Response(status_code=204)

        @router.get("/keys")
        async def my_keys(email: str = Depends(person)):
            return await memory.tenant_extension.list_keys(email)

        @router.post("/keys/{key_id}/renew")
        async def renew_key(key_id: str, request: Request, email: str = Depends(person)):
            renewal = memory.tenant_extension.renew_key(email, key_id, client_ip(request.headers))
            return {"id": key_id, "expires_at": await _or_refused(renewal)}

        @router.post("/keys/{key_id}/revoke")
        async def revoke_key(key_id: str, request: Request, email: str = Depends(person)):
            await _or_refused(memory.tenant_extension.revoke_key(email, key_id, client_ip(request.headers)))
            return {"id": key_id, "state": "revoked"}

        @admin_router.post("/revoke-identity")
        async def revoke_identity(body: Identity, request: Request, email: str = Depends(admin)):
            revocation = memory.tenant_extension.revoke_identity(email, body.email, client_ip(request.headers))
            return {"revoked": await _or_refused(revocation)}

        @router.post("/keys")
        async def create_key(body: NewKey, request: Request, email: str = Depends(person)):
            try:
                key_id, key = await memory.tenant_extension.create_personal_key(
                    email, body.name, client_ip(request.headers)
                )
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return JSONResponse({"id": key_id, "name": body.name, "key": key}, headers={"Cache-Control": "no-store"})

        router.include_router(admin_router)
        return router


PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Agent Keys</title></head>
<body>
<h1>Agent Keys</h1>
<p>Signed in as $email. Your keys work for 90 days, and only while you sign in here at least every 30 days.</p>
$allowlist
<form id="create">
  <label for="key-name">Key name</label>
  <input id="key-name" required maxlength="100">
  <button>Create a personal key</button>
</form>
<p id="result" role="status"></p>
<h2>Your keys</h2>
<table>
  <thead><tr><th>Name</th><th>ID</th><th>Created</th><th>Expires</th><th>State</th><th></th></tr></thead>
  <tbody id="keys"></tbody>
</table>
<script>
const result = document.getElementById("result");
async function post(path, body) {
  const resp = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: JSON.stringify(body),
  });
  const answer = await resp.json();
  if (!resp.ok) result.textContent = "Refused: " + JSON.stringify(answer.detail);
  return resp.ok ? answer : null;
}
async function showKeys() {
  const keys = await (await fetch("/ext/keys")).json();
  document.getElementById("keys").replaceChildren(...keys.map((key) => {
    const row = document.createElement("tr");
    for (const text of [key.name, key.id, key.created_at, key.expires_at, key.state]) {
      row.insertCell().textContent = text;
    }
    const actions = row.insertCell();
    for (const action of key.state === "active" ? ["renew", "revoke"] : []) {
      const button = actions.appendChild(document.createElement("button"));
      button.textContent = action;
      button.onclick = async () => {
        if (action === "revoke" && !confirm("Revoke " + key.name + "? Agents using it stop at once.")) return;
        if (await post("/ext/keys/" + key.id + "/" + action, {})) {
          result.textContent = key.name + ": " + action + "ed.";
          showKeys();
        }
      };
    }
    return row;
  }));
}
document.getElementById("create").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = await post("/ext/keys", {name: document.getElementById("key-name").value});
  if (body) {
    result.textContent = "Your new key, shown only now. Copy it: " + body.key;
    showKeys();
  }
});
showKeys();
document.getElementById("request-access")?.addEventListener("click", async () => {
  const resp = await fetch("/ext/access-requests", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: "{}",
  });
  if (resp.ok) location.reload();
});
</script>
</body>
</html>
"""

ADMIN_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Key Allowlist</title></head>
<body>
<h1>Key Allowlist</h1>
<p>Only people on the Key Allowlist can create Agent Keys. Removing someone disables the keys they hold.
<a href="/ext/">Your keys</a></p>
<form id="add">
  <label for="email">Email</label>
  <input id="email" type="email" required maxlength="254">
  <button>Add</button>
</form>
<p id="result" role="status"></p>
<h2>Revoke an identity</h2>
<form id="revoke-identity">
  <label for="identity">Email</label>
  <input id="identity" type="email" required maxlength="254">
  <button>Revoke every key this person holds</button>
</form>
<h2>People</h2>
<table>
<thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Change</th></tr></thead>
<tbody>
$rows
</tbody>
</table>
<script>
async function setRole(email, role) {
  const resp = await fetch("/ext/admin/people", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: JSON.stringify({email, role}),
  });
  if (resp.ok) return location.reload();
  document.getElementById("result").textContent = "Refused: " + JSON.stringify((await resp.json()).detail);
}
document.getElementById("add").addEventListener("submit", (event) => {
  event.preventDefault();
  setRole(document.getElementById("email").value, "member");
});
document.querySelectorAll("button[data-email]").forEach((button) => {
  button.addEventListener("click", () => setRole(button.dataset.email, button.dataset.role || null));
});
document.getElementById("revoke-identity").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("identity").value;
  if (!confirm("Revoke every key " + email + " holds?")) return;
  const resp = await fetch("/ext/admin/revoke-identity", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: JSON.stringify({email}),
  });
  const answer = await resp.json();
  document.getElementById("result").textContent = resp.ok
    ? "Revoked " + answer.revoked + " keys held by " + email + "."
    : "Refused: " + JSON.stringify(answer.detail);
});
</script>
</body>
</html>
"""
