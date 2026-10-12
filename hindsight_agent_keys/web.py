"""The key pages under /ext, for people signed in through Cloudflare Access.

Upstream mounts this router with no authentication of its own, so one gate on the
router covers every route: the Access-protected hostname only (agents' bypass
hostname gets 404), a valid Access JWT, and for state changes JSON, a custom header
and a same-origin Origin. The state lives on the tenant extension.
"""

import html
from string import Template
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from hindsight_api.extensions.http import HttpExtension
from pydantic import BaseModel, StringConstraints

from hindsight_agent_keys.extension import client_ip
from hindsight_agent_keys.store import Refused

ACCESS_JWT_HEADER = "cf-access-jwt-assertion"
STATE_CHANGE_HEADER = "x-agent-keys"


Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")]


class NewKey(BaseModel):
    name: Name


class NewTeam(BaseModel):
    name: Name


class Member(BaseModel):
    email: Email
    role: Literal["owner", "member"]


class FormerMember(BaseModel):
    email: Email


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

        router = APIRouter(include_in_schema=False, dependencies=[Depends(person)])

        @router.get("/", response_class=HTMLResponse)
        async def page(email: str = Depends(person)):
            return PAGE.replace("$email", html.escape(email))

        @router.post("/keys")
        async def create_key(body: NewKey, request: Request, email: str = Depends(person)):
            try:
                key_id, key = await memory.tenant_extension.create_personal_key(
                    email, body.name, client_ip(request.headers)
                )
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return JSONResponse({"id": key_id, "name": body.name, "key": key}, headers={"Cache-Control": "no-store"})

        @router.get("/teams", response_class=HTMLResponse)
        async def teams_page(email: str = Depends(person)):
            return teams_html(email, await memory.tenant_extension.teams(email))

        @router.post("/teams")
        async def create_team(body: NewTeam, request: Request, email: str = Depends(person)):
            try:
                team = await memory.tenant_extension.create_team(email, body.name, client_ip(request.headers))
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return {"team": team, "name": body.name}

        @router.post("/teams/{team}/keys")
        async def create_team_key(team: str, body: NewKey, request: Request, email: str = Depends(person)):
            """`public` is the Public Team."""
            try:
                key_id, key = await memory.tenant_extension.create_team_key(
                    email, team, body.name, client_ip(request.headers)
                )
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return JSONResponse({"id": key_id, "name": body.name, "key": key}, headers={"Cache-Control": "no-store"})

        @router.post("/teams/{team}/members")
        async def set_member(team: str, body: Member, request: Request, email: str = Depends(person)):
            try:
                await memory.tenant_extension.set_member(email, team, body.email, body.role, client_ip(request.headers))
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return {"team": team, "email": body.email, "role": body.role}

        @router.delete("/teams/{team}/members")
        async def remove_member(team: str, body: FormerMember, request: Request, email: str = Depends(person)):
            try:
                await memory.tenant_extension.remove_member(email, team, body.email, client_ip(request.headers))
            except Refused as refusal:
                return JSONResponse({"detail": str(refusal)}, status_code=refusal.status)
            return {"team": team, "email": body.email}

        return router


PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Agent Keys</title></head>
<body>
<h1>Agent Keys</h1>
<p>Signed in as $email. <a href="/ext/teams">Teams</a></p>
<form id="create">
  <label for="key-name">Key name</label>
  <input id="key-name" required maxlength="100">
  <button>Create a personal key</button>
</form>
<p id="result" role="status"></p>
<script>
document.getElementById("create").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.getElementById("result");
  const resp = await fetch("/ext/keys", {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: JSON.stringify({name: document.getElementById("key-name").value}),
  });
  const body = await resp.json();
  result.textContent = resp.ok
    ? "Your new key, shown only now. Copy it: " + body.key
    : "Refused: " + JSON.stringify(body.detail);
});
</script>
</body>
</html>
"""


def teams_html(email: str, teams: list[dict]) -> str:
    """The Teams page; every value from the database or the token is escaped."""
    e = html.escape
    sections = []
    for t in teams:
        url = f"/ext/teams/{e(t['team'])}"
        members = "".join(f"<li>{e(m['email'])} ({e(m['role'])})</li>" for m in t["members"])
        parts = [
            f"<h2>{e(t['name'])}</h2>",
            f"<p>Schema {e(t['team'])}. Your role: {e(t['role'] or 'none (admin)')}.</p>",
            f"<ul>{members}</ul>",
        ]
        if t["role"]:
            parts.append(KEY_FORM.format(url=url, label="Create a Team key"))
        parts.append(MEMBER_FORMS.format(url=url))
        sections.append("<section>" + "".join(parts) + "</section>")
    # One pass, so a value that contains a placeholder is not substituted again.
    return TEAMS_PAGE.substitute(
        email=e(email),
        public=KEY_FORM.format(url="/ext/teams/public", label="Create a Public Team key"),
        teams="".join(sections) or "<p>You are in no Team yet.</p>",
    )


KEY_FORM = """<form data-url="{url}/keys" data-method="POST">
<label>Key name <input name="name" required maxlength="100"></label> <button>{label}</button></form>"""

# Shown to members too; the server refuses changes from anyone but owners and admins.
MEMBER_FORMS = """<form data-url="{url}/members" data-method="POST">
<label>Email <input name="email" type="email" required></label>
<label>Role <select name="role"><option>member</option><option>owner</option></select></label>
<button>Add, or change role</button></form>
<form data-url="{url}/members" data-method="DELETE">
<label>Email <input name="email" type="email" required></label> <button>Remove</button></form>"""

TEAMS_PAGE = Template("""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Teams</title></head>
<body>
<h1>Teams</h1>
<p>Signed in as $email. <a href="/ext/">Your keys</a></p>
<p id="result" role="status"></p>
<h2>Public Team</h2>
$public
<h2>Create a Team</h2>
<form data-url="/ext/teams" data-method="POST">
<label>Team name <input name="name" required maxlength="100"></label> <button>Create</button></form>
$teams
<script>
for (const form of document.querySelectorAll("form[data-url]")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = document.getElementById("result");
    const resp = await fetch(form.dataset.url, {
      method: form.dataset.method,
      headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const body = await resp.json();
    if (!resp.ok) {
      result.textContent = "Refused: " + JSON.stringify(body.detail);
    } else if (body.key) {
      result.textContent = "Your new key, shown only now. Copy it: " + body.key;
    } else {
      location.reload();
    }
  });
}
</script>
</body>
</html>
""")
