"""The key pages under /ext, for people signed in through Cloudflare Access.

Upstream mounts this router with no authentication of its own, so one gate on the
router covers every route: the Access-protected hostname only (agents' bypass
hostname gets 404), a valid Access JWT, and for state changes JSON, a custom header
and a same-origin Origin. The state lives on the tenant extension.
"""

import html
from collections.abc import Awaitable
from datetime import UTC, datetime
from string import Template
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from hindsight_api.extensions.http import HttpExtension
from pydantic import BaseModel, StringConstraints

from hindsight_agent_keys.extension import client_ip
from hindsight_agent_keys.store import Refused

ACCESS_JWT_HEADER = "cf-access-jwt-assertion"
STATE_CHANGE_HEADER = "x-agent-keys"
# No page may be framed, so nobody can trick a signed-in admin into clicking Approve or Grant.
NO_FRAMING = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'"}


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


class RoleChange(BaseModel):
    email: Email
    role: Literal["member", "admin"] | None  # None removes the person, or declines their request


# What the page says about a person's place on the Key Allowlist, by role.
ALLOWLIST_NOTE = {
    None: '<div class="note"><svg class="i"><use href="#shield"/></svg><span class="grow">You are not on the Key Allowlist,'
    ' so you cannot create keys.</span><button class="btn sm" id="request-access" type="button">Ask an admin to add you</button></div>',
    "requested": '<div class="note"><svg class="i"><use href="#clock"/></svg>'
    "<span>Your request to join the Key Allowlist is waiting for an admin.</span></div>",
    "member": "",
    "admin": "",
}
ROLE_LABELS = {"requested": "Asked to join", "member": "Member", "admin": "Admin"}
ROLE_PILLS = {"requested": "ask", "member": "member", "admin": "admin"}
# The admin page's buttons for each role: (new role, label, style); an empty role removes.
ROLE_ACTIONS = {
    "requested": (("member", "Approve", ""), ("", "Decline", "sec")),
    "member": (("admin", "Grant admin rights", "sec"), ("", "Remove", "danger")),
    "admin": (("member", "Remove admin rights", "sec"), ("", "Remove", "danger")),
}


def _allowlist_row(email: str, role: str, bootstrap: bool) -> str:
    shown = html.escape(email)
    # Removing someone stops their keys, so the page asks first.
    ask = f' data-confirm="Remove {shown}? Their keys stop at once."'
    actions = '<span class="sub">Set in AGENT_KEYS_ADMIN_EMAILS</span>' if bootstrap else " ".join(
        f'<button class="btn {style} sm" type="button" data-email="{shown}" data-role="{new}"'
        f'{ask if label == "Remove" else ""}>{label}</button>'
        for new, label, style in ROLE_ACTIONS[role]
    )
    pill = f'<span class="pill {ROLE_PILLS[role]}">{ROLE_LABELS[role]}</span>'
    return f'<tr><td>{shown}</td><td>{pill}</td><td class="act">{actions}</td></tr>'


def _stale_row(row) -> str:
    last = row["last_active"]
    days = (datetime.now(UTC) - last).days if last else None
    shown = "never had a key" if days is None else f'<span title="{last:%d %b %Y}">{days} days ago</span>'
    return f"<tr><td>{html.escape(row['schema'])}</td><td>{html.escape(row['email'])}</td><td>{shown}</td></tr>"


class Identity(BaseModel):
    email: Email


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
            role = await memory.tenant_extension.role(email)
            # One pass, so a value that contains a placeholder is not substituted again.
            main = PAGE.substitute(allowlist=ALLOWLIST_NOTE[role], create_hidden="" if role in ("member", "admin") else " hidden")
            return HTMLResponse(shell("Your keys", "/ext/", email, role, main), headers=NO_FRAMING)

        @router.post("/access-requests", status_code=204)
        async def request_access(request: Request, email: str = Depends(person)):
            await memory.tenant_extension.request_access(email, client_ip(request.headers))

        @admin_router.get("", response_class=HTMLResponse)
        async def admin_page(email: str = Depends(admin)):
            keys = memory.tenant_extension
            rows = "\n".join(_allowlist_row(e, r, e in keys.bootstrap_admins) for e, r in await keys.allowlist())
            stale = "\n".join(_stale_row(r) for r in await keys.stale_schemas()) or NO_STALE
            # One pass, so a value that contains a placeholder is not substituted again.
            main = ADMIN_PAGE.substitute(rows=rows, stale=stale)
            return HTMLResponse(shell("Key Allowlist", "/ext/admin", email, "admin", main), headers=NO_FRAMING)

        @admin_router.post("/people")
        async def set_role(body: RoleChange, request: Request, email: str = Depends(admin)):
            await _or_refused(memory.tenant_extension.set_role(email, body.email, body.role, client_ip(request.headers)))
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
            creation = memory.tenant_extension.create_personal_key(email, body.name, client_ip(request.headers))
            key_id, key = await _or_refused(creation)
            return JSONResponse({"id": key_id, "name": body.name, "key": key}, headers={"Cache-Control": "no-store"})

        @router.get("/teams", response_class=HTMLResponse)
        async def teams_page(email: str = Depends(person)):
            keys = memory.tenant_extension
            return HTMLResponse(teams_html(email, await keys.role(email), await keys.teams(email)), headers=NO_FRAMING)

        @router.post("/teams")
        async def create_team(body: NewTeam, request: Request, email: str = Depends(person)):
            team = await _or_refused(memory.tenant_extension.create_team(email, body.name, client_ip(request.headers)))
            return {"team": team, "name": body.name}

        @router.post("/teams/{team}/keys")
        async def create_team_key(team: str, body: NewKey, request: Request, email: str = Depends(person)):
            """`public` is the Public Team."""
            creation = memory.tenant_extension.create_team_key(email, team, body.name, client_ip(request.headers))
            key_id, key = await _or_refused(creation)
            return JSONResponse({"id": key_id, "name": body.name, "key": key}, headers={"Cache-Control": "no-store"})

        @router.post("/teams/{team}/members")
        async def set_member(team: str, body: Member, request: Request, email: str = Depends(person)):
            change = memory.tenant_extension.set_member(email, team, body.email, body.role, client_ip(request.headers))
            await _or_refused(change)
            return {"team": team, "email": body.email, "role": body.role}

        @router.delete("/teams/{team}/members")
        async def remove_member(team: str, body: FormerMember, request: Request, email: str = Depends(person)):
            await _or_refused(memory.tenant_extension.remove_member(email, team, body.email, client_ip(request.headers)))
            return {"team": team, "email": body.email}

        @router.post("/teams/{team}/confirmations")
        async def confirm_member(team: str, body: Member, request: Request, email: str = Depends(person)):
            """Confirm a pending request to add someone, filed by an agent over MCP, for the role the page showed."""
            change = memory.tenant_extension.confirm_member(email, team, body.email, body.role, client_ip(request.headers))
            await _or_refused(change)
            return {"team": team, "email": body.email, "role": body.role}

        @router.delete("/teams/{team}/requests")
        async def decline_member(team: str, body: FormerMember, request: Request, email: str = Depends(person)):
            """Decline a pending request to add someone, filed by an agent over MCP."""
            await _or_refused(memory.tenant_extension.decline_member(email, team, body.email, client_ip(request.headers)))
            return {"team": team, "email": body.email}

        router.include_router(admin_router)
        return router


NAV = (("/ext/", "key", "Your keys"), ("/ext/teams", "users", "Teams"), ("/ext/admin", "shield", "Key Allowlist"))
NO_STALE = '<tr><td colspan="3" class="empty">No stale personal schemas.</td></tr>'


def shell(title: str, current: str, email: str, role: str | None, main: str) -> str:
    """A page in the Console frame: the sidebar, then `main`. Only admins see the Key Allowlist link."""
    links = []
    for href, icon, label in NAV:
        if href == "/ext/admin" and role != "admin":
            continue
        here = ' aria-current="page"' if href == current else ""
        badge = '<span class="badge">Admin</span>' if href == "/ext/admin" else ""
        links.append(f'<a href="{href}"{here}><svg class="i"><use href="#{icon}"/></svg>{label}{badge}</a>')
    # One pass, so a value that contains a placeholder is not substituted again.
    return SHELL.substitute(
        title=title,
        style=STYLE,
        logo=LOGO,
        nav="".join(links),
        email=html.escape(email),
        role=ROLE_LABELS.get(role, "Not on the Key Allowlist"),
        main=main,
    )


STYLE = """:root{--cyan:#00a1e2;--navy:#051a35;--muted:#475467;--bg:#F0F3F4;--wash:#EEFAFF;--line:#d1d6dc;--link:#0071ce;--link-h:#0049a6;--err:#cb5555;--err-t:#a63d3d;--err-bg:#fbeeee;--ok:#4fa06e;--ok-t:#27693f;--ok-bg:#edf7f1;
--head:"Source Sans 3","Source Sans Pro","Segoe UI",system-ui,-apple-system,sans-serif;--body:"Open Sans","Segoe UI",system-ui,-apple-system,sans-serif;--mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
html{color-scheme:light}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--navy);font:14px/1.5 var(--body);font-variant-numeric:tabular-nums}
h1,h2,h3{font-family:var(--head);margin:0}
h1{font-weight:400;font-size:30px;line-height:1.15;letter-spacing:-.01em}
h2{font-weight:600;font-size:17px}
h3{font-weight:600;font-size:15px;margin-bottom:8px}
a{color:var(--link)}a:hover{color:var(--link-h)}
code,.mono{font-family:var(--mono);font-size:12.5px}
:focus-visible{outline:2px solid var(--link);outline-offset:2px;border-radius:3px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
svg.i{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.shell{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.rail{background:var(--navy);color:#fff;display:flex;flex-direction:column;padding:20px 12px;position:sticky;top:0;height:100vh}
.rail .logo{display:block;padding:4px 10px 22px}.rail .logo svg{height:26px;width:auto;display:block}
.rail .label{font:600 11px var(--body);letter-spacing:.08em;text-transform:uppercase;color:#a9bad0;padding:0 10px 8px}
.rail nav{display:flex;flex-direction:column;gap:2px}
.rail nav a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:6px;color:#dbe6f3;text-decoration:none;font-weight:600;transition:background .15s,color .15s;position:relative}
.rail nav a:hover,.rail nav a[aria-current=page]{background:#0d2a4d;color:#fff}
.rail nav a[aria-current=page]::before{content:"";position:absolute;left:-12px;top:6px;bottom:6px;width:3px;border-radius:0 3px 3px 0;background:var(--cyan)}
.badge{margin-left:auto;font:700 10px var(--body);letter-spacing:.06em;text-transform:uppercase;color:var(--navy);background:var(--cyan);border-radius:50px;padding:1px 7px}
.me{margin-top:auto;border-top:1px solid #1C3A5E;padding:14px 10px 0;font-size:12.5px}
.me b{display:block;font-weight:600;color:#fff;overflow-wrap:anywhere}
.chip{display:inline-block;margin-top:4px;font:600 11px var(--body);border:1px solid #3b5a82;color:#dbe6f3;border-radius:50px;padding:1px 9px}
main{position:relative;overflow-x:clip;padding:32px 40px 64px;max-width:1180px;width:100%}
.head{margin-bottom:20px}
.head p{margin:6px 0 0;color:var(--muted);max-width:60ch}
.btn{display:inline-flex;align-items:center;gap:8px;border:1px solid transparent;border-radius:50px;padding:8px 18px;font:600 13.5px var(--body);cursor:pointer;background:var(--cyan);color:var(--navy);transition:background .15s;white-space:nowrap}
.btn:hover{background:#26b2ee}.btn:active{background:#0091cc}
.btn.sec{background:#fff;border-color:var(--line)}.btn.sec:hover{background:var(--wash);border-color:var(--cyan)}
.btn.sm{padding:3px 12px;font-size:12.5px}
.btn.danger{background:#fff;border-color:#e1b1b1;color:var(--err-t)}.btn.danger:hover{background:var(--err-bg);border-color:var(--err)}
label{display:block;font-weight:600;font-size:12.5px;margin-bottom:4px}
input[type=text],input[type=email]{width:100%;margin-top:4px;border:1px solid #9aa4b0;border-radius:3px;padding:7px 10px;font:14px var(--body);background:#fff;color:var(--navy);transition:border-color .15s,box-shadow .15s}
label+input{margin-top:0}
input:hover{border-color:var(--navy)}
input:focus{outline:none;border-color:var(--link);box-shadow:0 0 0 3px rgba(0,113,206,.25)}
.hint{color:var(--muted);font-size:12.5px;margin:4px 0 0}
.row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}.row>div{flex:1;min-width:180px}.row>.btn{flex:none}
.card{background:#fff;border:1px solid var(--line);border-radius:6px;margin-bottom:20px}
.card.risky{border-color:#e1b1b1}
.card>header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line)}
.card>header p{margin:2px 0 0;color:var(--muted);font-size:13px}
.card .pad{padding:16px 18px}
.banner{display:flex;gap:12px;align-items:center;background:var(--wash);border:1px solid #bfe6f7;border-radius:6px;padding:10px 16px;margin-bottom:20px}
.banner svg{color:var(--link)}
.note{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-radius:6px;background:#fff;border:1px solid var(--line);margin:0 0 20px}
.note .grow{flex:1}
.status{min-height:22px;margin:0 0 14px;font-weight:600}
.status.refused{color:var(--err-t)}.status.ok{color:var(--ok-t)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font:600 11.5px var(--body);letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 18px;border-bottom:1px solid var(--line);background:#fafbfc;white-space:nowrap}
td{padding:10px 18px;border-bottom:1px solid #e6eaee;vertical-align:middle}
td.strong{font-weight:600}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#f7fbfd}
td.act{text-align:right;white-space:nowrap}
td.act .btn{opacity:0;transition:opacity .15s}
tr:hover td.act .btn,tr:focus-within td.act .btn{opacity:1}
@media (hover:none),(max-width:860px){td.act .btn{opacity:1}}
.idbtn{font:12.5px var(--mono);background:var(--bg);border:1px solid transparent;border-radius:3px;padding:1px 6px;color:var(--navy);cursor:pointer;display:inline-flex;gap:6px;align-items:center}
.idbtn:hover{border-color:var(--line);background:#fff}
.idbtn svg{opacity:.55}
.pill{display:inline-flex;align-items:center;gap:6px;font:600 12px var(--body);padding:1px 10px 1px 8px;border-radius:50px;border:1px solid transparent;white-space:nowrap}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.pill.active{color:var(--ok-t);background:var(--ok-bg);border-color:#c5e3d1}.pill.active::before{background:var(--ok)}
.pill.revoked{color:var(--muted);background:var(--bg);border-color:var(--line);text-decoration:line-through}
.pill.expired{color:var(--err-t);background:var(--err-bg);border-color:#efc9c9}.pill.expired::before{background:var(--err)}
.pill.ask{color:var(--link-h);background:var(--wash);border-color:#bfe6f7}.pill.ask::before{background:var(--cyan)}
.pill.admin{color:var(--navy);background:#fff;border-color:var(--navy)}.pill.admin::before{background:var(--navy)}
.pill.member{color:var(--navy);background:var(--bg);border-color:var(--line)}.pill.member::before{background:var(--muted)}
tr.dim td:not(.act){color:var(--muted)}
.life{display:flex;flex-direction:column;gap:4px;min-width:140px}
.bar{height:4px;background:#e3e8ed;border-radius:4px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--cyan);border-radius:4px}
.bar.low i{background:var(--navy)}
.sub{color:var(--muted);font-size:12px}
.empty{padding:28px 18px;text-align:center;color:var(--muted)}
.team .meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:4px}
.team .cols{display:grid;grid-template-columns:1.2fr 1fr}
.team .cols>div{padding:16px 18px}.team .cols>div+div{border-left:1px solid var(--line)}
.pending{background:var(--wash);border-bottom:1px solid #bfe6f7;padding:12px 18px}
.pending ul{list-style:none;margin:8px 0 0;padding:0}
.pending li{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 0}
.pending .who{flex:1;min-width:200px}
.members{list-style:none;margin:0;padding:0}
.members li{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #eef1f4}
.members li:last-child{border:0}.members .e{flex:1;overflow-wrap:anywhere}
.members .x{opacity:0;transition:opacity .15s}
.members li:hover .x,.members li:focus-within .x{opacity:1}
@media (hover:none),(max-width:860px){.members .x{opacity:1}}
fieldset{border:0;padding:0;margin:0}
.seg{display:inline-flex;border:1px solid #9aa4b0;border-radius:3px;overflow:hidden}
.seg label{margin:0;cursor:pointer}
.seg span{display:block;padding:6px 12px;font-size:13px}
.seg input{position:absolute;opacity:0}
.seg input:checked+span{background:var(--navy);color:#fff}
.seg input:focus-visible+span{outline:2px solid var(--link);outline-offset:-2px}
.subform{display:flex;flex-direction:column;gap:10px}.subform .btn{align-self:flex-start}
.subform+.subform{margin-top:14px;padding-top:14px;border-top:1px solid #e6eaee}
.two{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
.two>.card{margin:0}
dialog{border:0;border-radius:16px;padding:0;width:min(560px,calc(100vw - 32px));color:var(--navy);box-shadow:0 12px 40px rgba(5,26,53,.35)}
dialog::backdrop{background:rgba(5,26,53,.6)}
dialog[open]{animation:pop .18s ease-out}
.dlg{padding:24px}
.dlg h2{font-size:22px;display:flex;align-items:center;gap:10px}
.dlg .ico{width:34px;height:34px;border-radius:50%;background:var(--navy);color:#fff;display:grid;place-items:center;flex:none}
.warn{display:flex;gap:10px;border-left:3px solid var(--cyan);background:var(--wash);padding:10px 12px;margin:14px 0;border-radius:0 6px 6px 0}
.warn svg{margin-top:2px;color:var(--link)}
.secret{display:flex;gap:8px;align-items:stretch}
.secret output{flex:1;font:14px var(--mono);background:var(--navy);color:#EDF3FA;border-radius:6px;padding:12px 14px;overflow-wrap:anywhere;letter-spacing:.02em;min-height:46px;display:flex;align-items:center}
.secret .btn{border-radius:6px}
.dlg .foot{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
@keyframes pop{from{opacity:0;transform:translateY(8px) scale(.98)}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media (max-width:860px){
.shell{display:block}
.rail{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;padding:10px 12px;gap:6px 12px}
.rail .logo{padding:0}.rail .label{display:none}
.rail nav{flex-direction:row;order:3;width:100%;overflow-x:auto}
.rail nav a{padding:6px 10px;white-space:nowrap}
.rail nav a[aria-current=page]::before{left:10px;right:10px;top:auto;bottom:0;width:auto;height:3px;border-radius:3px 3px 0 0}
.me{margin:0 0 0 auto;border:0;padding:0;text-align:right}
main{padding:20px 14px 48px}
h1{font-size:26px}
.team .cols,.two{grid-template-columns:1fr}.team .cols>div+div{border-left:0;border-top:1px solid var(--line)}
th,td{padding-left:12px;padding-right:12px}
}"""

# The white horizontal Aseva logo, inline because the pages have no static route.
LOGO = """<svg role="img" aria-label="Aseva" id="aseva-horizontal-white" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 432 113.06"><path id="aseva-horizontal-white-logo" fill="#fff" d="M169.51,84.46c-9.42,0-19.18-6.06-19.18-16.38,0-12.23,10.09-18.17,20.97-18.17,6.73,0,13.91,1.46,20.08,4.71v-8.3c0-10.54-9.65-13.24-18.28-13.24-6.28,0-12.79,1.46-17.38,4.15l-1.23-4.49c5.05-2.8,12.23-4.49,19.29-4.49,11.66,0,22.77,4.71,22.77,18.17l-.11,24.67c0,6.51-.34,10.21,6.84,9.31l.22,3.7c-9.2,1.46-11.55-1.79-11.22-10.32-4.26,7.85-13.8,10.66-22.77,10.66ZM191.38,59.33c-5.83-3.14-13.01-5.05-19.4-4.94-8.08,0-16.71,4.49-16.38,13.46.34,8.3,7.29,12,14.81,12,8.75,0,18.62-3.93,20.97-13.24v-7.29ZM213.81,68.87c.9,7.85,9.76,11.44,18.51,11.44s17.95-3.59,17.95-11.33c0-9.31-10.66-9.98-17.83-10.88-10.77-1.23-22.32-3.14-22.32-14.24s10.77-15.37,21.87-15.37,21.87,4.6,21.87,14.24h-4.94c0-6.73-8.41-9.76-16.82-9.76s-17.61,3.14-17.05,10.77c0,8.3,11.78,9.08,18.06,9.65,11.1,1.46,22.66,3.48,22.32,15.59,0,10.77-10.99,15.81-23.22,15.81-11.44,0-22.43-4.49-23.67-15.93h5.27ZM315.43,56.75h-45.87c0,15.59,9.76,22.77,24,23.11,7.29-.11,13.46-1.79,18.73-4.15l1.12,4.6c-6.28,2.8-13.46,4.37-19.74,4.37-18.17,0-30.4-10.66-29.5-30.06.9-16.49,11.89-26.25,27.37-26.25,17.5.11,26.92,10.32,23.89,28.38ZM310.94,52.15c1.23-12.79-7.51-19.29-19.63-19.29s-20.41,7.18-21.65,19.29h41.27ZM346.23,83.78l-25.24-53.72v-.56h5.94l20.3,45.2,20.64-45.2h5.72v.56l-25.01,53.72h-2.36ZM398.02,84.46c-9.42,0-19.18-6.06-19.18-16.38,0-12.23,10.09-18.17,20.97-18.17,6.73,0,13.91,1.46,20.08,4.71v-8.3c0-10.54-9.65-13.24-18.28-13.24-6.28,0-12.79,1.46-17.38,4.15l-1.23-4.49c5.05-2.8,12.23-4.49,19.29-4.49,11.66,0,22.77,4.71,22.77,18.17l-.11,24.67c0,6.51-.34,10.21,6.84,9.31l.22,3.7c-9.2,1.46-11.55-1.79-11.22-10.32-4.26,7.85-13.8,10.66-22.77,10.66ZM419.89,59.33c-5.83-3.14-13.01-5.05-19.4-4.94-8.08,0-16.71,4.49-16.38,13.46.34,8.3,7.29,12,14.81,12,8.75,0,18.62-3.93,20.97-13.24v-7.29ZM61.66,43.82l-2.61,13.56c-.03.15-.11.27-.24.36-.09.06-.2.1-.31.1-.04,0-.07,0-.11-.01l-1.97-.38c-.3-.06-.5-.35-.44-.66l2.61-13.56c.03-.15.11-.27.24-.36.12-.08.27-.11.42-.09l1.97.38c.3.06.5.35.44.66ZM56.47,33.06c-.1-.11-.23-.18-.38-.2l-1.99-.16c-.31-.03-.58.2-.6.51l-1.66,19.87c-.01.15.03.3.13.41.1.11.23.18.38.2l1.99.16s.03,0,.05,0c.29,0,.53-.22.56-.51l1.66-19.87c.01-.15-.03-.29-.13-.41ZM52.2,22.11c-.1-.11-.24-.18-.39-.19l-2-.11c-.31-.01-.57.22-.59.53l-1.57,28.03c0,.15.04.29.14.4.1.11.24.18.39.19l2,.11s.02,0,.03,0c.29,0,.54-.23.56-.53l1.57-28.03c0-.15-.04-.29-.14-.4ZM2.07,62.58c-.12-.09-.27-.12-.42-.1-.15.02-.28.1-.37.22l-1.18,1.62c-.18.25-.13.6.12.78l4.48,3.26c.1.07.21.11.33.11.03,0,.06,0,.09,0,.15-.02.28-.1.37-.22l1.18-1.62c.18-.25.13-.6-.12-.78l-4.48-3.26ZM2.52,55.74c-.11-.1-.25-.15-.4-.15-.15,0-.29.07-.39.18l-1.35,1.47c-.21.23-.19.58.03.79l6.2,5.7c.1.1.24.15.38.15,0,0,.02,0,.02,0,.15,0,.29-.07.39-.18l1.35-1.47c.21-.23.19-.58-.03-.79l-6.2-5.7ZM4.7,49.23c-.1-.11-.23-.18-.38-.19-.15-.01-.29.04-.41.14l-1.51,1.31c-.23.2-.26.56-.06.79l6.99,8.09c.1.11.23.18.38.19.01,0,.03,0,.04,0,.13,0,.26-.05.37-.14l1.51-1.31c.23-.2.26-.56.06-.79l-6.99-8.09ZM7.72,39.99c-.15-.27-.5-.36-.76-.21l-1.74.99c-.13.07-.22.2-.26.34s-.02.3.05.42l7.83,13.68c.1.18.29.28.49.28.09,0,.19-.02.28-.07l1.74-.99c.13-.07.22-.2.26-.34.04-.14.02-.3-.05-.42l-7.83-13.68ZM11.03,30.01c-.13-.28-.46-.41-.74-.28l-1.82.82c-.14.06-.24.17-.29.31-.05.14-.05.29.01.43l9.15,20.44c.09.21.3.33.51.33.08,0,.15-.02.23-.05l1.83-.82c.14-.06.24-.17.29-.31.05-.14.05-.29-.01-.43l-9.16-20.44ZM16.7,20.53c-.04-.14-.14-.26-.28-.33-.13-.07-.29-.08-.43-.04l-1.91.61c-.29.09-.46.41-.36.7l8.75,27.6c.04.14.14.26.28.33.08.04.17.06.26.06.06,0,.11,0,.17-.03l1.91-.61c.29-.09.46-.41.36-.7l-8.75-27.6ZM29.66,1.29c-.12-.09-.27-.13-.41-.11l-1.98.28c-.31.04-.52.32-.48.63l6.2,44.85c.02.15.1.28.22.37.1.07.22.11.34.11.03,0,.05,0,.08,0l1.98-.28c.31-.04.52-.33.48-.63L29.88,1.66c-.02-.15-.1-.28-.22-.37ZM37.68,0l-2,.11c-.15,0-.29.08-.39.19-.1.11-.15.26-.14.4l2.63,46.49c.02.3.26.53.56.53.01,0,.02,0,.03,0l2-.11c.15,0,.29-.08.39-.19.1-.11.15-.26.14-.4L38.27.53c-.02-.31-.28-.54-.59-.53ZM44.66,9.05l-2,.03c-.15,0-.29.06-.39.17s-.16.25-.16.4l.52,38.66c0,.31.25.55.56.55h0l2-.03c.15,0,.29-.06.39-.17s.16-.25.16-.4l-.52-38.66c0-.31-.25-.55-.57-.55ZM2.07,67.95c-.25-.18-.6-.13-.78.12l-1.18,1.62c-.09.12-.12.27-.1.42.02.15.1.28.22.37l2.99,2.17c.1.07.21.11.33.11.17,0,.34-.08.45-.23l1.18-1.62c.09-.12.12-.27.1-.42s-.1-.28-.22-.37l-2.99-2.17ZM22.27,10.85c-.03-.14-.12-.27-.25-.35-.13-.08-.28-.1-.42-.07l-1.95.45c-.3.07-.49.37-.42.67l8.39,36c.03.14.12.27.25.35.09.06.19.08.3.08.04,0,.09,0,.13-.01l1.95-.45c.3-.07.49-.37.42-.67L22.27,10.85ZM62.63,62.11l1.83-9.99c.06-.3-.15-.6-.45-.65l-1.97-.36c-.15-.03-.3,0-.42.09-.12.08-.21.21-.23.36l-1.83,9.99c-.06.3.15.6.45.65l1.97.36s.07,0,.1,0c.11,0,.22-.03.32-.1.12-.08.21-.21.23-.36ZM67.6,55.62l-1.97-.38c-.15-.03-.3,0-.42.09-.12.08-.21.21-.24.36l-2.61,13.56c-.06.3.14.6.44.66l1.97.38s.07.01.11.01c.11,0,.22-.03.31-.1.12-.08.21-.21.24-.36l2.61-13.56c.06-.3-.14-.6-.44-.66ZM72.06,59.57c-.1-.11-.23-.18-.38-.2l-1.99-.16c-.31-.03-.58.2-.6.51l-1.66,19.87c-.01.15.03.3.13.41.1.11.23.18.38.2l1.99.16s.03,0,.05,0c.29,0,.53-.22.56-.51l1.66-19.87c.01-.15-.03-.3-.13-.41ZM75.84,62.09l-2-.11c-.31-.01-.57.22-.59.53l-1.57,28.03c0,.15.04.29.14.4.1.11.24.18.39.19l2,.11s.02,0,.03,0c.29,0,.54-.23.56-.53l1.57-28.03c0-.15-.04-.29-.14-.4s-.24-.18-.39-.19ZM123.8,47.95l-4.48-3.26c-.12-.09-.27-.12-.42-.1-.15.02-.28.1-.37.22l-1.18,1.62c-.18.25-.13.6.12.78l4.48,3.26c.1.07.21.11.33.11.03,0,.06,0,.09,0,.15-.02.28-.1.37-.22l1.18-1.62c.18-.25.13-.6-.12-.78ZM117.41,49.31c-.23-.21-.58-.19-.79.03l-1.35,1.47c-.1.11-.15.25-.15.4,0,.15.07.29.18.39l6.2,5.7c.11.1.24.15.38.15.15,0,.3-.06.41-.18l1.35-1.47c.1-.11.15-.25.15-.4,0-.15-.07-.29-.18-.39l-6.2-5.71ZM114.7,53.7c-.1-.11-.23-.18-.38-.19-.15-.01-.29.04-.41.13l-1.51,1.31c-.23.2-.26.56-.06.79l6.99,8.09c.1.11.23.18.38.19.01,0,.03,0,.04,0,.13,0,.26-.05.37-.14l1.51-1.31c.23-.2.26-.56.06-.79l-6.99-8.09ZM111.19,57.83c-.07-.13-.2-.22-.34-.26-.14-.04-.3-.02-.42.05l-1.74.99c-.27.15-.36.5-.21.76l7.83,13.69c.07.13.2.22.34.26.05.01.1.02.15.02.1,0,.19-.03.28-.07l1.74-.99c.27-.15.36-.5.21-.76l-7.83-13.69ZM106.68,61.33c-.13-.28-.46-.41-.74-.28l-1.82.82c-.14.06-.24.17-.29.31-.05.14-.05.29.01.43l9.15,20.44c.09.21.3.33.51.33.08,0,.15-.02.23-.05l1.83-.82c.14-.06.24-.17.29-.31s.05-.29-.01-.43l-9.16-20.44ZM101.55,63.98c-.04-.14-.14-.26-.28-.33-.13-.07-.29-.08-.43-.04l-1.91.61c-.29.09-.46.41-.36.7l8.75,27.6c.04.14.14.26.28.33.08.04.17.06.26.06.06,0,.11,0,.17-.03l1.91-.61c.29-.09.46-.41.36-.7l-8.75-27.6ZM90.81,65.74c-.12-.09-.27-.13-.41-.11l-1.98.28c-.31.04-.52.32-.48.63l6.2,44.85c.02.15.1.28.22.37.1.07.22.11.34.11.03,0,.05,0,.08,0l1.98-.28c.31-.04.52-.32.48-.63l-6.2-44.85c-.02-.15-.1-.28-.22-.37ZM85.65,65.34l-2,.11c-.15,0-.29.08-.39.19s-.15.26-.14.4l2.63,46.49c.02.3.26.53.56.53.01,0,.02,0,.03,0l2-.11c.15,0,.29-.08.39-.19.1-.11.15-.26.14-.4l-2.63-46.49c-.02-.31-.28-.54-.59-.53ZM80.83,64.2l-2,.03c-.15,0-.29.06-.39.17s-.16.25-.16.4l.52,38.66c0,.31.25.55.56.55h0l2-.03c.15,0,.29-.06.39-.17s.16-.25.16-.4l-.52-38.66c0-.31-.25-.55-.57-.55ZM121.96,45.11c.1.07.21.11.33.11.03,0,.06,0,.09,0,.15-.02.28-.1.36-.22l1.17-1.62c.18-.25.13-.6-.13-.78l-2.99-2.16c-.12-.09-.27-.12-.42-.1-.15.02-.28.1-.37.22l-1.17,1.62c-.18.25-.13.6.13.78l2.99,2.16ZM96.4,65.5c-.03-.14-.12-.27-.25-.35-.13-.08-.28-.1-.42-.07l-1.95.45c-.3.07-.49.37-.42.67l8.39,36c.03.14.12.27.25.35.09.06.19.08.3.08.04,0,.09,0,.13-.01l1.95-.45c.3-.07.49-.37.42-.67l-8.39-36Z"/></svg>"""

# Every page: the sidebar, the key reveal dialog and the shared script, then the page's own
# content and script. The shared script runs first, so the page's script can call it.
SHELL = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title - Agent Keys</title>
<style>
$style
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<symbol id="key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/></symbol>
<symbol id="users" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.5-4 3-6 6.5-6s6 2 6.5 6M16 4.5a3.5 3.5 0 010 7M21.5 20c-.3-2.6-1.5-4.4-3.5-5.2"/></symbol>
<symbol id="shield" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></symbol>
<symbol id="copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/></symbol>
<symbol id="eye" viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></symbol>
<symbol id="eyeoff" viewBox="0 0 24 24"><path d="M3 3l18 18M10.6 5.1A9.7 9.7 0 0112 5c6.4 0 10 7 10 7a17 17 0 01-3.2 4M6.5 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7c1.5 0 2.9-.4 4.1-1M9.9 9.9a3 3 0 004.2 4.2"/></symbol>
<symbol id="alert" viewBox="0 0 24 24"><path d="M12 3L2 20h20zM12 10v4M12 17.5v.01"/></symbol>
<symbol id="clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></symbol>
</svg>
<dialog id="reveal" aria-labelledby="rv-h"><div class="dlg">
<h2 id="rv-h"><span class="ico"><svg class="i"><use href="#key"/></svg></span>Key created</h2>
<p style="margin:12px 0 0"><b id="rv-name"></b> <span class="sub mono" id="rv-id"></span></p>
<div class="warn"><svg class="i"><use href="#alert"/></svg><div><b>Shown only now.</b> Copy it and store it in your agent's secret store.
Hindsight keeps only a hash, so this key cannot be shown again.</div></div>
<label for="rv-secret">Secret key</label>
<div class="secret"><output id="rv-secret" tabindex="0"></output>
<button class="btn sec" type="button" id="rv-eye" aria-pressed="false" aria-label="Show key"><svg class="i"><use href="#eye"/></svg></button>
<button class="btn" type="button" id="rv-copy"><svg class="i"><use href="#copy"/></svg>Copy</button></div>
<p class="status ok" role="status" id="rv-st" style="margin:8px 0 0"></p>
<div class="foot"><button class="btn" type="button" id="rv-done">I've stored it</button></div>
</div></dialog>
<script>
const DAY = 864e5;
const day = (iso) => new Date(iso).toLocaleDateString("en-GB", {day: "numeric", month: "short", year: "numeric", timeZone: "UTC"});
const ago = (iso) => {
  const n = Math.floor((Date.now() - Date.parse(iso)) / DAY);
  return n < 1 ? "today" : n === 1 ? "yesterday" : n + " days ago";
};
function say(text, refused) {
  const status = document.getElementById("result");
  status.textContent = text;
  status.className = "status " + (refused ? "refused" : "ok");
}
async function send(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: {"Content-Type": "application/json", "X-Agent-Keys": "1"},
    body: JSON.stringify(body),
  });
  const answer = resp.status === 204 ? {} : await resp.json();
  if (!resp.ok) say("Refused: " + JSON.stringify(answer.detail), true);
  return resp.ok ? answer : null;
}
async function copy(text, done) {
  try {
    await navigator.clipboard.writeText(text);
    done("Copied.");
  } catch {
    done("Could not copy; select it and copy it yourself.");
  }
}
// A new key's secret lives only here and in the dialog, until "I've stored it".
let rvKey = "";
const rvDialog = document.getElementById("reveal"), rvSecret = document.getElementById("rv-secret");
const rvEye = document.getElementById("rv-eye"), rvSt = document.getElementById("rv-st");
function rvMask(masked) {
  rvSecret.textContent = masked ? "•".repeat(32) : rvKey;
  rvEye.setAttribute("aria-pressed", String(!masked));
  rvEye.setAttribute("aria-label", masked ? "Show key" : "Hide key");
  rvEye.querySelector("use").setAttribute("href", masked ? "#eye" : "#eyeoff");
}
function reveal(created) {
  rvKey = created.key;
  document.getElementById("rv-name").textContent = created.name;
  document.getElementById("rv-id").textContent = created.id;
  rvSt.textContent = "";
  rvMask(true);
  rvDialog.showModal();
}
rvEye.onclick = () => rvMask(rvEye.getAttribute("aria-pressed") === "true");
document.getElementById("rv-copy").onclick = () => copy(rvKey, (text) => { rvSt.textContent = text; });
document.getElementById("rv-done").onclick = () => {
  rvKey = "";
  rvSecret.textContent = "";
  rvDialog.close();
};
rvDialog.addEventListener("cancel", (event) => event.preventDefault());  // Esc must not lose the only copy
document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-copy]");
  if (button) copy(button.dataset.copy, (text) => say(button.dataset.copy + ": " + text));
});
</script>
<div class="shell">
<aside class="rail">
<a class="logo" href="/ext/" aria-label="Agent Keys home">$logo</a>
<div class="label">Agent Keys</div>
<nav aria-label="Agent Keys">$nav</nav>
<div class="me"><b>$email</b><span class="chip">$role</span></div>
</aside>
<main>
$main
</main>
</div>
</body>
</html>
""")

PAGE = Template("""<div class="head"><h1>Your keys</h1>
<p>Personal Agent Keys let your AI coding agents reach Hindsight memory as you.</p></div>
<div class="banner"><svg class="i"><use href="#clock"/></svg>
<b>Your keys work for 90 days, and only while you sign in here at least every 30 days.</b></div>
$allowlist
<p class="status" id="result" role="status"></p>
<div class="card"$create_hidden>
<header><div><h2>Create a personal key</h2><p>Name it after the agent or machine that will use it.</p></div></header>
<form class="pad" id="create"><div class="row"><div><label for="key-name">Key name</label>
<input id="key-name" type="text" required maxlength="100" placeholder="e.g. claude-code laptop"></div>
<button class="btn">Create a personal key</button></div></form>
</div>
<div class="card"><header><h2>Keys</h2><span class="sub" id="key-count"></span></header>
<div class="tw"><table>
<thead><tr><th scope="col">Name</th><th scope="col">ID</th><th scope="col">Created</th><th scope="col">Expires</th>
<th scope="col">State</th><th scope="col"><span class="sr">Actions</span></th></tr></thead>
<tbody id="keys"></tbody>
</table></div></div>
<script>
const ACTIONS = [["renew", "Renew", "sec", "renewed"], ["revoke", "Revoke", "danger", "revoked"]];
function expiry(key) {
  // Built only from dates and numbers, never from what a person typed.
  // Whole days left, so 1d 1s reads "1 day left"; the server's state wins over the browser clock.
  const left = Math.floor((Date.parse(key.expires_at) - Date.now()) / DAY);
  const when = key.state === "expired" ? "expired " + ago(key.expires_at)
    : left < 1 ? "expires today" : left + (left === 1 ? " day left" : " days left");
  const width = Math.max(0, Math.min(100, left / 90 * 100));
  return '<div class="life" title="' + day(key.expires_at) + '"><span>' + when + '</span>'
    + '<div class="bar' + (left < 30 ? " low" : "") + '" role="img" aria-label="' + Math.max(left, 0) + ' of 90 days left">'
    + '<i style="width:' + width + '%"></i></div></div>';
}
async function showKeys() {
  const keys = await (await fetch("/ext/keys")).json();
  document.getElementById("key-count").textContent = keys.length + (keys.length === 1 ? " key" : " keys");
  const rows = keys.map((key) => {
    const row = document.createElement("tr");
    if (key.state !== "active") row.className = "dim";
    const name = row.insertCell();
    name.className = "strong";
    name.textContent = key.name;
    const id = row.insertCell().appendChild(document.createElement("button"));
    id.type = "button";
    id.className = "idbtn";
    id.title = "Copy the key ID";
    id.dataset.copy = key.id;
    id.textContent = key.id;
    const created = row.insertCell();
    created.textContent = ago(key.created_at);
    created.title = day(key.created_at);
    row.insertCell().innerHTML = key.state === "revoked" ? '<span class="sub">-</span>' : expiry(key);
    const pill = row.insertCell().appendChild(document.createElement("span"));
    pill.className = "pill " + key.state;
    pill.textContent = key.state[0].toUpperCase() + key.state.slice(1);
    const actions = row.insertCell();
    actions.className = "act";
    for (const [action, label, style, done] of key.state === "active" ? ACTIONS : []) {
      const button = actions.appendChild(document.createElement("button"));
      button.type = "button";
      button.className = "btn sm " + style;
      button.textContent = label;
      button.onclick = async () => {
        if (action === "revoke" && !confirm("Revoke " + key.name + "? Agents using it stop at once.")) return;
        if (await send("POST", "/ext/keys/" + key.id + "/" + action, {})) {
          say(key.name + ": " + done + ".");
          showKeys();
        }
      };
      actions.append(" ");
    }
    return row;
  });
  if (!rows.length) rows.push(Object.assign(document.createElement("tr"), {innerHTML: '<td colspan="6" class="empty">No keys yet.</td>'}));
  document.getElementById("keys").replaceChildren(...rows);
}
document.getElementById("create").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = await send("POST", "/ext/keys", {name: document.getElementById("key-name").value});
  if (body) {
    event.target.reset();
    say("Created " + body.name + ".");
    reveal(body);
    showKeys();
  }
});
showKeys();
document.getElementById("request-access")?.addEventListener("click", async () => {
  if (await send("POST", "/ext/access-requests", {})) location.reload();
});
</script>
""")

ADMIN_PAGE = Template("""<div class="head"><h1>Key Allowlist</h1>
<p>Only people on the Key Allowlist can create Agent Keys. Removing someone disables the keys they hold.</p></div>
<p class="status" id="result" role="status"></p>
<div class="two">
<div class="card"><header><div><h2>Add to the Key Allowlist</h2><p>They can create keys right away.</p></div></header>
<form class="pad" id="add"><div class="row"><div><label for="email">Email</label>
<input id="email" type="email" required maxlength="254"></div><button class="btn">Add</button></div></form></div>
<div class="card risky"><header><div><h2>Revoke an identity</h2><p>Revokes every key this person holds.</p></div></header>
<form class="pad" id="revoke-identity"><div class="row"><div><label for="identity">Email</label>
<input id="identity" type="email" required maxlength="254"></div>
<button class="btn danger">Revoke every key this person holds</button></div></form></div>
</div>
<div class="card"><header><h2>People</h2></header>
<div class="tw"><table>
<thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col"><span class="sr">Change</span></th></tr></thead>
<tbody>
$rows
</tbody>
</table></div></div>
<div class="card"><header><div><h2>Stale personal schemas</h2>
<p>Personal schemas that no valid key has reached for 90 days. Nothing is deleted automatically:
an operator purges a schema with <code>scripts/purge-schema.sql</code> (README, "Stale personal schemas").</p></div></header>
<div class="tw"><table>
<thead><tr><th scope="col">Schema</th><th scope="col">Owner</th><th scope="col">Last key activity</th></tr></thead>
<tbody>
$stale
</tbody>
</table></div></div>
<script>
async function setRole(email, role) {
  if (await send("POST", "/ext/admin/people", {email, role})) location.reload();
}
document.getElementById("add").addEventListener("submit", (event) => {
  event.preventDefault();
  setRole(document.getElementById("email").value, "member");
});
document.querySelectorAll("button[data-email]").forEach((button) => {
  button.addEventListener("click", () => {
    if (button.dataset.confirm && !confirm(button.dataset.confirm)) return;
    setRole(button.dataset.email, button.dataset.role || null);
  });
});
document.getElementById("revoke-identity").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("identity").value;
  if (!confirm("Revoke every key " + email + " holds?")) return;
  const answer = await send("POST", "/ext/admin/revoke-identity", {email});
  if (answer) say("Revoked " + answer.revoked + " keys held by " + email + ".");
});
</script>
""")


def teams_html(email: str, role: str | None, teams: list[dict]) -> str:
    """The Teams page; every value from the database or the token is escaped."""
    e = html.escape
    sections = []
    for t in teams:
        url = f"/ext/teams/{e(t['team'])}"
        # Owners and admins see the controls; the server refuses changes from anyone else either way.
        manage = t["role"] == "owner" or role == "admin"
        members = "".join(
            f'<li><span class="e">{e(m["email"])}</span>'
            f'<span class="pill {"admin" if m["role"] == "owner" else "member"}">{e(m["role"])}</span>'
            f'{REMOVE_FORM.format(url=url, email=e(m["email"]), team=e(t["name"])) if manage else ""}</li>'
            for m in t["members"]
        )
        header = (
            f'<header><div><h2>{e(t["name"])}</h2><div class="meta"><span class="mono">{e(t["team"])}</span>'
            f'<span class="pill {"admin" if t["role"] == "owner" else "member"}">Your role: {e(t["role"] or "none (admin)")}</span>'
            "</div></div></header>"
        )
        parts = [header]
        if t["requests"]:
            asked = "".join(
                f'<li><span class="who">{e(q["email"])} as {e(q["role"])}, asked by {e(q["by"])}</span>'
                f'{REQUEST_FORMS.format(url=url, email=e(q["email"]), role=e(q["role"])) if manage else ""}</li>'
                for q in t["requests"]
            )
            parts.append(f'<div class="pending"><b>Waiting for an owner to confirm</b><ul>{asked}</ul></div>')
        side = KEY_FORM.format(url=url, label="Create a Team key", cls="subform") if t["role"] else ""
        side += MEMBER_FORM.format(url=url) if manage else '<p class="hint">Only owners and admins change membership.</p>'
        parts.append(f'<div class="cols"><div><h3>Members</h3><ul class="members">{members}</ul></div><div>{side}</div></div>')
        sections.append('<article class="card team">' + "".join(parts) + "</article>")
    # One pass, so a value that contains a placeholder is not substituted again.
    main = TEAMS_PAGE.substitute(
        public=KEY_FORM.format(url="/ext/teams/public", label="Create a Public Team key", cls="row"),
        teams="".join(sections) or '<p class="note">You are in no Team yet.</p>',
    )
    return shell("Teams", "/ext/teams", email, role, main)


KEY_FORM = """<form class="{cls}" data-url="{url}/keys" data-method="POST">
<div><label>Key name <input type="text" name="name" required maxlength="100"></label></div>
<button class="btn sec">{label}</button></form>"""

MEMBER_FORM = """<form class="subform" data-url="{url}/members" data-method="POST">
<h3>Add a member, or change a role</h3>
<label>Email <input name="email" type="email" required maxlength="254"></label>
<fieldset><legend class="sr">Role</legend><div class="seg">
<label><input type="radio" name="role" value="member" checked><span>Member</span></label>
<label><input type="radio" name="role" value="owner"><span>Owner</span></label></div></fieldset>
<div><button class="btn sec sm">Save member</button></div></form>"""

# Removing a member stops the keys they made for the Team, so the page asks first.
REMOVE_FORM = """<form data-url="{url}/members" data-method="DELETE" data-confirm="Remove {email} from {team}?">
<input type="hidden" name="email" value="{email}"><button class="btn danger sm x">Remove</button></form>"""

# A request an agent filed over MCP lets nobody in until an owner or admin presses Confirm,
# which sends the role shown, so a request changed since is refused rather than granted.
REQUEST_FORMS = """<form data-url="{url}/confirmations" data-method="POST">
<input type="hidden" name="email" value="{email}"><input type="hidden" name="role" value="{role}"><button class="btn sm">Confirm</button></form>
<form data-url="{url}/requests" data-method="DELETE">
<input type="hidden" name="email" value="{email}"><button class="btn sec sm">Decline</button></form>"""

TEAMS_PAGE = Template("""<div class="head"><h1>Teams</h1>
<p>Shared memory for a group. Team keys reach that Team's schema only.</p></div>
<p class="status" id="result" role="status"></p>
<div class="two">
<div class="card"><header><div><h2>Public Team</h2><p>Keys for the Public Team's schema.</p></div></header>
<div class="pad">$public</div></div>
<div class="card"><header><div><h2>Create a Team</h2><p>You become its owner.</p></div></header>
<form class="pad" data-url="/ext/teams" data-method="POST"><div class="row"><div><label for="team-name">Team name</label>
<input id="team-name" name="name" type="text" required maxlength="100"></div><button class="btn">Create</button></div></form></div>
</div>
$teams
<script>
for (const form of document.querySelectorAll("form[data-url]")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) return;
    const body = await send(form.dataset.method, form.dataset.url, Object.fromEntries(new FormData(form)));
    if (body && body.key) {
      form.reset();
      reveal(body);
    } else if (body) {
      location.reload();
    }
  });
}
</script>
""")
