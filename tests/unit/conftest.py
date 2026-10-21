"""Stand-ins for what the extension talks to: its database, Hindsight's migrations,
the event log, and a Cloudflare Access team that serves signing keys and signs JWTs."""

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hindsight_api.extensions.context import ExtensionContext
from jwt.algorithms import RSAAlgorithm

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.store import (
    ACTIVE_KEYS,
    CREATIONS_PER_HOUR,
    TEAMS_PER_PERSON,
    Refused,
)
from hindsight_agent_keys.web import AgentKeysHttpExtension

AUD = "aud-tag-0123456789"
PEPPER = "pepper-0123456789abcdef0123456789abcdef"
ACCESS_HOST = "keys.example.test"
# The delegation application and WorkPlane's own Access application, on the same Access team.
DELEGATION_HOST = "delegation.example.test"
DELEGATION_AUD = "delegation-aud-0123"
WORKPLANE_AUD = "workplane-aud-0123"
DELEGATE_ID = "workplane-0123.access"


class RecordedEvents:
    def __init__(self, fail=False):
        self.rows = []
        self.fail = fail

    async def start(self, db_url):
        pass

    async def stop(self):
        pass

    async def record(self, kind, key_id, client_ip, email=None, actor=None, team=None, *, channel=None, delegate=None):
        if self.fail:
            raise RuntimeError("event store unavailable")
        # Every column PostgresEventLog writes, so a path that loses its channel shows in a test.
        self.rows.append(
            {
                "kind": kind,
                "key_id": key_id,
                "client_ip": client_ip,
                "email": email,
                "actor": actor,
                "team": team,
                "channel": channel,
                "delegate": delegate,
            }
        )


class MemoryStore:
    """In-memory stand-in for PostgresKeyStore, with the same operations."""

    def __init__(self):
        self.people = {}
        self.keys = {}
        self.sign_ins = {}
        self.roles = {}
        self.teams_by_schema = {}
        self.team_roles = {}  # (team, email) -> "owner" | "member"
        self.creators = {}  # team -> email
        self.requests = {}  # (team, email) -> (role, requested_by)
        # Rows of the stale_schemas view, whose rule only Postgres runs (tests/integration).
        self.stale = []
        self.fail = False
        self.idempotency = {}  # (delegate, email, key) -> body_sha256, key_id, created_at

    async def stale_schemas(self):
        return self.stale

    async def tenant_schemas(self):
        if self.fail:
            raise OSError("database unavailable")
        return [s for s in self.people.values() if s] + list(self.teams_by_schema)

    async def check_team_limit(self, email):
        if list(self.creators.values()).count(email) >= TEAMS_PER_PERSON:
            raise Refused(429, f"You can create at most {TEAMS_PER_PERSON} Teams.")

    async def create_team(self, schema, name, owner):
        await self.check_team_limit(owner)
        if name.lower() in (n.lower() for n in self.teams_by_schema.values()):
            raise Refused(409, "A Team with that name exists.")
        self.teams_by_schema[schema] = name
        self.creators[schema] = owner
        self.team_roles[schema, owner] = "owner"

    async def team_schema(self, name):
        return next((s for s, n in self.teams_by_schema.items() if n.lower() == name.lower()), None)

    async def teams(self, email, everyone=False):
        rows = [
            {"schema": s, "name": n, "role": self.team_roles.get((s, email))} for s, n in self.teams_by_schema.items()
        ]
        return sorted((r for r in rows if everyone or r["role"]), key=lambda r: r["name"].lower())

    async def team_role(self, team, email):
        return self.team_roles.get((team, email))

    async def set_member(self, team, email, role):
        self._change_members(team, lambda roles: roles.__setitem__((team, email), role))

    async def remove_member(self, team, email):
        self._change_members(team, lambda roles: roles.pop((team, email), None))

    async def request_member(self, team, email, role, by):
        self._change_members(team, lambda roles: None)
        self.requests[team, email] = (role, by)

    async def confirm_member(self, team, email, role):
        asked, _ = self.requests.get((team, email), (None, None))
        if asked == role:
            await self.set_member(team, email, role)
            del self.requests[team, email]
        return asked

    async def decline_member(self, team, email):
        self._change_members(team, lambda roles: None)
        role, _ = self.requests.pop((team, email), (None, None))
        return role

    async def member_requests(self, team):
        return [{"email": e, "role": r, "requested_by": b} for (t, e), (r, b) in sorted(self.requests.items()) if t == team]

    def _change_members(self, team, change):
        if team not in self.teams_by_schema:
            raise Refused(404, "There is no such Team.")
        roles = dict(self.team_roles)
        change(roles)
        if "owner" not in (r for (t, _), r in roles.items() if t == team):
            raise Refused(409, "A Team must keep at least one owner.")
        self.team_roles = roles

    async def members(self, team):
        return [{"email": e, "role": r} for (t, e), r in sorted(self.team_roles.items()) if t == team]

    async def person_schema(self, email):
        return self.people.get(email)

    async def add_person(self, email, schema):
        self.people[email] = self.people.get(email) or schema
        return self.people[email]

    async def add_key(
        self,
        key_id,
        digest,
        name,
        email,
        schema,
        kind,
        expires_at,
        *,
        via=None,
        cap=ACTIVE_KEYS,
        per_hour=CREATIONS_PER_HOUR,
        idempotency=None,
    ):
        assert email in self.people, "keys.email references people"
        now, mine = datetime.now(UTC), "keys created via WorkPlane" if via else "keys"
        if idempotency is not None:
            earlier = self.idempotency.get((via, email, idempotency[0]))
            if earlier is not None and earlier["created_at"] > now - timedelta(hours=24):
                if earlier["body_sha256"] != idempotency[1]:
                    raise Refused(409, "That idempotency key was used for another request.")
                return earlier["key_id"]
        counted = [k for k in self.keys.values() if k["email"] == email and (k["via"] is None) == (via is None)]
        if sum(k["revoked_at"] is None and k["expires_at"] > now for k in counted) >= cap:
            raise Refused(429, f"You already hold {cap} active {mine}.")
        if sum(k["created_at"] > now - timedelta(hours=1) for k in counted) >= per_hour:
            raise Refused(429, f"You can create at most {per_hour} {mine} an hour.")
        self.keys[key_id] = {
            "id": key_id,
            "digest": digest,
            "name": name,
            "email": email,
            "schema": schema,
            "kind": kind,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
            "revoked_at": None,
            "via": via,
        }
        if idempotency is not None:
            self.idempotency[via, email, idempotency[0]] = {
                "body_sha256": idempotency[1], "key_id": key_id, "created_at": now
            }
        return key_id

    async def find_key(self, key_id):
        key = self.keys.get(key_id)
        return key and {**key, "role": self.roles.get(key["email"]), "last_seen": self.sign_ins.get(key["email"])}

    async def role(self, email):
        return self.roles.get(email)

    async def add_request(self, email):
        if email in self.roles:
            return False
        self.roles[email] = "requested"
        return True

    async def allowlist(self):
        rows = sorted(({"email": e, "role": r} for e, r in self.roles.items()), key=lambda r: r["email"])
        return sorted(rows, key=lambda r: r["role"], reverse=True)

    async def set_role(self, email, role):
        old = self.roles.pop(email, None)
        if role is not None:
            self.roles[email] = role
        return old

    async def signed_in(self, email, at):
        self.sign_ins[email] = max(at, self.sign_ins.get(email, at))

    def _reached(self, key, email, via_workplane):
        return key is not None and key["email"] == email and (not via_workplane or key["via"] is not None)

    async def list_keys(self, email, *, via_workplane=False):
        fields = ("id", "name", "created_at", "expires_at", "revoked_at", "via")
        return [{f: k[f] for f in fields} for k in self.keys.values() if self._reached(k, email, via_workplane)]

    async def renew_key(self, email, key_id, now, expires_at, *, via_workplane=False):
        key = self.keys.get(key_id)
        if not self._reached(key, email, via_workplane) or key["revoked_at"] is not None or key["expires_at"] <= now:
            return False
        key["expires_at"] = expires_at
        return True

    async def revoke_keys(self, email, now, key_id=None, *, via_workplane=False):
        hits = [
            k
            for k in self.keys.values()
            if self._reached(k, email, via_workplane) and k["revoked_at"] is None and key_id in (None, k["id"])
        ]
        for key in hits:
            key["revoked_at"] = now
        return len(hits)

    async def close(self):
        pass

    async def last_sign_in(self, email):
        return self.sign_ins.get(email)


class Migrations(ExtensionContext):
    """Records the schemas Hindsight was asked to create and migrate."""

    def __init__(self):
        self.schemas = []

    async def run_migration(self, schema):
        self.schemas.append(schema)

    def get_memory_engine(self):
        raise AssertionError("not used by these tests")


class Signer:
    def __init__(self, kid):
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self):
        return {**RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True), "kid": self.kid, "use": "sig"}


# Key generation is slow; two signers serve every test.
FIRST = Signer("first")
SECOND = Signer("second")


class Team:
    """Serves {url}/cdn-cgi/access/certs from `published` and counts the fetches."""

    def __init__(self):
        self.aud = AUD
        self.published = [FIRST]
        self.fetches = 0
        team = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/cdn-cgi/access/certs":
                    self.send_error(404)
                    return
                team.fetches += 1
                body = json.dumps({"keys": [s.jwk() for s in team.published]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def token(self, signer=FIRST, **overrides):
        """A JWT as Access issues it; an override of None drops that claim."""
        now = int(time.time())
        claims = {
            "iss": self.url,
            "aud": [AUD],
            "email": "Alice@Example.com",
            "sub": "0f6a1c2e-person",
            "iat": now,
            "exp": now + 300,
            "type": "app",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, signer.key, algorithm="RS256", headers={"kid": signer.kid})


@pytest.fixture
def team():
    t = Team()
    yield t
    t.server.shutdown()
    t.server.server_close()


def delegated_headers(team, email="alice@example.com", *, delegate=None, person=None):
    """A Delegated Request's headers: the Delegate's service-token JWT, as Access forwards it, and the
    person's own JWT for WorkPlane's application. Each dict overrides that credential's claims; an
    override of None drops the claim (as Team.token does)."""
    service = {"email": None, "sub": "", "common_name": DELEGATE_ID, "aud": [DELEGATION_AUD], **(delegate or {})}
    signed_in = {"email": email, "aud": [WORKPLANE_AUD], **(person or {})}
    return {
        "Host": DELEGATION_HOST,
        "Cf-Access-Jwt-Assertion": team.token(**service),
        "X-Delegated-Access-Jwt": team.token(**signed_in),
        "Content-Type": "application/json",
    }


def delegated_app(team, store=None, *, clock=None, **config):
    """The /ext router (key pages and Delegated Requests), mounted as upstream mounts it
    (api/http.py:5301-5316). Returns (client, extension, events); a config value of None drops it."""
    config = {
        "key_pepper": PEPPER,
        "access_team_domain": team.url,
        "access_aud": team.aud,
        "access_host": ACCESS_HOST,
        "delegation_host": DELEGATION_HOST,
        "delegation_aud": DELEGATION_AUD,
        "workplane_aud": WORKPLANE_AUD,
        "delegate_client_id": DELEGATE_ID,
        **config,
    }
    events = RecordedEvents()
    ext = AgentKeysTenantExtension(
        {k: v for k, v in config.items() if v is not None},
        store=store if store is not None else MemoryStore(),
        events=events,
        clock=clock,
    )
    ext.set_context(Migrations())
    app = FastAPI()
    app.include_router(AgentKeysHttpExtension({}).get_router(SimpleNamespace(tenant_extension=ext)), prefix="/ext")
    return TestClient(app), ext, events
