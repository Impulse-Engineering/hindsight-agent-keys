"""Stand-ins for what the extension talks to: its database, Hindsight's migrations,
the event log, and a Cloudflare Access team that serves signing keys and signs JWTs."""

import json
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from hindsight_api.extensions.context import ExtensionContext
from jwt.algorithms import RSAAlgorithm

AUD = "aud-tag-0123456789"


class RecordedEvents:
    def __init__(self, fail=False):
        self.rows = []
        self.fail = fail

    async def start(self, db_url):
        pass

    async def stop(self):
        pass

    async def record(self, kind, key_id, client_ip, email=None, actor=None):
        if self.fail:
            raise RuntimeError("event store unavailable")
        self.rows.append({"kind": kind, "key_id": key_id, "client_ip": client_ip, "email": email, "actor": actor})


class MemoryStore:
    """In-memory stand-in for PostgresKeyStore, with the same operations."""

    def __init__(self):
        self.people = {}
        self.keys = {}
        self.sign_ins = {}
        self.roles = {}
        self.fail = False

    async def tenant_schemas(self):
        if self.fail:
            raise OSError("database unavailable")
        return list(self.people.values())

    async def person_schema(self, email):
        return self.people.get(email)

    async def add_person(self, email, schema):
        return self.people.setdefault(email, schema)

    async def add_key(self, key_id, digest, name, email, schema, expires_at):
        self.keys[key_id] = {
            "id": key_id,
            "digest": digest,
            "name": name,
            "email": email,
            "schema": schema,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
            "revoked_at": None,
        }

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

    async def list_keys(self, email):
        fields = ("id", "name", "created_at", "expires_at", "revoked_at")
        return [{f: k[f] for f in fields} for k in self.keys.values() if k["email"] == email]

    async def renew_key(self, email, key_id, now, expires_at):
        key = self.keys.get(key_id)
        if key is None or key["email"] != email or key["revoked_at"] is not None or key["expires_at"] <= now:
            return False
        key["expires_at"] = expires_at
        return True

    async def revoke_keys(self, email, now, key_id=None):
        hits = [k for k in self.keys.values() if k["email"] == email and k["revoked_at"] is None and key_id in (None, k["id"])]
        for key in hits:
            key["revoked_at"] = now
        return len(hits)

    async def close(self):
        pass


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
