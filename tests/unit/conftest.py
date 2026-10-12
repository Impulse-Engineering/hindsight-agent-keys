"""Stand-ins for what the extension talks to: its database, Hindsight's migrations,
the event log, and a Cloudflare Access team that serves signing keys and signs JWTs."""

import json
import threading
import time
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

    async def record(self, kind, key_id, client_ip, email=None):
        if self.fail:
            raise RuntimeError("event store unavailable")
        self.rows.append({"kind": kind, "key_id": key_id, "client_ip": client_ip, "email": email})


class MemoryStore:
    """In-memory stand-in for PostgresKeyStore, with the same operations."""

    def __init__(self):
        self.people = {}
        self.keys = {}
        self.fail = False

    async def tenant_schemas(self):
        if self.fail:
            raise OSError("database unavailable")
        return list(self.people.values())

    async def person_schema(self, email):
        return self.people.get(email)

    async def add_person(self, email, schema):
        return self.people.setdefault(email, schema)

    async def add_key(self, key_id, digest, name, email, schema):
        self.keys[key_id] = {"digest": digest, "name": name, "email": email, "schema": schema}

    async def find_key(self, key_id):
        return self.keys.get(key_id)

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
