"""Agent Keys and the people who hold them, kept in the extension's own schema."""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime

import asyncpg

from hindsight_agent_keys.events import SCHEMA, _asyncpg_dsn

# Per person. Counted in the database, so they hold across API processes.
CREATIONS_PER_HOUR = 5
ACTIVE_KEYS = 10
# Each Team is a migrated schema, and agents can create them.
TEAMS_PER_PERSON = 10

# Idempotent and outside upstream's Alembic history, like the event log.
# A key stores only an HMAC of the whole key, never the key.
DDL = f"""
CREATE SCHEMA IF NOT EXISTS {SCHEMA};
CREATE TABLE IF NOT EXISTS {SCHEMA}.people (
    email text PRIMARY KEY,
    -- NULL until the person's first personal key; a Team key needs no personal schema.
    schema text UNIQUE CHECK (schema <> ''),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS {SCHEMA}.teams (
    schema text PRIMARY KEY CHECK (schema <> ''),
    name text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS teams_name_idx ON {SCHEMA}.teams (lower(name));
CREATE INDEX IF NOT EXISTS teams_created_by_idx ON {SCHEMA}.teams (created_by);
-- People are members by email, whether or not they have signed in yet.
CREATE TABLE IF NOT EXISTS {SCHEMA}.members (
    team text NOT NULL REFERENCES {SCHEMA}.teams (schema),
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'member')),
    PRIMARY KEY (team, email)
);
CREATE INDEX IF NOT EXISTS members_email_idx ON {SCHEMA}.members (email);
-- Asked for over MCP; nobody joins until an owner or admin confirms on the Teams page.
CREATE TABLE IF NOT EXISTS {SCHEMA}.member_requests (
    team text NOT NULL REFERENCES {SCHEMA}.teams (schema),
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'member')),
    requested_by text NOT NULL,
    PRIMARY KEY (team, email)
);
CREATE TABLE IF NOT EXISTS {SCHEMA}.keys (
    id text PRIMARY KEY,
    digest bytea NOT NULL,
    name text NOT NULL,
    email text NOT NULL REFERENCES {SCHEMA}.people (email),
    schema text NOT NULL CHECK (schema <> ''),
    -- A Team key (Public Team included) works only while its holder is in the Team.
    kind text NOT NULL CHECK (kind IN ('personal', 'team')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS keys_email_idx ON {SCHEMA}.keys (email);
CREATE TABLE IF NOT EXISTS {SCHEMA}.sign_ins (
    email text PRIMARY KEY,
    last_seen timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS {SCHEMA}.allowlist (
    email text PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('requested', 'member', 'admin'))
);
-- Personal schemas no valid key has reached for 90 days, read by the admin page and by
-- scripts/purge-schema.sql. A key reaching the schema was valid at the latest until it
-- expired, was revoked, or 30 days after its owner's last sign-in (extension.SIGN_IN_WINDOW);
-- a schema with no key counts from when its owner was first recorded.
CREATE OR REPLACE VIEW {SCHEMA}.stale_schemas AS
SELECT p.schema, p.email, k.last_active
FROM {SCHEMA}.people p LEFT JOIN {SCHEMA}.sign_ins s ON s.email = p.email,
LATERAL (SELECT max(least(expires_at, revoked_at, s.last_seen + interval '30 days')) AS last_active
         FROM {SCHEMA}.keys WHERE schema = p.schema) k
WHERE p.schema IS NOT NULL AND coalesce(k.last_active, p.created_at) <= now() - interval '90 days';
"""


class Refused(Exception):
    """A request the caller may not make; `status` is the HTTP status to answer with."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status


class PostgresKeyStore:
    """Connects on first use: Hindsight lists tenants before extensions start."""

    def __init__(self, db_url: Callable[[], Awaitable[str]]):
        self._db_url = db_url
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            async with self._lock:
                if self._pool is None:
                    pool = await asyncpg.create_pool(_asyncpg_dsn(await self._db_url()), min_size=1, max_size=4)
                    try:
                        await pool.execute(DDL)
                    except BaseException:
                        await pool.close()
                        raise
                    self._pool = pool
        return self._pool

    async def close(self) -> None:
        pool, self._pool = self._pool, None
        if pool is not None:
            await pool.close()

    async def tenant_schemas(self) -> list[str]:
        pool = await self._get_pool()
        rows = await pool.fetch(
            f"SELECT schema FROM (SELECT schema, created_at FROM {SCHEMA}.people WHERE schema IS NOT NULL"
            f" UNION ALL SELECT schema, created_at FROM {SCHEMA}.teams) s ORDER BY created_at"
        )
        return [r["schema"] for r in rows]

    async def stale_schemas(self) -> list[asyncpg.Record]:
        pool = await self._get_pool()
        return await pool.fetch(
            f"SELECT schema, email, last_active FROM {SCHEMA}.stale_schemas ORDER BY last_active NULLS FIRST, email"
        )

    async def person_schema(self, email: str) -> str | None:
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT schema FROM {SCHEMA}.people WHERE email = $1", email)

    async def add_person(self, email: str, schema: str | None) -> str | None:
        """Record the person and give them this schema unless they have one; returns the one they have."""
        pool = await self._get_pool()
        return await pool.fetchval(
            f"INSERT INTO {SCHEMA}.people (email, schema) VALUES ($1, $2)"
            f" ON CONFLICT (email) DO UPDATE SET schema = coalesce({SCHEMA}.people.schema, excluded.schema)"
            " RETURNING schema",
            email,
            schema,
        )

    async def add_key(
        self, key_id: str, digest: bytes, name: str, email: str, schema: str, kind: str, expires_at: datetime
    ) -> None:
        """Store a key, or raise Refused(429) if its owner is at a limit."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # Locking the person makes concurrent creations count each other.
            await conn.execute(f"SELECT 1 FROM {SCHEMA}.people WHERE email = $1 FOR UPDATE", email)
            active, recent = await conn.fetchrow(
                "SELECT count(*) FILTER (WHERE revoked_at IS NULL AND expires_at > now()),"
                f" count(*) FILTER (WHERE created_at > now() - interval '1 hour') FROM {SCHEMA}.keys WHERE email = $1",
                email,
            )
            if active >= ACTIVE_KEYS:
                raise Refused(429, f"You already hold {ACTIVE_KEYS} active keys.")
            if recent >= CREATIONS_PER_HOUR:
                raise Refused(429, f"You can create at most {CREATIONS_PER_HOUR} keys an hour.")
            await conn.execute(
                f"INSERT INTO {SCHEMA}.keys (id, digest, name, email, schema, kind, expires_at)"
                " VALUES ($1, $2, $3, $4, $5, $6, $7)",
                key_id,
                digest,
                name,
                email,
                schema,
                kind,
                expires_at,
            )

    async def role(self, email: str) -> str | None:
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT role FROM {SCHEMA}.allowlist WHERE email = $1", email)

    async def allowlist(self) -> list[asyncpg.Record]:
        """Everyone with a role, pending requests first."""
        pool = await self._get_pool()
        return await pool.fetch(f"SELECT email, role FROM {SCHEMA}.allowlist ORDER BY role DESC, email")

    async def add_request(self, email: str) -> bool:
        """Record a request to join unless the person already has a role; True if recorded."""
        pool = await self._get_pool()
        return bool(
            await pool.fetchval(
                f"INSERT INTO {SCHEMA}.allowlist (email, role) VALUES ($1, 'requested')"
                " ON CONFLICT (email) DO NOTHING RETURNING true",
                email,
            )
        )

    async def set_role(self, email: str, role: str | None) -> str | None:
        """Set the person's role, or remove them with None; returns the role they had."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            old = await conn.fetchval(f"SELECT role FROM {SCHEMA}.allowlist WHERE email = $1 FOR UPDATE", email)
            if role is None:
                await conn.execute(f"DELETE FROM {SCHEMA}.allowlist WHERE email = $1", email)
            else:
                await conn.execute(
                    f"INSERT INTO {SCHEMA}.allowlist (email, role) VALUES ($1, $2)"
                    " ON CONFLICT (email) DO UPDATE SET role = excluded.role",
                    email,
                    role,
                )
        return old

    async def find_key(self, key_id: str) -> asyncpg.Record | None:
        """The key's digest, email, schema, kind, expiry and revocation, its owner's role on
        the Key Allowlist and its owner's last sign-in, in one indexed lookup."""
        pool = await self._get_pool()
        return await pool.fetchrow(
            f"SELECT k.digest, k.email, k.schema, k.kind, k.expires_at, k.revoked_at, a.role, s.last_seen"
            f" FROM {SCHEMA}.keys k LEFT JOIN {SCHEMA}.allowlist a ON a.email = k.email"
            f" LEFT JOIN {SCHEMA}.sign_ins s ON s.email = k.email WHERE k.id = $1",
            key_id,
        )

    async def check_team_limit(self, email: str, conn: asyncpg.Connection | None = None) -> None:
        """Raise Refused(429) if the person has created as many Teams as they may."""
        db = conn or await self._get_pool()
        if await db.fetchval(f"SELECT count(*) FROM {SCHEMA}.teams WHERE created_by = $1", email) >= TEAMS_PER_PERSON:
            raise Refused(429, f"You can create at most {TEAMS_PER_PERSON} Teams.")

    async def create_team(self, schema: str, name: str, owner: str) -> None:
        """Store a Team with its first owner, or raise Refused(409) if the name is taken
        or Refused(429) if the owner is at the limit."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # Serialises one person's creations, so concurrent ones count each other.
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"{SCHEMA}.teams:{owner}")
            await self.check_team_limit(owner, conn)
            try:
                await conn.execute(
                    f"INSERT INTO {SCHEMA}.teams (schema, name, created_by) VALUES ($1, $2, $3)", schema, name, owner
                )
            except asyncpg.UniqueViolationError:
                raise Refused(409, "A Team with that name exists.") from None
            await conn.execute(
                f"INSERT INTO {SCHEMA}.members (team, email, role) VALUES ($1, $2, 'owner')", schema, owner
            )

    async def team_schema(self, name: str) -> str | None:
        """The schema of the Team with this name, in any case."""
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT schema FROM {SCHEMA}.teams WHERE lower(name) = lower($1)", name)

    async def teams(self, email: str, everyone: bool = False) -> list[asyncpg.Record]:
        """The person's Teams (all Teams if `everyone`) with the person's role, None if not a member."""
        pool = await self._get_pool()
        return await pool.fetch(
            f"SELECT t.schema, t.name, m.role FROM {SCHEMA}.teams t"
            f" LEFT JOIN {SCHEMA}.members m ON m.team = t.schema AND m.email = $1"
            f" WHERE $2 OR m.role IS NOT NULL ORDER BY lower(t.name)",
            email,
            everyone,
        )

    async def members(self, team: str) -> list[asyncpg.Record]:
        pool = await self._get_pool()
        return await pool.fetch(f"SELECT email, role FROM {SCHEMA}.members WHERE team = $1 ORDER BY email", team)

    async def team_role(self, team: str, email: str) -> str | None:
        """The person's role in the Team, "owner" or "member", or None if they are not in it."""
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT role FROM {SCHEMA}.members WHERE team = $1 AND email = $2", team, email)

    async def set_member(self, team: str, email: str, role: str) -> None:
        """Add the person to the Team or change their role."""
        await self._change_members(
            team,
            f"INSERT INTO {SCHEMA}.members (team, email, role) VALUES ($1, $2, $3)"
            " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role",
            email,
            role,
        )

    async def remove_member(self, team: str, email: str) -> None:
        await self._change_members(team, f"DELETE FROM {SCHEMA}.members WHERE team = $1 AND email = $2", email)

    async def request_member(self, team: str, email: str, role: str, by: str) -> None:
        """Ask for the person to get this role in the Team; replaces an earlier request for them."""
        await self._change_members(
            team,
            f"INSERT INTO {SCHEMA}.member_requests (team, email, role, requested_by) VALUES ($1, $2, $3, $4)"
            " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role, requested_by = excluded.requested_by",
            email,
            role,
            by,
        )

    async def confirm_member(self, team: str, email: str, role: str) -> str | None:
        """Give the person `role` if a pending request asks for exactly that. Returns the role the
        request asks for (nothing changes if it is another), or None if there is no request."""
        return await self._change_members(
            team,
            f"WITH asked AS (SELECT role FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2),"
            f" taken AS (DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 AND role = $3 RETURNING role),"
            f" granted AS (INSERT INTO {SCHEMA}.members (team, email, role) SELECT $1, $2, role FROM taken"
            " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role)"
            " SELECT role FROM asked",
            email,
            role,
        )

    async def decline_member(self, team: str, email: str) -> str | None:
        """Drop a pending request; returns the role it asked for, or None if there was no request."""
        return await self._change_members(
            team, f"DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 RETURNING role", email
        )

    async def member_requests(self, team: str) -> list[asyncpg.Record]:
        pool = await self._get_pool()
        return await pool.fetch(
            f"SELECT email, role, requested_by FROM {SCHEMA}.member_requests WHERE team = $1 ORDER BY email", team
        )

    async def _change_members(self, team: str, sql: str, *args: str) -> str | None:
        """Run one change to the Team's members and return its first value; Refused(404) if there
        is no such Team, Refused(409) if the change would leave it without an owner."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # Locking the Team makes concurrent changes see each other's owners.
            if await conn.fetchval(f"SELECT 1 FROM {SCHEMA}.teams WHERE schema = $1 FOR UPDATE", team) is None:
                raise Refused(404, "There is no such Team.")
            value = await conn.fetchval(sql, team, *args)
            if not await conn.fetchval(f"SELECT count(*) FROM {SCHEMA}.members WHERE team = $1 AND role = 'owner'", team):
                raise Refused(409, "A Team must keep at least one owner.")
        return value

    async def signed_in(self, email: str, at: datetime) -> None:
        """Record a sign-in through Access; an older one never replaces a newer one."""
        pool = await self._get_pool()
        await pool.execute(
            f"INSERT INTO {SCHEMA}.sign_ins (email, last_seen) VALUES ($1, $2) ON CONFLICT (email)"
            f" DO UPDATE SET last_seen = greatest({SCHEMA}.sign_ins.last_seen, EXCLUDED.last_seen)",
            email,
            at,
        )

    async def list_keys(self, email: str) -> list[dict]:
        pool = await self._get_pool()
        rows = await pool.fetch(
            f"SELECT id, name, created_at, expires_at, revoked_at FROM {SCHEMA}.keys"
            " WHERE email = $1 ORDER BY created_at, id",
            email,
        )
        return [dict(r) for r in rows]

    async def renew_key(self, email: str, key_id: str, now: datetime, expires_at: datetime) -> bool:
        """Move the expiry of the person's key unless it is revoked or already expired."""
        pool = await self._get_pool()
        renewed = await pool.fetchval(
            f"UPDATE {SCHEMA}.keys SET expires_at = $4"
            " WHERE id = $1 AND email = $2 AND revoked_at IS NULL AND expires_at > $3 RETURNING id",
            key_id,
            email,
            now,
            expires_at,
        )
        return renewed is not None

    async def revoke_keys(self, email: str, now: datetime, key_id: str | None = None) -> int:
        """Revoke one of the person's keys, or with no key ID all of them; returns how many."""
        pool = await self._get_pool()
        rows = await pool.fetch(
            f"UPDATE {SCHEMA}.keys SET revoked_at = $2"
            " WHERE email = $1 AND revoked_at IS NULL AND ($3::text IS NULL OR id = $3) RETURNING id",
            email,
            now,
            key_id,
        )
        return len(rows)
