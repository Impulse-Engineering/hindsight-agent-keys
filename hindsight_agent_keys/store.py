"""Agent Keys and the people who hold them, kept in the extension's own schema."""

import asyncio
from collections.abc import Awaitable, Callable

import asyncpg

from hindsight_agent_keys.events import SCHEMA, _asyncpg_dsn

# Per person. Counted in the database, so they hold across API processes.
CREATIONS_PER_HOUR = 5
ACTIVE_KEYS = 10

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
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS teams_name_idx ON {SCHEMA}.teams (lower(name));
-- People are members by email, whether or not they have signed in yet.
CREATE TABLE IF NOT EXISTS {SCHEMA}.members (
    team text NOT NULL REFERENCES {SCHEMA}.teams (schema),
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'member')),
    PRIMARY KEY (team, email)
);
CREATE INDEX IF NOT EXISTS members_email_idx ON {SCHEMA}.members (email);
CREATE TABLE IF NOT EXISTS {SCHEMA}.keys (
    id text PRIMARY KEY,
    digest bytea NOT NULL,
    name text NOT NULL,
    email text NOT NULL REFERENCES {SCHEMA}.people (email),
    schema text NOT NULL CHECK (schema <> ''),
    -- A Team key (Public Team included) works only while its holder is in the Team.
    kind text NOT NULL CHECK (kind IN ('personal', 'team')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS keys_email_idx ON {SCHEMA}.keys (email);
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

    async def add_key(self, key_id: str, digest: bytes, name: str, email: str, schema: str, kind: str) -> None:
        """Store a key, or raise Refused(429) if its owner is at a limit."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # Locking the person makes concurrent creations count each other.
            await conn.execute(f"SELECT 1 FROM {SCHEMA}.people WHERE email = $1 FOR UPDATE", email)
            active, recent = await conn.fetchrow(
                f"SELECT count(*), count(*) FILTER (WHERE created_at > now() - interval '1 hour')"
                f" FROM {SCHEMA}.keys WHERE email = $1",
                email,
            )
            if active >= ACTIVE_KEYS:
                raise Refused(429, f"You already hold {ACTIVE_KEYS} active keys.")
            if recent >= CREATIONS_PER_HOUR:
                raise Refused(429, f"You can create at most {CREATIONS_PER_HOUR} keys an hour.")
            await conn.execute(
                f"INSERT INTO {SCHEMA}.keys (id, digest, name, email, schema, kind) VALUES ($1, $2, $3, $4, $5, $6)",
                key_id,
                digest,
                name,
                email,
                schema,
                kind,
            )

    async def find_key(self, key_id: str) -> asyncpg.Record | None:
        """The key's digest, email, schema and kind."""
        pool = await self._get_pool()
        return await pool.fetchrow(f"SELECT digest, email, schema, kind FROM {SCHEMA}.keys WHERE id = $1", key_id)

    async def create_team(self, schema: str, name: str, owner: str) -> None:
        """Store a Team with its first owner, or raise Refused(409) if the name is taken."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            try:
                await conn.execute(f"INSERT INTO {SCHEMA}.teams (schema, name) VALUES ($1, $2)", schema, name)
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

    async def role(self, team: str, email: str) -> str | None:
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

    async def _change_members(self, team: str, sql: str, *args: str) -> None:
        """Run one change to the Team's members; Refused(404) if there is no such Team,
        Refused(409) if the change would leave it without an owner."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # Locking the Team makes concurrent changes see each other's owners.
            if await conn.fetchval(f"SELECT 1 FROM {SCHEMA}.teams WHERE schema = $1 FOR UPDATE", team) is None:
                raise Refused(404, "There is no such Team.")
            await conn.execute(sql, team, *args)
            if not await conn.fetchval(f"SELECT count(*) FROM {SCHEMA}.members WHERE team = $1 AND role = 'owner'", team):
                raise Refused(409, "A Team must keep at least one owner.")
