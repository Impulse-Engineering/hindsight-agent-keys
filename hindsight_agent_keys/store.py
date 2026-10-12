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
    schema text NOT NULL UNIQUE CHECK (schema <> ''),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS {SCHEMA}.keys (
    id text PRIMARY KEY,
    digest bytea NOT NULL,
    name text NOT NULL,
    email text NOT NULL REFERENCES {SCHEMA}.people (email),
    schema text NOT NULL CHECK (schema <> ''),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS keys_email_idx ON {SCHEMA}.keys (email);
CREATE TABLE IF NOT EXISTS {SCHEMA}.allowlist (
    email text PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('requested', 'member', 'admin'))
);
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
        return [r["schema"] for r in await pool.fetch(f"SELECT schema FROM {SCHEMA}.people ORDER BY created_at")]

    async def person_schema(self, email: str) -> str | None:
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT schema FROM {SCHEMA}.people WHERE email = $1", email)

    async def add_person(self, email: str, schema: str) -> str:
        """Give the person this schema unless they have one; returns the one they have."""
        pool = await self._get_pool()
        await pool.execute(
            f"INSERT INTO {SCHEMA}.people (email, schema) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
            email,
            schema,
        )
        return await self.person_schema(email)

    async def add_key(self, key_id: str, digest: bytes, name: str, email: str, schema: str) -> None:
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
                f"INSERT INTO {SCHEMA}.keys (id, digest, name, email, schema) VALUES ($1, $2, $3, $4, $5)",
                key_id,
                digest,
                name,
                email,
                schema,
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
        """The key's digest, email and schema, and its owner's role on the Key Allowlist."""
        pool = await self._get_pool()
        return await pool.fetchrow(
            f"SELECT k.digest, k.email, k.schema, a.role FROM {SCHEMA}.keys k"
            f" LEFT JOIN {SCHEMA}.allowlist a ON a.email = k.email WHERE k.id = $1",
            key_id,
        )
