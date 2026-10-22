"""Agent Keys and the people who hold them, kept in the extension's own schema."""

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from datetime import date, datetime

import asyncpg

from hindsight_agent_keys.events import SCHEMA, _asyncpg_dsn

# Per person. Counted in the database, so they hold across API processes.
CREATIONS_PER_HOUR = 5
ACTIVE_KEYS = 10
# Each Team is a migrated schema, and agents can create them.
TEAMS_PER_PERSON = 10
# A creation waits this many seconds, polling this often, for the Team name another creation holds.
TEAM_NAME_LOCK_WAIT = 60.0
TEAM_NAME_LOCK_POLL = 0.1
# A change that ends someone's eligibility for a notice, and an opt-out, wait this many seconds, polling this often, for a
# message to the person in flight. A send is cut off after notices.SEND_DEADLINE (10), so this is three times that: a
# realistic change never gets 503 behind a send, and 503 means the lock has been held abnormally long.
NOTICE_LOCK_WAIT = 30.0
NOTICE_LOCK_POLL = 0.05


def _notice_lock_key(email: str) -> str:
    """The key of the lock a message to the person is sent under, and every change that can end their eligibility for
    a notice is made under (`notice_lock`, `_lock_notices`): one key, so the two exclude each other."""
    return f"{SCHEMA}.notice_send:{email}"


# Whether the person ($1) is on the Key Allowlist, given the bootstrap admins ($2), who are admins whatever the allowlist
# says. 'member' and 'admin' are extension.LISTED, the roles that may create keys.
_LISTED = f"($1 = ANY($2::text[]) OR EXISTS (SELECT 1 FROM {SCHEMA}.allowlist a WHERE a.email = $1 AND a.role IN ('member', 'admin')))"
# Whether a queued notice (t.kind, t.team) is still the person's to read: an owner of the Team on the Key Allowlist, an
# admin, a key's holder still on the Key Allowlist, or the asker of a decided request. Any other kind is not.
NOTICE_ELIGIBLE = (
    "CASE t.kind"
    f" WHEN 'owner' THEN EXISTS (SELECT 1 FROM {SCHEMA}.members m WHERE m.team = t.team AND m.email = $1 AND m.role = 'owner')"
    f"   AND {_LISTED}"
    f" WHEN 'admin' THEN $1 = ANY($2::text[]) OR EXISTS (SELECT 1 FROM {SCHEMA}.allowlist a WHERE a.email = $1 AND a.role = 'admin')"
    f" WHEN 'holder' THEN {_LISTED}"
    " WHEN 'asker' THEN true"
    " ELSE false END"
)
# Whether the request `r` (a member_requests row) still waits for an answer: its person is not in the Team already at the
# role it asks for, or as an owner. Nothing files one that does not, and joining an Open Team settles one for a member's
# place, but a request filed before those rules may be left. The Teams page, pending_reviews and the reminders all read
# requests through this, and a request for someone else is filed only where it holds.
_WAITING = (
    f"NOT EXISTS (SELECT 1 FROM {SCHEMA}.members w WHERE w.team = r.team AND w.email = r.email AND w.role IN ('owner', r.role))"
)

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
-- Asked for by an owner or admin over MCP, or by the person themselves (a Join Request, requested_by = email);
-- nobody joins until an owner on the Key Allowlist, or an admin, confirms on the Teams page or by Delegated Request.
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
-- #999: a key created via WorkPlane names the Delegate (its service-token client ID) that created it; NULL on /ext.
ALTER TABLE {SCHEMA}.keys ADD COLUMN IF NOT EXISTS via text;
-- #999: the Delegate's idempotency key for each creation, kept 24 hours, so a retry returns the key it created.
CREATE TABLE IF NOT EXISTS {SCHEMA}.idempotency (
    delegate text NOT NULL,
    email text NOT NULL,
    key text NOT NULL,
    body_sha256 bytea NOT NULL,
    key_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (delegate, email, key)
);
-- #1002: an Open Team, which anyone on the Key Allowlist joins without asking; only admins open or close one.
ALTER TABLE {SCHEMA}.teams ADD COLUMN IF NOT EXISTS open boolean NOT NULL DEFAULT false;
-- #1004: when the request was filed, so an admin hears of Join Requests left waiting. Asking again keeps it.
ALTER TABLE {SCHEMA}.member_requests ADD COLUMN IF NOT EXISTS requested_at timestamptz NOT NULL DEFAULT now();
-- #1005: Webex notices. A notice waits here, one line for one person, until the person may be messaged again.
-- `kind` is who the recipient is to the notice, checked again when it is taken to be sent: an 'owner' of `team`
-- (on the Key Allowlist), an 'admin', or the 'asker' of a request that was decided.
CREATE TABLE IF NOT EXISTS {SCHEMA}.notice_queue (
    id bigserial PRIMARY KEY,
    recipient text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('owner', 'admin', 'asker')),
    team text,
    line text NOT NULL,
    path text NOT NULL
);
CREATE INDEX IF NOT EXISTS notice_queue_recipient_idx ON {SCHEMA}.notice_queue (recipient, id);
-- #1005: the send log, one row per message. 'sending' is written when the notices are claimed, before the call to Webex,
-- and is still there if the process stopped before or just after it, or the outcome could not be written; 'skipped' is
-- a message not sent because the person turned notices off, or was no longer eligible, after the claim. shortcut: never pruned, at most 96 rows a day for each
-- person; delete old rows when the table is large enough to matter.
CREATE TABLE IF NOT EXISTS {SCHEMA}.notice_log (
    id bigserial PRIMARY KEY,
    recipient text NOT NULL,
    at timestamptz NOT NULL,
    items integer NOT NULL,
    status text NOT NULL CHECK (status IN ('sending', 'sent', 'failed', 'skipped')),
    detail text
);
CREATE INDEX IF NOT EXISTS notice_log_recipient_idx ON {SCHEMA}.notice_log (recipient, at);
-- #1005: people who turned Webex notices off.
CREATE TABLE IF NOT EXISTS {SCHEMA}.notice_optouts (
    email text PRIMARY KEY
);
-- #1006: when a 'requested' row was filed, so admins are reminded of one left waiting. Rows there before count from then.
ALTER TABLE {SCHEMA}.allowlist ADD COLUMN IF NOT EXISTS requested_at timestamptz NOT NULL DEFAULT now();
-- #1006: each day whose reminders were queued, written in the transaction that queues them, so a day runs once.
CREATE TABLE IF NOT EXISTS {SCHEMA}.reminder_runs (
    day date PRIMARY KEY,
    at timestamptz NOT NULL
);
-- #1006: a notice may also be for the 'holder' of keys running out (on the Key Allowlist). Replaced by the name Postgres
-- gave #1005's column CHECK, so a table #1005 made takes it too.
ALTER TABLE {SCHEMA}.notice_queue DROP CONSTRAINT IF EXISTS notice_queue_kind_check,
    ADD CONSTRAINT notice_queue_kind_check CHECK (kind IN ('owner', 'admin', 'asker', 'holder'));
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
        self,
        key_id: str,
        digest: bytes,
        name: str,
        email: str,
        schema: str,
        kind: str,
        expires_at: datetime,
        *,
        via: str | None = None,
        cap: int = ACTIVE_KEYS,
        per_hour: int = CREATIONS_PER_HOUR,
        idempotency: tuple[str, bytes] | None = None,
    ) -> str:
        """Store a key and return its ID, or raise Refused(429) if its owner is at a limit. Keys created
        via WorkPlane (`via`, the Delegate's client ID) and the person's own are counted apart, each against
        its own limits. With `idempotency`, the Delegate's (key, body digest): a repeat within 24 hours stores
        nothing and returns the ID the first one stored, and the same key with another body is Refused(409)."""
        pool = await self._get_pool()
        mine = "keys created via WorkPlane" if via else "keys"
        async with pool.acquire() as conn, conn.transaction():
            # Locking the person makes concurrent creations, and retries, count each other.
            await conn.execute(f"SELECT 1 FROM {SCHEMA}.people WHERE email = $1 FOR UPDATE", email)
            if idempotency is not None:
                await conn.execute(
                    f"DELETE FROM {SCHEMA}.idempotency WHERE email = $1 AND created_at <= now() - interval '24 hours'", email
                )
                earlier = await conn.fetchrow(
                    f"SELECT body_sha256, key_id FROM {SCHEMA}.idempotency WHERE delegate = $1 AND email = $2 AND key = $3",
                    via,
                    email,
                    idempotency[0],
                )
                if earlier is not None:
                    if earlier["body_sha256"] != idempotency[1]:
                        raise Refused(409, "That idempotency key was used for another request.")
                    return earlier["key_id"]
            active, recent = await conn.fetchrow(
                "SELECT count(*) FILTER (WHERE revoked_at IS NULL AND expires_at > now()),"
                f" count(*) FILTER (WHERE created_at > now() - interval '1 hour') FROM {SCHEMA}.keys"
                " WHERE email = $1 AND (via IS NULL) = ($2::text IS NULL)",
                email,
                via,
            )
            if active >= cap:
                raise Refused(429, f"You already hold {cap} active {mine}.")
            if recent >= per_hour:
                raise Refused(429, f"You can create at most {per_hour} {mine} an hour.")
            await conn.execute(
                f"INSERT INTO {SCHEMA}.keys (id, digest, name, email, schema, kind, expires_at, via)"
                " VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                key_id,
                digest,
                name,
                email,
                schema,
                kind,
                expires_at,
                via,
            )
            if idempotency is not None:
                await conn.execute(
                    f"INSERT INTO {SCHEMA}.idempotency (delegate, email, key, body_sha256, key_id) VALUES ($1, $2, $3, $4, $5)",
                    via,
                    email,
                    *idempotency,
                    key_id,
                )
        return key_id

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
            await self._lock_notices(conn, email)
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

    async def set_member(self, team: str, email: str, role: str) -> tuple[str | None, str | None]:
        """Add the person to the Team or change their role; returns (the role they had, None if they were not in it,
        and who asked for them, None if no request of theirs was open)."""
        row = await self._change_members(
            team,
            f"WITH had AS (SELECT role FROM {SCHEMA}.members WHERE team = $1 AND email = $2),"
            f" put AS (INSERT INTO {SCHEMA}.members (team, email, role) VALUES ($1, $2, $3)"
            " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role),"
            # A direct add settles the person's open request, so confirming it later cannot change the role they were given.
            f" settled AS (DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 RETURNING requested_by)"
            " SELECT (SELECT role FROM had) AS had, (SELECT requested_by FROM settled) AS asked_by",
            email,
            role,
            who=email,
            row=True,
        )
        return row["had"], row["asked_by"]

    async def remove_member(self, team: str, email: str) -> str | None:
        """Take the person out of the Team; returns the role they had, None if they were not in it."""
        return await self._change_members(
            team, f"DELETE FROM {SCHEMA}.members WHERE team = $1 AND email = $2 RETURNING role", email, who=email
        )

    async def request_member(self, team: str, email: str, role: str, by: str) -> bool:
        """Ask for the person to get this role in the Team, replacing an earlier request for them; True if filed. Nothing
        is filed for someone in the Team already at that role, or as an owner: it would wait for nothing (`_WAITING`)."""
        return bool(
            await self._change_members(
                team,
                f"INSERT INTO {SCHEMA}.member_requests (team, email, role, requested_by)"
                f" SELECT r.team, r.email, r.role, $4::text FROM (SELECT $1::text AS team, $2::text AS email, $3::text AS role) r"
                f" WHERE {_WAITING}"
                " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role, requested_by = excluded.requested_by RETURNING true",
                email,
                role,
                by,
                who=None,
            )
        )

    async def add_join_request(self, team: str, email: str, role: str) -> bool:
        """Record the person's own request for this role unless they are in the Team or already asked
        (their open request, whoever filed it, stays as it is); True if recorded. A Team that does not exist
        stores nothing and is no error, so the caller cannot tell it from a Team that does."""
        try:
            return bool(
                await self._change_members(
                    team,
                    f"INSERT INTO {SCHEMA}.member_requests (team, email, role, requested_by)"
                    " SELECT $1::text, $2::text, $3::text, $2::text"
                    f" WHERE NOT EXISTS (SELECT 1 FROM {SCHEMA}.members WHERE team = $1 AND email = $2)"
                    " ON CONFLICT (team, email) DO NOTHING RETURNING true",
                    email,
                    role,
                    who=None,
                )
            )
        except Refused as refusal:
            if refusal.status != 404:
                raise
            return False

    async def confirm_member(self, team: str, email: str, role: str) -> tuple[str, str] | None:
        """Give the person `role` if a pending request asks for exactly that. Returns (the role the request asks for,
        who asked), nothing changing if it asks for another role, or None if there is no request."""
        row = await self._change_members(
            team,
            f"WITH asked AS (SELECT role, requested_by FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2),"
            f" taken AS (DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 AND role = $3 RETURNING role),"
            f" granted AS (INSERT INTO {SCHEMA}.members (team, email, role) SELECT $1, $2, role FROM taken"
            " ON CONFLICT (team, email) DO UPDATE SET role = excluded.role)"
            " SELECT role, requested_by FROM asked",
            email,
            role,
            who=email,
            row=True,
        )
        return None if row is None else (row["role"], row["requested_by"])

    async def decline_member(self, team: str, email: str) -> tuple[str, str] | None:
        """Drop a pending request; returns (the role it asked for, who asked), or None if there was no request."""
        row = await self._change_members(
            team,
            f"DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 RETURNING role, requested_by",
            email,
            who=None,
            row=True,
        )
        return None if row is None else (row["role"], row["requested_by"])

    async def member_requests(self, team: str) -> list[asyncpg.Record]:
        """The Team's requests that wait for an answer (`_WAITING`)."""
        pool = await self._get_pool()
        return await pool.fetch(
            f"SELECT r.email, r.role, r.requested_by FROM {SCHEMA}.member_requests r WHERE r.team = $1 AND {_WAITING}"
            " ORDER BY r.email",
            team,
        )

    async def _change_members(self, team: str, sql: str, *args: str, who: str | None, row: bool = False):
        """Run one change to the Team's members and return its first value (with `row`, its first row, None if it
        returned none); Refused(404) if there is no such Team, Refused(409) if the change would leave it without an owner.
        `who` is the person whose place in the Team the change may end (a removal, or a role change), whose notice lock it
        takes first (`_lock_notices`); None for a change that only files or drops a request and cannot."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            if who is not None:
                await self._lock_notices(conn, who)
            # Locking the Team makes concurrent changes see each other's owners.
            if await conn.fetchval(f"SELECT 1 FROM {SCHEMA}.teams WHERE schema = $1 FOR UPDATE", team) is None:
                raise Refused(404, "There is no such Team.")
            value = await (conn.fetchrow if row else conn.fetchval)(sql, team, *args)
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

    # With `via_workplane`, the next three reach only keys created via WorkPlane.

    async def list_keys(self, email: str, *, via_workplane: bool = False) -> list[dict]:
        pool = await self._get_pool()
        rows = await pool.fetch(
            f"SELECT id, name, created_at, expires_at, revoked_at, via FROM {SCHEMA}.keys"
            " WHERE email = $1 AND (NOT $2::boolean OR via IS NOT NULL) ORDER BY created_at, id",
            email,
            via_workplane,
        )
        return [dict(r) for r in rows]

    async def renew_key(
        self, email: str, key_id: str, now: datetime, expires_at: datetime, *, via_workplane: bool = False
    ) -> bool:
        """Move the expiry of the person's key unless it is revoked or already expired."""
        pool = await self._get_pool()
        renewed = await pool.fetchval(
            f"UPDATE {SCHEMA}.keys SET expires_at = $4"
            " WHERE id = $1 AND email = $2 AND revoked_at IS NULL AND expires_at > $3 AND (NOT $5::boolean OR via IS NOT NULL)"
            " RETURNING id",
            key_id,
            email,
            now,
            expires_at,
            via_workplane,
        )
        return renewed is not None

    async def revoke_keys(
        self, email: str, now: datetime, key_id: str | None = None, *, via_workplane: bool = False
    ) -> int:
        """Revoke one of the person's keys, or with no key ID all of them; returns how many. Revoking all of them also drops
        the warnings queued for the person (`_drop_key_warnings`)."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            if key_id is None:
                await self._drop_key_warnings(conn, [email])
            rows = await conn.fetch(
                f"UPDATE {SCHEMA}.keys SET revoked_at = $2"
                " WHERE email = $1 AND revoked_at IS NULL AND ($3::text IS NULL OR id = $3) AND (NOT $4::boolean OR via IS NOT NULL)"
                " RETURNING id",
                email,
                now,
                key_id,
                via_workplane,
            )
        return len(rows)

    async def last_sign_in(self, email: str) -> datetime | None:
        """When the person last signed in through Access, as `signed_in` recorded it."""
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT last_seen FROM {SCHEMA}.sign_ins WHERE email = $1", email)

    async def team_name(self, team: str) -> str | None:
        """The Team's name as it was created, None if there is no such Team."""
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT name FROM {SCHEMA}.teams WHERE schema = $1", team)

    async def team_creator(self, team: str) -> str | None:
        """The email of the person who created the Team, None if there is no such Team."""
        pool = await self._get_pool()
        return await pool.fetchval(f"SELECT created_by FROM {SCHEMA}.teams WHERE schema = $1", team)

    @contextlib.asynccontextmanager
    async def team_name_lock(self, name: str):
        """Hold a lock on the Team name, in any case, across API processes. It takes a connection of its own,
        not one of the pool's, so waiting for it, or a migration under it, never starves the key lookups.
        A waiter gives up after TEAM_NAME_LOCK_WAIT seconds with Refused(503) and closes its connection, so each
        waiter behind a stuck holder holds a connection for at most that long; how many wait is not capped. A holder
        that stops, mid-migration say, frees the lock as its connection closes."""
        conn = await asyncpg.connect(_asyncpg_dsn(await self._db_url()))
        try:
            # Postgres's own lower(), the one the unique index on the name uses. A waiter polls: a statement left
            # waiting for the lock holds a transaction open, and the migration under the lock creates indexes
            # concurrently, which waits for every open transaction to finish, so a blocked waiter would deadlock it.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + TEAM_NAME_LOCK_WAIT
            while not await conn.fetchval(
                "SELECT pg_try_advisory_lock(hashtext(lower($1)))", f"{SCHEMA}.team_name:{name.strip()}"
            ):
                if loop.time() >= deadline:
                    raise Refused(503, "Another request is still creating a Team with that name; try again in a minute.")
                await asyncio.sleep(TEAM_NAME_LOCK_POLL)
            yield
        finally:
            # Closing the connection releases the lock, on a failure too.
            await conn.close()

    async def revoke_workplane_keys(self, now: datetime) -> int:
        """Revoke every unrevoked key created via WorkPlane, whoever holds it, and drop the warnings queued for its holders
        (`_drop_key_warnings`); returns how many."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            holders = await conn.fetch(f"SELECT DISTINCT email FROM {SCHEMA}.keys WHERE via IS NOT NULL AND revoked_at IS NULL")
            await self._drop_key_warnings(conn, [r["email"] for r in holders])
            rows = await conn.fetch(
                f"UPDATE {SCHEMA}.keys SET revoked_at = $1 WHERE via IS NOT NULL AND revoked_at IS NULL RETURNING id", now
            )
        return len(rows)

    # --- #1002 ---

    async def set_open(self, team: str, opened: bool) -> bool:
        """Open or close the Team; returns whether it was open. Refused(404) if there is no such Team."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # The Team's lock, which a join takes too, so a join that waits for a closing finds the Team closed.
            was = await conn.fetchval(f"SELECT open FROM {SCHEMA}.teams WHERE schema = $1 FOR UPDATE", team)
            if was is None:
                raise Refused(404, "There is no such Team.")
            await conn.execute(f"UPDATE {SCHEMA}.teams SET open = $2 WHERE schema = $1", team, opened)
        return was

    async def join_open_team(self, team: str, email: str) -> tuple[str, bool] | None:
        """Make the person a member of the Team if it is open: (their role now, whether they joined just now); someone in it
        already keeps their role. Their request for a member's place, which then waits for nothing, is settled; one for an
        owner's place stays for an owner to answer. None, changing nothing, if the Team is not open or does not exist."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            # The Team's lock, as every member change takes, so a join waits for a concurrent closing or approval.
            if not await conn.fetchval(f"SELECT open FROM {SCHEMA}.teams WHERE schema = $1 FOR UPDATE", team):
                return None
            joined = await conn.fetchval(
                f"INSERT INTO {SCHEMA}.members (team, email, role) VALUES ($1, $2, 'member')"
                " ON CONFLICT (team, email) DO NOTHING RETURNING true",
                team,
                email,
            )
            await conn.execute(
                f"DELETE FROM {SCHEMA}.member_requests WHERE team = $1 AND email = $2 AND role = 'member'", team, email
            )
            role = await conn.fetchval(f"SELECT role FROM {SCHEMA}.members WHERE team = $1 AND email = $2", team, email)
        return role, bool(joined)

    async def open_teams(self, email: str) -> list[asyncpg.Record]:
        """Every Open Team with the person's role in it, None if not a member."""
        pool = await self._get_pool()
        return await pool.fetch(
            f"SELECT t.schema, t.name, m.role FROM {SCHEMA}.teams t"
            f" LEFT JOIN {SCHEMA}.members m ON m.team = t.schema AND m.email = $1 WHERE t.open ORDER BY lower(t.name)",
            email,
        )

    # --- pending_reviews (#1004) ---

    async def pending_join_requests(self, email: str, *, admin: bool, older_than: datetime) -> int:
        """How many requests to join the Teams the person owns wait (`_WAITING`), and for an admin those for any other Team
        filed before `older_than`."""
        pool = await self._get_pool()
        return await pool.fetchval(
            f"SELECT count(*) FROM {SCHEMA}.member_requests r WHERE {_WAITING} AND (($2::boolean AND r.requested_at < $3)"
            f" OR EXISTS (SELECT 1 FROM {SCHEMA}.members m WHERE m.team = r.team AND m.email = $1 AND m.role = 'owner'))",
            email,
            admin,
            older_than,
        )

    # --- #1005 ---

    async def queue_notice(
        self, recipients: list[str], kind: str, team: str | None, line: str, path: str, conn: asyncpg.Connection | None = None
    ) -> None:
        """Queue one line, linking to `path` on the key pages, for each recipient, who is `kind` to it ('owner' of
        `team`, 'admin', 'asker' or 'holder'). On `conn`, inside its transaction, when given."""
        db = conn or await self._get_pool()
        await db.execute(
            f"INSERT INTO {SCHEMA}.notice_queue (recipient, kind, team, line, path)"
            " SELECT r, $2, $3, $4, $5 FROM unnest($1::text[]) r",
            recipients,
            kind,
            team,
            line,
            path,
        )

    async def run_reminders(
        self,
        day: date,
        now: datetime,
        is_due: Callable[[datetime | None, bool], bool],
        build: Callable[[dict], list],
    ) -> bool:
        """Queue the reminders of `day` unless a process has, if `is_due(the last run's time or None, whether the day before
        was run)` (Notices.remind). One transaction records the day, reads what reminders are made of, and queues the notices
        `build(due)` makes, so a stop anywhere in it leaves the day not run and nothing queued. A second process running the
        same day waits for the first's transaction at the day's row, then finds the day run. Returns whether the day has been
        run, by this call or before; False, queuing nothing, while it is not due. `due` holds `last`, when the previous run
        was (None before the first), and every row of `allowlist` and `sign_ins`, of `requests` that wait (`_WAITING`, with
        the Team's name and its owners), and of `keys` that are unrevoked and unexpired at `now` (with their Team's name and
        their holder's role in it, `team_role`)."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            last, ran, ran_before = await conn.fetchrow(
                f"SELECT max(at), bool_or(day = $1::date), bool_or(day = $1::date - 1) FROM {SCHEMA}.reminder_runs", day
            )
            if ran:
                return True
            if not is_due(last, bool(ran_before)):
                return False
            if not await conn.fetchval(
                f"INSERT INTO {SCHEMA}.reminder_runs (day, at) VALUES ($1, $2) ON CONFLICT (day) DO NOTHING RETURNING true",
                day,
                now,
            ):
                return True
            due = {
                "last": last,
                "allowlist": await conn.fetch(f"SELECT email, role, requested_at FROM {SCHEMA}.allowlist ORDER BY email"),
                "sign_ins": await conn.fetch(f"SELECT email, last_seen FROM {SCHEMA}.sign_ins ORDER BY email"),
                "requests": await conn.fetch(
                    f"SELECT r.team, t.name, r.email, r.role, r.requested_by, r.requested_at,"
                    f" ARRAY(SELECT o.email FROM {SCHEMA}.members o WHERE o.team = r.team AND o.role = 'owner' ORDER BY o.email)"
                    f" AS owners FROM {SCHEMA}.member_requests r JOIN {SCHEMA}.teams t ON t.schema = r.team"
                    f" WHERE {_WAITING} ORDER BY r.requested_at, r.team, r.email"
                ),
                "keys": await conn.fetch(
                    f"SELECT k.email, k.name, k.kind, k.schema, k.expires_at, t.name AS team_name, m.role AS team_role"
                    f" FROM {SCHEMA}.keys k LEFT JOIN {SCHEMA}.teams t ON t.schema = k.schema"
                    f" LEFT JOIN {SCHEMA}.members m ON m.team = k.schema AND m.email = k.email"
                    " WHERE k.revoked_at IS NULL AND k.expires_at > $1 ORDER BY k.expires_at, k.id",
                    now,
                ),
            }
            for notice in build(due):
                await self.queue_notice(notice.recipients, notice.kind, notice.team, notice.line, notice.path, conn)
        return True

    async def queued_recipients(self) -> list[str]:
        pool = await self._get_pool()
        return [r["recipient"] for r in await pool.fetch(f"SELECT DISTINCT recipient FROM {SCHEMA}.notice_queue ORDER BY 1")]

    async def claim_notice(
        self, recipient: str, now: datetime, since: datetime, admins: list[str]
    ) -> tuple[int, list[tuple[str, str, str, str | None]]] | None:
        """Take everything queued for the person that they are still eligible for and log it as one message `sending`:
        (log ID, [(line, path, kind, team)]). Eligible is still what the notice made them (NOTICE_ELIGIBLE): an owner of its
        Team who is on the Key Allowlist, an admin (`admins` are the bootstrap admins), or a key's holder on the Key
        Allowlist; the rest is dropped. None, taking
        nothing, if they were messaged after `since` (it stays queued) or have nothing left to be told; their queue is
        emptied, and nothing logged, if they turned notices off. One transaction, one at a time per person across
        processes: a stop inside it rolls it back and the queue is as it was. The sender checks eligibility again under
        the person's notice lock, just before it sends (`still_eligible`)."""
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"{SCHEMA}.notices:{recipient}")
            if await conn.fetchval(f"SELECT 1 FROM {SCHEMA}.notice_log WHERE recipient = $1 AND at > $2", recipient, since):
                return None
            rows = await conn.fetch(
                f"WITH taken AS (DELETE FROM {SCHEMA}.notice_queue WHERE recipient = $1 RETURNING id, kind, team, line, path)"
                f" SELECT line, path, kind, team FROM taken t WHERE {NOTICE_ELIGIBLE} ORDER BY id",
                recipient,
                admins,
            )
            if not rows or await conn.fetchval(f"SELECT 1 FROM {SCHEMA}.notice_optouts WHERE email = $1", recipient):
                return None
            log_id = await conn.fetchval(
                f"INSERT INTO {SCHEMA}.notice_log (recipient, at, items, status) VALUES ($1, $2, $3, 'sending') RETURNING id",
                recipient,
                now,
                len(rows),
            )
        return log_id, [(r["line"], r["path"], r["kind"], r["team"]) for r in rows]

    async def still_eligible(
        self, conn: asyncpg.Connection, recipient: str, items: list[tuple[str, str, str, str | None]], admins: list[str]
    ) -> list[bool]:
        """For each claimed item, whether the person is still eligible for it now. Called under the person's notice lock, on
        the connection `notice_lock` gave, which every change that can end their eligibility takes before it commits, so once
        one has committed this sees it and, until it has, the change waits for the message that follows."""
        rows = await conn.fetch(
            f"SELECT t.ord FROM unnest($3::text[], $4::text[]) WITH ORDINALITY AS t(kind, team, ord) WHERE {NOTICE_ELIGIBLE}",
            recipient,
            admins,
            [item[2] for item in items],
            [item[3] for item in items],
        )
        yes = {r["ord"] - 1 for r in rows}
        return [i in yes for i in range(len(items))]

    async def finish_notice(self, log_id: int, status: str, detail: str | None, conn: asyncpg.Connection | None = None) -> None:
        """Say how the message went: 'sent', 'skipped' (turned off, or no longer eligible, after the claim), or 'failed' with
        why. On the connection `notice_lock` gave when the sender holds the lock; on the pool's when it never got it."""
        db = conn or await self._get_pool()
        await db.execute(f"UPDATE {SCHEMA}.notice_log SET status = $2, detail = $3 WHERE id = $1", log_id, status, detail)

    @contextlib.asynccontextmanager
    async def notice_lock(self, email: str):
        """Hold the person's notice lock, across API processes: a message to them is sent under it, and an opt-out is
        written under it (as is every change that can end their eligibility, `_lock_notices`), so those wait for a send
        in flight and a send that starts after one sees it. It takes a connection of its own and polls, as
        team_name_lock does, and yields it: the holder does everything it does under the lock on that connection and never
        waits for one from the pool, which changes waiting for this lock can have filled (they hold the pool's connections
        while they wait). TimeoutError after NOTICE_LOCK_WAIT seconds, which is longer than a send can last."""
        conn = await asyncpg.connect(_asyncpg_dsn(await self._db_url()))
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + NOTICE_LOCK_WAIT
            while not await conn.fetchval("SELECT pg_try_advisory_lock(hashtext($1))", _notice_lock_key(email)):
                if loop.time() >= deadline:
                    raise TimeoutError
                await asyncio.sleep(NOTICE_LOCK_POLL)
            yield conn
        finally:
            await conn.close()

    async def _lock_notices(self, conn: asyncpg.Connection, email: str) -> None:
        """Take the person's notice lock until the transaction on `conn` ends. Every change that can end someone's eligibility
        for a notice (a removal or a role change in a Team, a role change on the Key Allowlist) calls this before it changes
        anything, so it waits for a message to them in flight and a message whose final check comes after the commit sees it;
        so does a revocation that drops their queued warnings (`_drop_key_warnings`).
        It takes the lock on the transaction's own connection, first, so a change holds one pool connection while it waits
        and never waits for a second while it holds the lock.
        Polls, as notice_lock does; Refused(503) if the message does not finish within NOTICE_LOCK_WAIT seconds."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + NOTICE_LOCK_WAIT
        while not await conn.fetchval("SELECT pg_try_advisory_xact_lock(hashtext($1))", _notice_lock_key(email)):
            if loop.time() >= deadline:
                raise Refused(503, "A message to that person is being sent; try again in a moment.")
            await asyncio.sleep(NOTICE_LOCK_POLL)

    async def _drop_key_warnings(self, conn: asyncpg.Connection, emails: list[str]) -> None:
        """Drop the warnings queued for these people (their 'holder' notices), in the transaction on `conn` that revokes their
        keys, so none asks them afterwards to renew a key that no longer works. Takes each one's notice lock first, in order
        (`_lock_notices`), so a message to them in flight is sent before the revocation commits. shortcut: a message claimed
        just before, whose final check comes after, still goes out (a holder's eligibility is their place on the Key
        Allowlist, which a revocation keeps), and the queue does not say which key a warning is about, so the kill switch
        also drops a warning about a holder's own key; make a warning name its key if either matters."""
        for email in sorted(set(emails)):
            await self._lock_notices(conn, email)
        await conn.execute(f"DELETE FROM {SCHEMA}.notice_queue WHERE kind = 'holder' AND recipient = ANY($1::text[])", emails)

    async def notices_enabled(self, email: str, conn: asyncpg.Connection | None = None) -> bool:
        """Whether the person has not turned notices off; on `notice_lock`'s connection when the sender holds the lock."""
        db = conn or await self._get_pool()
        return not await db.fetchval(f"SELECT 1 FROM {SCHEMA}.notice_optouts WHERE email = $1", email)

    async def set_notices_enabled(self, email: str, enabled: bool) -> None:
        """Turn the person's notices on, or off: off waits for a send to them in flight (TimeoutError if it does not end),
        and writes on the lock's own connection, never a second one from the pool."""
        if enabled:
            pool = await self._get_pool()
            await pool.execute(f"DELETE FROM {SCHEMA}.notice_optouts WHERE email = $1", email)
            return
        async with self.notice_lock(email) as conn:
            await conn.execute(f"INSERT INTO {SCHEMA}.notice_optouts (email) VALUES ($1) ON CONFLICT DO NOTHING", email)
