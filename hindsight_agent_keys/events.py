"""The extension's own event log, kept in its own schema outside upstream's migrations."""

import logging
from collections.abc import Hashable
from datetime import datetime, timedelta
from typing import Protocol

import asyncpg

SCHEMA = "agent_keys"

logger = logging.getLogger(__name__)

# Idempotent and schema-qualified: our tables never enter upstream's Alembic
# history, so stock Hindsight still starts against a database this image used.
DDL = f"""
CREATE SCHEMA IF NOT EXISTS {SCHEMA};
CREATE TABLE IF NOT EXISTS {SCHEMA}.events (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    kind text NOT NULL,
    key_id text,
    client_ip text
);
CREATE INDEX IF NOT EXISTS events_at_idx ON {SCHEMA}.events (at);
"""


class EventLog(Protocol):
    async def start(self, db_url: str) -> None: ...

    async def stop(self) -> None: ...

    async def record(self, kind: str, key_id: str, client_ip: str | None) -> None: ...


class Throttle:
    """Allows one occurrence per key per window, with bounded memory."""

    def __init__(self, window_seconds: int, max_entries: int = 10_000):
        self._window = timedelta(seconds=window_seconds)
        self._max = max_entries
        self._last: dict[Hashable, datetime] = {}

    def allow(self, key: Hashable, now: datetime) -> bool:
        last = self._last.get(key)
        if last is not None and now - last < self._window:
            return False
        if len(self._last) >= self._max:
            self._last = {k: t for k, t in self._last.items() if now - t < self._window}
            if len(self._last) >= self._max:
                self._last.clear()
        self._last[key] = now
        return True


def _asyncpg_dsn(db_url: str) -> str:
    # Hindsight may hand out an SQLAlchemy-style URL; asyncpg wants plain postgresql://.
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if db_url.startswith(prefix):
            return "postgresql://" + db_url[len(prefix):]
    return db_url


class PostgresEventLog:
    """Writes events to Hindsight's own Postgres; records nothing until started."""

    def __init__(self) -> None:
        self._pool: asyncpg.Pool | None = None

    async def start(self, db_url: str) -> None:
        """Connect and create our tables; on failure log a warning and stay inert."""
        pool = None
        try:
            pool = await asyncpg.create_pool(_asyncpg_dsn(db_url), min_size=1, max_size=2)
            async with pool.acquire() as conn:
                await conn.execute(DDL)
        except Exception as exc:
            logger.warning("agent-keys: event log unavailable, events will not be recorded: %s", exc)
            if pool is not None:
                await pool.close()
            return
        self._pool = pool

    async def stop(self) -> None:
        pool, self._pool = self._pool, None
        if pool is not None:
            await pool.close()

    async def record(self, kind: str, key_id: str, client_ip: str | None) -> None:
        if self._pool is None:
            return
        await self._pool.execute(
            f"INSERT INTO {SCHEMA}.events (kind, key_id, client_ip) VALUES ($1, $2, $3)",
            kind,
            key_id,
            client_ip,
        )
