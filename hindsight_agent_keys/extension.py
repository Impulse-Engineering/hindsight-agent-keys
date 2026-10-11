"""Tenant extension that maps each Agent Key to the schema it may use.

In this first form it knows one key: the legacy shared key, which reaches the
Public Team in the `public` schema. Every other key, and a missing key, is refused.
"""

import hashlib
import hmac
import ipaddress
import logging
import re
from collections.abc import Callable
from datetime import datetime, timezone

from hindsight_api.config import HindsightConfig
from hindsight_api.extensions.tenant import AuthenticationError, Tenant, TenantContext, TenantExtension
from hindsight_api.models import RequestContext

from hindsight_agent_keys.events import EventLog, PostgresEventLog, Throttle

PUBLIC_SCHEMA = "public"
LEGACY_KEY_ID = "legacy"

# Per-bank settings no bank may change. Upstream audit logging stays off while the
# Public Team lives in `public`: unauthenticated requests would write into its log.
DENIED_BANK_FIELDS = frozenset({"audit_log_enabled"})

# Agent Keys look like hsk_<id>_<secret>; only the id may ever be logged.
_AGENT_KEY_ID = re.compile(r"^hsk_([A-Za-z0-9]{1,32})_")

# The fronting proxy must set X-Real-IP to the real client address and overwrite
# any client-supplied value; the image passes the header through.
CLIENT_IP_HEADER = "x-real-ip"

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_expiry(text: str) -> datetime:
    """Read an ISO date or datetime; a bare date means midnight UTC, naive times are UTC."""
    try:
        when = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise ValueError(f"HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES is not an ISO date or datetime: {text!r}") from exc
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _client_ip(context: RequestContext) -> str | None:
    """The forwarded client address in canonical form, or None if absent or not an address."""
    raw = (context.extra_headers or {}).get(CLIENT_IP_HEADER) or ""
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def _key_id(key: str) -> str:
    if not key:
        return "missing"
    match = _AGENT_KEY_ID.match(key)
    return match.group(1) if match else "unrecognized"


def _digest(value: str) -> bytes:
    # Comparing fixed-length digests keeps the comparison constant-time
    # whatever the length of the presented key.
    return hashlib.sha256(value.encode()).digest()


class AgentKeysTenantExtension(TenantExtension):
    def __init__(
        self,
        config: dict[str, str],
        *,
        clock: Callable[[], datetime] | None = None,
        events: EventLog | None = None,
    ):
        super().__init__(config)
        legacy = config.get("legacy_key") or ""
        self._legacy_digest = _digest(legacy) if legacy else None
        expires = config.get("legacy_key_expires") or ""
        self._legacy_expires = _parse_expiry(expires) if expires else None
        self._clock = clock or _now
        self._events = events if events is not None else PostgresEventLog()
        self._throttle = Throttle(window_seconds=60)

    async def on_startup(self) -> None:
        await self._events.start(self.context.get_memory_engine().db_url)

    async def on_shutdown(self) -> None:
        await self._events.stop()

    async def authenticate(self, context: RequestContext) -> TenantContext:
        key = context.api_key or ""
        if key and self._legacy_digest is not None and hmac.compare_digest(_digest(key), self._legacy_digest):
            if self._legacy_expires is None or self._clock() < self._legacy_expires:
                context.api_key_id = LEGACY_KEY_ID
                return TenantContext(schema_name=PUBLIC_SCHEMA)
            await self._refused(context, "legacy_key_expired", LEGACY_KEY_ID)
            raise AuthenticationError("API key expired")
        await self._refused(context, "key_refused", _key_id(key))
        raise AuthenticationError("Invalid or missing API key")

    async def _refused(self, context: RequestContext, kind: str, key_id: str) -> None:
        client_ip = _client_ip(context)
        # One row per kind per client IP per minute, whatever key it presents:
        # unauthenticated callers must not be able to grow the log at will.
        if not self._throttle.allow((kind, client_ip), self._clock()):
            return
        try:
            await self._events.record(kind, key_id, client_ip)
        except Exception as exc:  # the refusal stands even if it cannot be logged
            logger.warning("agent-keys: could not record %s event: %s", kind, exc)

    async def list_tenants(self) -> list[Tenant]:
        # Always include `public`: startup migrates and the worker polls only the
        # schemas listed here (upstream #5400).
        return [Tenant(schema=PUBLIC_SCHEMA)]

    async def get_allowed_config_fields(self, context: RequestContext, bank_id: str) -> set[str] | None:
        return HindsightConfig.get_configurable_fields() - DENIED_BANK_FIELDS
