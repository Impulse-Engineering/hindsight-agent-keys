"""Tenant extension that maps each Agent Key to the schema it may use.

It knows two kinds of key: the legacy shared key, which reaches the Public Team in
the `public` schema, and personal Agent Keys, each reaching its owner's own schema.
Every other key, and a missing key, is refused.
"""

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from hindsight_api.config import HindsightConfig, get_config
from hindsight_api.extensions.tenant import (
    AuthenticationError,
    Tenant,
    TenantContext,
    TenantExtension,
)
from hindsight_api.models import RequestContext
from hindsight_api.pg0 import resolve_database_url

from hindsight_agent_keys.access import AccessVerifier
from hindsight_agent_keys.events import EventLog, PostgresEventLog, RateLimit, Throttle
from hindsight_agent_keys.store import PostgresKeyStore, Refused

PUBLIC_SCHEMA = "public"

# Roles on the Key Allowlist that may create keys; 'requested' may not.
LISTED = ("member", "admin")

# Reserved key IDs are parenthesised: a presented key's ID is alphanumeric
# (see _AGENT_KEY_ID), so no presented key can pose as one of these.
LEGACY_KEY_ID = "(legacy)"
MISSING_KEY_ID = "(missing)"
UNRECOGNIZED_KEY_ID = "(unrecognized)"
NO_KEY_ID = "(none)"

# Per-bank settings no bank may change. Upstream audit logging stays off while the
# Public Team lives in `public`: unauthenticated requests would write into its log.
DENIED_BANK_FIELDS = frozenset({"audit_log_enabled"})

# Agent Keys look like hsk_<id>_<secret>; only the id may ever be logged.
_AGENT_KEY_ID = re.compile(r"^hsk_([A-Za-z0-9]{1,32})_")

# Compared against when a key ID is unknown, so that costs the same as a wrong secret.
_NO_DIGEST = bytes(32)

# The fronting proxy must set X-Real-IP to the real client address and overwrite
# any client-supplied value; the image passes the header through.
CLIENT_IP_HEADER = "x-real-ip"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    """Who an accepted key acts as."""

    kind: str  # "legacy" or "personal"
    schema: str
    key_id: str
    email: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_expiry(text: str) -> datetime:
    """Read an ISO date or datetime; a bare date means midnight UTC, naive times are UTC."""
    try:
        when = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise ValueError(f"HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES is not an ISO date or datetime: {text!r}") from exc
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def client_ip(headers: Mapping[str, str] | None) -> str | None:
    """The forwarded client address in canonical form, or None if absent or not an address."""
    raw = (headers or {}).get(CLIENT_IP_HEADER) or ""
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    # One client, one form: ::ffff:a.b.c.d is the IPv4 address a.b.c.d.
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _client_bucket(client_ip: str | None) -> str | None:
    """The unit one client is throttled by: an IPv4 address, or an IPv6 /64
    (one subscriber typically holds a whole /64 and can rotate within it)."""
    if client_ip is None:
        return None
    address = ipaddress.ip_address(client_ip)
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return client_ip


def _key_id(key: str) -> str:
    if not key:
        return MISSING_KEY_ID
    match = _AGENT_KEY_ID.match(key)
    return match.group(1) if match else UNRECOGNIZED_KEY_ID


def _role_change(old: str | None, new: str | None) -> str:
    """The event kind for an admin changing someone's role on the Key Allowlist from old to new."""
    if new == "admin":
        return "admin_granted"
    if new == "member":
        return {"admin": "admin_removed", "requested": "access_approved"}.get(old, "allowlist_added")
    return "access_declined" if old == "requested" else "allowlist_removed"


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
        store: PostgresKeyStore | None = None,
    ):
        super().__init__(config)
        legacy = config.get("legacy_key") or ""
        self._legacy_digest = _digest(legacy) if legacy else None
        expires = config.get("legacy_key_expires") or ""
        self._legacy_expires = _parse_expiry(expires) if expires else None
        pepper = (config.get("key_pepper") or "").encode()
        if pepper and len(pepper) < 32:
            raise ValueError("HINDSIGHT_API_TENANT_KEY_PEPPER must be at least 32 bytes")
        # Without a pepper no key can be created and every Agent Key is refused.
        self._pepper = pepper or None
        # Always admins, so always on the Key Allowlist; the page cannot change them.
        self.bootstrap_admins = frozenset(
            e.strip().lower() for e in os.environ.get("AGENT_KEYS_ADMIN_EMAILS", "").split(",") if e.strip()
        )
        team, audience, host = (config.get(k) or "" for k in ("access_team_domain", "access_aud", "access_host"))
        # The key pages answer only when all three are set.
        self.access_host = host.strip().lower() if team and audience and host else None
        self._access = AccessVerifier(team, audience) if self.access_host else None
        self._clock = clock or _now
        self._events = events if events is not None else PostgresEventLog()
        self._store = store if store is not None else PostgresKeyStore(self._db_url)
        self._tenants: list[Tenant] | None = None
        # Refusal rows are bounded twice: one a minute per client, and at most
        # 60 a minute in total, so unauthenticated callers cannot grow the log.
        self._throttle = Throttle(window_seconds=60)
        self._refusal_budget = RateLimit(limit=60, window_seconds=60)

    async def _db_url(self) -> str:
        if self._context is None:
            # hindsight-admin lists tenants with no context (admin/cli.py:572); resolve as it does.
            return await resolve_database_url(get_config().database_url)
        return self.context.get_memory_engine().db_url

    async def on_startup(self) -> None:
        await self._events.start(self.context.get_memory_engine().db_url)

    async def on_shutdown(self) -> None:
        await self._events.stop()
        await self._store.close()

    async def access_email(self, token: str | None) -> str | None:
        """The signed-in person's lowercase email from an Access JWT, or None."""
        if self._access is None or not token:
            return None
        return await self._access.email(token)

    async def role(self, email: str) -> str | None:
        """The person's place on the Key Allowlist: 'admin', 'member', 'requested' (asked to join) or None."""
        return "admin" if email in self.bootstrap_admins else await self._store.role(email)

    async def allowlist(self) -> list[tuple[str, str]]:
        """(email, role) for the bootstrap admins, then everyone else with a role, pending requests first."""
        stored = [(r["email"], r["role"]) for r in await self._store.allowlist() if r["email"] not in self.bootstrap_admins]
        return [(e, "admin") for e in sorted(self.bootstrap_admins)] + stored

    async def request_access(self, email: str, client_ip: str | None) -> None:
        """Ask the admins to add a signed-in person; does nothing if they already have a role."""
        if await self.role(email) is None and await self._store.add_request(email):
            await self._record("access_requested", NO_KEY_ID, client_ip, email, email)

    async def set_role(self, admin: str, email: str, role: str | None, client_ip: str | None) -> None:
        """An admin makes the person a 'member' or an 'admin' of the Key Allowlist, or removes them (None)."""
        if email in self.bootstrap_admins:
            raise Refused(409, "Admins set in AGENT_KEYS_ADMIN_EMAILS cannot be changed here.")
        old = await self._store.set_role(email, role)
        if old != role:
            await self._record(_role_change(old, role), NO_KEY_ID, client_ip, email, admin)

    def _hmac(self, key: str) -> bytes:
        return hmac.new(self._pepper, key.encode(), hashlib.sha256).digest()

    async def create_personal_key(self, email: str, name: str, client_ip: str | None) -> tuple[str, str]:
        """Create a key for the person's own schema. Returns (key ID, key); the key is never stored."""
        if self._pepper is None:
            raise Refused(503, "Key creation is not configured.")
        if await self.role(email) not in LISTED:
            raise Refused(403, "You are not on the Key Allowlist.")
        schema = await self._store.person_schema(email)
        if schema is None:
            # Generated, never derived from the email, and migrated before any key reaches it.
            schema = "p_" + secrets.token_hex(8)
            await self.context.run_migration(schema)
            # shortcut: a concurrent first key for the same person wins and this schema stays
            # empty and unlisted; serialise first keys per person if that ever shows up.
            schema = await self._store.add_person(email, schema)
        key_id = secrets.token_hex(8)
        key = f"hsk_{key_id}_{secrets.token_urlsafe(32)}"
        await self._store.add_key(key_id, self._hmac(key), name, email, schema)
        await self._record("key_created", key_id, client_ip, email)
        return key_id, key

    def _is_legacy(self, key: str) -> bool:
        return bool(key) and self._legacy_digest is not None and hmac.compare_digest(_digest(key), self._legacy_digest)

    async def principal(self, api_key: str | None) -> Principal | None:
        """Who a key acts as, or None if it is refused."""
        key = api_key or ""
        if self._is_legacy(key):
            if self._legacy_expires is not None and self._clock() >= self._legacy_expires:
                return None
            return Principal("legacy", PUBLIC_SCHEMA, LEGACY_KEY_ID)
        match = _AGENT_KEY_ID.match(key)
        if match is None or self._pepper is None:
            return None
        row = await self._store.find_key(match.group(1))
        if not hmac.compare_digest(self._hmac(key), row["digest"] if row else _NO_DIGEST) or row is None:
            return None
        # Removing someone from the Key Allowlist disables the keys they hold.
        if row["role"] not in LISTED and row["email"] not in self.bootstrap_admins:
            return None
        return Principal("personal", row["schema"], match.group(1), row["email"])

    async def authenticate(self, context: RequestContext) -> TenantContext:
        key = context.api_key or ""
        principal = await self.principal(key)
        if principal is not None:
            context.api_key_id = principal.key_id
            return TenantContext(schema_name=principal.schema)
        if self._is_legacy(key):
            await self._refused(context, "legacy_key_expired", LEGACY_KEY_ID)
            raise AuthenticationError("API key expired")
        await self._refused(context, "key_refused", _key_id(key))
        raise AuthenticationError("Invalid or missing API key")

    async def _refused(self, context: RequestContext, kind: str, key_id: str) -> None:
        ip = client_ip(context.extra_headers)
        now = self._clock()
        if not self._throttle.allow(_client_bucket(ip), now):
            return
        if not self._refusal_budget.allow(now):
            # Make the suppression itself visible, once a minute.
            if self._refusal_budget.first_saturation(now):
                logger.warning("agent-keys: refusal log budget used up; more refusals this minute are not recorded")
                await self._record("refusal_log_saturated", NO_KEY_ID, None)
            return
        await self._record(kind, key_id, ip)

    async def _record(
        self, kind: str, key_id: str, client_ip: str | None, email: str | None = None, actor: str | None = None
    ) -> None:
        try:
            await self._events.record(kind, key_id, client_ip, email, actor)
        except Exception as exc:  # noqa: BLE001 - the decision stands even if it cannot be logged
            logger.warning("agent-keys: could not record %s event: %s", kind, exc)

    async def list_tenants(self) -> list[Tenant]:
        # `public` once and first, then every personal schema: startup migrates and
        # the worker polls only the schemas listed here (upstream #5400).
        try:
            schemas = await self._store.tenant_schemas()
        except Exception:
            # With no list yet (startup) fail, so no schema silently skips its migrations;
            # later, keep the worker claiming from the last list it had.
            if self._tenants is None:
                raise
            logger.warning("agent-keys: could not list tenants; using the last list", exc_info=True)
            return self._tenants
        self._tenants = [Tenant(schema=PUBLIC_SCHEMA), *(Tenant(schema=s) for s in schemas)]
        return self._tenants

    async def get_allowed_config_fields(self, context: RequestContext, bank_id: str) -> set[str] | None:
        return HindsightConfig.get_configurable_fields() - DENIED_BANK_FIELDS
