"""Tenant extension that maps each Agent Key to the schema it may use.

It knows three kinds of key: the legacy shared key, which reaches the Public Team in
the `public` schema; personal Agent Keys, each reaching its owner's own schema; and
Team keys, each reaching one Team's schema (or `public` for the Public Team) only while
its holder is in that Team. Every other key, and a missing key, is refused.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial

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

# A key works for this long after it is created or renewed,
KEY_LIFETIME = timedelta(days=90)
# and only while its owner has signed in through Access within this window.
SIGN_IN_WINDOW = timedelta(days=30)

# Roles on the Key Allowlist that may create keys; 'requested' may not.
LISTED = ("member", "admin")

# Keys created via WorkPlane, per person, apart from their own (store.ACTIVE_KEYS, store.CREATIONS_PER_HOUR).
# Defaults of the settings HINDSIGHT_API_TENANT_WORKPLANE_ACTIVE_KEYS and ..._WORKPLANE_KEYS_PER_HOUR. An hour may
# fill the whole cap, so onboarding into many Teams at once is never held up; the rate still bounds a
# create-and-revoke loop.
WORKPLANE_ACTIVE_KEYS = 25
WORKPLANE_KEYS_PER_HOUR = 25

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

    kind: str  # "legacy", "personal" or "team" (the Public Team included)
    schema: str
    key_id: str
    email: str | None = None


@dataclass(frozen=True)
class Via:
    """The channel a request came in on, which every event it records names."""

    channel: str  # "ext" (the key pages), "delegated" (a Delegated Request) or "mcp"
    delegate: str | None = None  # the Delegate's service-token client ID, on "delegated"


# Set once per request by its channel's gate. Each request runs in its own task, and a
# FastAPI dependency or an MCP tool runs in the task of the handler it serves, so the
# value reaches every event that request records and no other request's.
_via: ContextVar[Via | None] = ContextVar("agent_keys_via", default=None)


def acting_via(channel: str, delegate: str | None = None) -> None:
    """Tag every event the current request records with its channel and Delegate."""
    _via.set(Via(channel, delegate))


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


def host_and_json(headers: Mapping[str, str]) -> tuple[str, bool]:
    """What the /ext gates check first: the hostname asked for (lower-cased, without its port),
    and whether the body is declared as JSON."""
    host = (headers.get("host") or "").partition(":")[0].lower()
    content_type = (headers.get("content-type") or "").partition(";")[0].strip().lower()
    return host, content_type == "application/json"


def _limit(config: dict[str, str], name: str, default: int) -> int:
    """A whole-number setting; blank means the default, anything else that is not a whole number stops startup."""
    text = (config.get(name) or "").strip()
    if not text:
        return default
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError(f"HINDSIGHT_API_TENANT_{name.upper()} is not a whole number: {text!r}")
    return int(text)


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
        # Stripped before anything decides on them, so a blank setting is an unset one.
        team, audience, host = ((config.get(k) or "").strip() for k in ("access_team_domain", "access_aud", "access_host"))
        # The key pages answer only when all three are set.
        self.access_host = host.lower() if team and audience and host else None
        self._access = AccessVerifier(team, audience) if self.access_host else None
        names = ("delegation_host", "delegation_aud", "workplane_aud", "delegate_client_id")
        delegation_host, delegation_aud, workplane_aud, client_id = ((config.get(k) or "").strip() for k in names)
        # Delegated Requests answer only when the team and all four delegation settings are set.
        delegation = team and delegation_host and delegation_aud and workplane_aud and client_id
        self.delegation_host = delegation_host.lower() if delegation else None
        self._delegate_client_id = client_id if delegation else None
        # The Delegate's service token is for the delegation application; the person's JWT for WorkPlane's.
        self._delegation = AccessVerifier(team, delegation_aud) if delegation else None
        self._workplane = AccessVerifier(team, workplane_aud) if delegation else None
        # Checked only when a key is created, so lowering one revokes nothing.
        self._workplane_cap = _limit(config, "workplane_active_keys", WORKPLANE_ACTIVE_KEYS)
        self._workplane_per_hour = _limit(config, "workplane_keys_per_hour", WORKPLANE_KEYS_PER_HOUR)
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
        """The signed-in person's lowercase email from an Access JWT, or None.

        Records the sign-in: agents never pass through Access, so this is the only
        evidence that a key's owner is still with us.
        """
        return await self._signed_in(self._access, token)

    async def delegated_email(self, token: str | None) -> str | None:
        """The person a Delegated Request acts for: the lowercase email of their own Access JWT for
        WorkPlane's application, or None. Records the sign-in as access_email does, dated by the token."""
        return await self._signed_in(self._workplane, token)

    async def _signed_in(self, verifier: AccessVerifier | None, token: str | None) -> str | None:
        if verifier is None or not token:
            return None
        person = await verifier.email(token)
        if person is None:
            return None
        email, signed_in_at = person
        # The token's iat, never the request time, and never older than the stored sign-in.
        await self._store.signed_in(email, signed_in_at)
        return email

    async def delegate(self, token: str | None) -> str | None:
        """The Delegate's client ID if `token` is a valid service-token JWT for the delegation
        application issued to the configured client ID, else None. A JWT with an email claim, even an
        empty one, never is."""
        if self._delegation is None or not token:
            return None
        claims = await self._delegation.claims(token)
        if claims is None or "email" in claims or claims.get("common_name") != self._delegate_client_id:
            return None
        return self._delegate_client_id

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

    async def stale_schemas(self) -> list:
        """Personal schemas no valid key has reached for 90 days: schema, owner's email and
        last key activity (None if it never had a key). Never a Team schema or `public`."""
        return await self._store.stale_schemas()

    def _hmac(self, key: str) -> bytes:
        return hmac.new(self._pepper, key.encode(), hashlib.sha256).digest()

    async def _require_allowlisted(self, email: str) -> None:
        if await self.role(email) not in LISTED:
            raise Refused(403, "You are not on the Key Allowlist.")

    async def create_personal_key(
        self, email: str, name: str, client_ip: str | None, *, via: str | None = None, idempotency_key: str | None = None
    ) -> tuple[str, str | None]:
        """Create a key for the person's own schema, marked as created via WorkPlane if `via` names
        the Delegate. Returns (key ID, key); the key is never stored. A repeat of the Delegate's
        `idempotency_key` within 24 hours returns (the key ID it created, None)."""
        if self._pepper is None:
            raise Refused(503, "Key creation is not configured.")
        await self._require_allowlisted(email)
        schema = await self._store.person_schema(email)
        if schema is None:
            # Generated, never derived from the email, and migrated before any key reaches it.
            schema = "p_" + secrets.token_hex(8)
            await self.context.run_migration(schema)
            # shortcut: a concurrent first key for the same person wins and this schema stays
            # empty and unlisted; serialise first keys per person if that ever shows up.
            schema = await self._store.add_person(email, schema)
        return await self._add_key(email, schema, "personal", name, client_ip, via=via, idempotency_key=idempotency_key)

    async def _add_key(
        self,
        email: str,
        schema: str,
        kind: str,
        name: str,
        client_ip: str | None,
        *,
        via: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[str, str | None]:
        key_id = secrets.token_hex(8)
        key = f"hsk_{key_id}_{secrets.token_urlsafe(32)}"
        expires_at = self._clock() + KEY_LIFETIME
        limits = {"cap": self._workplane_cap, "per_hour": self._workplane_per_hour} if via else {}
        # The body a repeat must match: what kind of key, for which schema, under which name.
        idempotency = (idempotency_key, _digest(json.dumps([kind, schema, name]))) if idempotency_key else None
        stored = await self._store.add_key(
            key_id, self._hmac(key), name, email, schema, kind, expires_at, via=via, idempotency=idempotency, **limits
        )
        if stored != key_id:
            # A repeat: the key it created, whose secret was shown once and never again. It records no event,
            # so a key stored just before the process stopped (or the event log failed) keeps no key_created
            # row; the key is listed and works as any other (README, "Delegated Requests").
            return stored, None
        await self._record("key_created", key_id, client_ip, email, email, team=schema if kind == "team" else None)
        return key_id, key

    # With `via_workplane`, the next three reach only the person's keys created via WorkPlane.

    async def list_keys(self, email: str, *, via_workplane: bool = False) -> list[dict]:
        """The person's own keys, oldest first, each with its state and whole days to expiry (rounded up;
        0 once expired, None once revoked, so a revoked key never looks due for renewal)."""
        now = self._clock()
        return [
            {
                **row,
                "state": "revoked" if row["revoked_at"] else "expired" if now >= row["expires_at"] else "active",
                "days_to_expiry": None
                if row["revoked_at"]
                else max(0, math.ceil((row["expires_at"] - now) / timedelta(days=1))),
            }
            for row in await self._store.list_keys(email, via_workplane=via_workplane)
        ]

    async def renew_key(self, email: str, key_id: str, client_ip: str | None, *, via_workplane: bool = False) -> datetime:
        """Give the person's unexpired key another full lifetime from now; returns its new expiry.
        Refused once the person's sign-in window has closed: their keys already stop working then."""
        now = self._clock()
        signed_in = await self._store.last_sign_in(email)
        if signed_in is None or now - signed_in >= SIGN_IN_WINDOW:
            raise Refused(403, "You have not signed in through Access for 30 days; sign in again, then renew.")
        expires_at = now + KEY_LIFETIME
        if not await self._store.renew_key(email, key_id, now, expires_at, via_workplane=via_workplane):
            raise Refused(404, "You hold no active key with that ID.")
        await self._record("key_renewed", key_id, client_ip, email, email)
        return expires_at

    async def revoke_key(self, email: str, key_id: str, client_ip: str | None, *, via_workplane: bool = False) -> None:
        """Revoke one of the person's own keys; it is refused from its next request. With `via_workplane`
        (a Delegated Request), a repeat for one of those keys already revoked changes and records nothing."""
        if await self._store.revoke_keys(email, self._clock(), key_id, via_workplane=via_workplane):
            await self._record("key_revoked", key_id, client_ip, email, email)
            return
        if via_workplane and any(
            k["id"] == key_id and k["revoked_at"] for k in await self._store.list_keys(email, via_workplane=True)
        ):
            return
        raise Refused(404, "You hold no unrevoked key with that ID.")

    async def revoke_identity(self, admin: str, email: str, client_ip: str | None) -> int:
        """Revoke every key the person holds; returns how many. Admins only."""
        if await self.role(admin) != "admin":
            raise Refused(403, "Only an admin can revoke an identity.")
        revoked = await self._store.revoke_keys(email, self._clock())
        await self._record("identity_revoked", NO_KEY_ID, client_ip, email, actor=admin)
        return revoked

    async def create_team_key(
        self, email: str, team: str, name: str, client_ip: str | None, *, via: str | None = None, idempotency_key: str | None = None
    ) -> tuple[str, str | None]:
        """Create a key for a Team the person is in, or for the Public Team (`public`), marked as created
        via WorkPlane if `via` names the Delegate. Returns (key ID, key); the key is never stored. A repeat
        of the Delegate's `idempotency_key` within 24 hours returns (the key ID it created, None)."""
        if self._pepper is None:
            raise Refused(503, "Key creation is not configured.")
        await self._require_allowlisted(email)
        if team != PUBLIC_SCHEMA and await self._store.team_role(team, email) is None:
            raise Refused(403, "You are not in that Team.")
        await self._store.add_person(email, None)
        return await self._add_key(email, team, "team", name, client_ip, via=via, idempotency_key=idempotency_key)

    async def create_team(self, email: str, name: str, client_ip: str | None, *, delegated_repeat: bool = False) -> str:
        """Create a Team with the person as its first owner. Returns the Team's schema. With `delegated_repeat`
        (a Delegated Request), the name of a Team the person already owns returns its schema and changes nothing."""
        await self._require_allowlisted(email)
        if name.lower() == PUBLIC_SCHEMA:
            raise Refused(409, "The name public is reserved for the Public Team.")
        # One creation of a name at a time, across API processes: the first migrates and stores the Team,
        # and a concurrent one, which waits here, finds it and is answered or refused without migrating.
        async with self._store.team_name_lock(name):
            # Checked before migrating, so a taken name or a person at the limit leaves no schema behind.
            taken = await self._store.team_schema(name)
            if taken is not None:
                if delegated_repeat and await self._store.team_role(taken, email) == "owner":
                    return taken
                raise Refused(409, "A Team with that name exists.")
            await self._store.check_team_limit(email)
            schema = "t_" + secrets.token_hex(8)
            await self.context.run_migration(schema)
            # shortcut: concurrent creations by one person past the limit leave this schema empty and
            # unlisted; serialise a person's creations around the migration if that ever shows up.
            await self._store.create_team(schema, name, email)
        await self._record("team_created", NO_KEY_ID, client_ip, email, email, team=schema)
        return schema

    async def team_name(self, team: str) -> str | None:
        """The Team's name as it was created. For a caller that just created the Team or was told it is theirs."""
        return await self._store.team_name(team)

    async def teams(self, email: str) -> list[dict]:
        """The person's Teams, or every Team for an admin, each with the person's role, its members
        and the pending requests to add people."""
        rows = await self._store.teams(email, everyone=await self.role(email) == "admin")
        return [
            {
                "team": r["schema"],
                "name": r["name"],
                "role": r["role"],
                "members": [{"email": m["email"], "role": m["role"]} for m in await self._store.members(r["schema"])],
                "requests": [
                    {"email": q["email"], "role": q["role"], "by": q["requested_by"]}
                    for q in await self._store.member_requests(r["schema"])
                ],
            }
            for r in rows
        ]

    async def _require_manager(self, email: str, team: str) -> None:
        if await self.role(email) == "admin":
            return
        if await self._store.team_role(team, email) != "owner":
            raise Refused(403, "Only the Team's owners and admins can change its members.")
        # An owner cut off from the Key Allowlist keeps the Team and returns to managing it when added back.
        await self._require_allowlisted(email)

    async def set_member(
        self, email: str, team: str, member: str, role: str, client_ip: str | None, *, delegated_repeat: bool = False
    ) -> None:
        """As an admin, or an owner on the Key Allowlist, add `member` to the Team as "owner" or "member", or change their role.
        With `delegated_repeat` (a Delegated Request), a repeat that leaves their role as it was records nothing."""
        await self._require_manager(email, team)
        had = await self._store.set_member(team, member, role)
        if not (delegated_repeat and had == role):
            await self._record(f"{role}_added", NO_KEY_ID, client_ip, member, email, team=team)

    async def remove_member(self, email: str, team: str, member: str, client_ip: str | None, *, delegated_repeat: bool = False) -> None:
        """As an admin, or an owner on the Key Allowlist, take `member` out of the Team. With `delegated_repeat`
        (a Delegated Request), a removal of someone who was not in the Team records nothing."""
        await self._require_manager(email, team)
        had = await self._store.remove_member(team, member)
        if not (delegated_repeat and had is None):
            await self._record("member_removed", NO_KEY_ID, client_ip, member, email, team=team)

    async def request_member(self, email: str, team: str, member: str, role: str, client_ip: str | None) -> None:
        """As an admin, or an owner on the Key Allowlist, ask for `member` to become an "owner" or "member" of the Team.
        Agents add people this way: nothing changes until an owner on the Key Allowlist, or an admin, confirms it on the Teams page."""
        await self._require_manager(email, team)
        await self._store.request_member(team, member, role, email)
        await self._record(f"{role}_requested", NO_KEY_ID, client_ip, member, email, team=team)

    async def confirm_member(self, email: str, team: str, member: str, role: str, client_ip: str | None) -> None:
        """As an admin, or an owner on the Key Allowlist, give `member` the role a pending request asked for. `role` is the one
        the page showed: if the request asks for another now, nothing is granted (Refused 409)."""
        confirm = partial(self._store.confirm_member, role=role)
        await self._answer_request(email, team, member, client_ip, confirm, "confirmed", role)

    async def decline_member(self, email: str, team: str, member: str, client_ip: str | None) -> None:
        """As an admin, or an owner on the Key Allowlist, drop a pending request for `member`; their place in the Team stays as it was."""
        await self._answer_request(email, team, member, client_ip, self._store.decline_member, "declined")

    async def _answer_request(self, email, team, member, client_ip, answer, outcome, shown=None) -> None:
        await self._require_manager(email, team)
        role = await answer(team, member)
        if role is None:
            raise Refused(404, "Nobody asked to add that person to the Team.")
        if shown not in (None, role):
            raise Refused(409, f"That request now asks for {role}; reload the page.")
        await self._record(f"{role}_{outcome}", NO_KEY_ID, client_ip, member, email, team=team)

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
        now = self._clock()
        if row["revoked_at"] is not None or now >= row["expires_at"]:
            return None
        if row["last_seen"] is None or now - row["last_seen"] >= SIGN_IN_WINDOW:
            return None
        # Removing someone from the Key Allowlist disables the keys they hold.
        if row["role"] not in LISTED and row["email"] not in self.bootstrap_admins:
            return None
        team = row["kind"] == "team" and row["schema"] != PUBLIC_SCHEMA
        # Uncached, so removing a member stops their Team keys on their next request.
        if team and await self._store.team_role(row["schema"], row["email"]) is None:
            return None
        return Principal(row["kind"], row["schema"], match.group(1), row["email"])

    async def authenticate(self, context: RequestContext) -> TenantContext:
        key = context.api_key or ""
        principal = await self.principal(key)
        if principal is not None:
            context.api_key_id = principal.key_id
            return TenantContext(schema_name=principal.schema)
        ip = client_ip(context.extra_headers)
        if self._is_legacy(key):
            await self.refused(ip, "legacy_key_expired", LEGACY_KEY_ID)
            raise AuthenticationError("API key expired")
        await self.refused(ip, "key_refused", _key_id(key))
        raise AuthenticationError("Invalid or missing API key")

    async def refused(self, ip: str | None, kind: str, key_id: str = NO_KEY_ID) -> None:
        """Record a refused request from an unauthenticated client, throttled per client and in total."""
        now = self._clock()
        if not self._throttle.allow(_client_bucket(ip), now):
            return
        if not self._refusal_budget.allow(now):
            # Make the suppression itself visible, once a minute.
            if self._refusal_budget.first_saturation(now):
                logger.warning("agent-keys: refusal log budget used up; more refusals this minute are not recorded")
                # Every channel's refusals share the budget, so this row belongs to none of them.
                await self._record("refusal_log_saturated", NO_KEY_ID, None, tagged=False)
            return
        await self._record(kind, key_id, ip)

    async def _record(
        self,
        kind: str,
        key_id: str,
        client_ip: str | None,
        email: str | None = None,
        actor: str | None = None,
        team: str | None = None,
        *,
        tagged: bool = True,
    ) -> None:
        via = _via.get() if tagged else None
        channel, delegate = (via.channel, via.delegate) if via else (None, None)
        try:
            await self._events.record(kind, key_id, client_ip, email, actor, team, channel=channel, delegate=delegate)
        except Exception as exc:  # noqa: BLE001 - the decision stands even if it cannot be logged
            logger.warning("agent-keys: could not record %s event: %s", kind, exc)

    async def list_tenants(self) -> list[Tenant]:
        # `public` once and first, then every personal and Team schema: startup migrates and
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
