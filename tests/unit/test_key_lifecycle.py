"""Agent Keys expire, can be renewed and revoked, and work only while their owner keeps signing in."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.store import Refused

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
ALICE = "alice@example.com"
BOB = "bob@example.com"
DAY = timedelta(days=1)
# A year back, so every Access token signed for these tests was issued in the past.
START = datetime.now(UTC).replace(microsecond=0) - timedelta(days=365)


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", f"{ALICE},{BOB}")


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now


@pytest.fixture
def keys(team):
    clock, events = Clock(), RecordedEvents()
    config = {"key_pepper": PEPPER, "access_team_domain": team.url, "access_aud": team.aud, "access_host": "k.test"}
    ext = AgentKeysTenantExtension(config, clock=clock, events=events, store=MemoryStore())
    ext.set_context(Migrations())
    return SimpleNamespace(ext=ext, clock=clock, events=events, team=team)


async def sign_in(keys, email, at):
    """The person loads the key page with an Access token issued at `at`."""
    assert await keys.ext.access_email(keys.team.token(email=email, iat=int(at.timestamp()))) == email


async def works(keys, key):
    try:
        await keys.ext.authenticate(RequestContext(api_key=key))
    except AuthenticationError:
        return False
    return True


async def test_a_key_expires_90_days_after_creation(keys):
    _, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    await sign_in(keys, ALICE, START + 89 * DAY)
    keys.clock.now = START + 90 * DAY - timedelta(seconds=1)
    assert await works(keys, key)
    keys.clock.now = START + 90 * DAY
    assert not await works(keys, key)


async def test_a_key_stops_30_days_after_its_owners_last_sign_in_and_works_again_once_they_sign_in(keys):
    _, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    await sign_in(keys, ALICE, START)
    keys.clock.now = START + 30 * DAY - timedelta(seconds=1)
    assert await works(keys, key)
    keys.clock.now = START + 30 * DAY
    assert not await works(keys, key)
    await sign_in(keys, ALICE, keys.clock.now)
    assert await works(keys, key)


async def test_a_key_whose_owner_never_signed_in_is_refused(keys):
    _, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    assert not await works(keys, key)


async def test_a_sign_in_counts_from_when_access_issued_the_token(keys):
    _, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    keys.clock.now = START + 30 * DAY
    # Loading the page now with a token issued 30 days ago is not a fresh sign-in.
    await sign_in(keys, ALICE, START)
    assert not await works(keys, key)


async def test_an_older_token_does_not_move_the_last_sign_in_back(keys):
    _, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    await sign_in(keys, ALICE, START + 20 * DAY)
    await sign_in(keys, ALICE, START)
    keys.clock.now = START + 40 * DAY
    assert await works(keys, key)


async def test_the_owner_can_renew_a_key_for_90_days_from_the_renewal(keys):
    key_id, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    keys.clock.now = START + 60 * DAY
    await keys.ext.renew_key(ALICE, key_id, None)
    await sign_in(keys, ALICE, START + 149 * DAY)
    keys.clock.now = START + 150 * DAY - timedelta(seconds=1)
    assert await works(keys, key)
    keys.clock.now = START + 150 * DAY
    assert not await works(keys, key)


async def test_an_expired_key_cannot_be_renewed(keys):
    key_id, _ = await keys.ext.create_personal_key(ALICE, "laptop", None)
    keys.clock.now = START + 90 * DAY
    with pytest.raises(Refused) as refusal:
        await keys.ext.renew_key(ALICE, key_id, None)
    assert refusal.value.status == 404


async def test_a_revoked_key_is_refused_on_its_next_request_and_cannot_be_renewed(keys):
    key_id, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    _, other = await keys.ext.create_personal_key(ALICE, "desktop", None)
    await sign_in(keys, ALICE, START)
    assert await works(keys, key)
    await keys.ext.revoke_key(ALICE, key_id, None)
    assert not await works(keys, key)
    assert await works(keys, other)
    with pytest.raises(Refused):
        await keys.ext.renew_key(ALICE, key_id, None)


async def test_nobody_but_the_owner_can_renew_or_revoke_a_key(keys):
    key_id, key = await keys.ext.create_personal_key(ALICE, "laptop", None)
    await sign_in(keys, ALICE, START)
    for change in (keys.ext.renew_key, keys.ext.revoke_key):
        with pytest.raises(Refused) as refusal:
            await change(BOB, key_id, None)
        assert refusal.value.status == 404
    assert await works(keys, key)
    keys.clock.now = START + 90 * DAY
    await sign_in(keys, ALICE, keys.clock.now)
    assert not await works(keys, key)


async def test_the_owner_lists_only_their_own_keys_each_with_its_state(keys):
    laptop, _ = await keys.ext.create_personal_key(ALICE, "laptop", None)
    keys.clock.now = START + DAY
    desktop, _ = await keys.ext.create_personal_key(ALICE, "desktop", None)
    phone, _ = await keys.ext.create_personal_key(ALICE, "phone", None)
    await keys.ext.create_personal_key(BOB, "laptop", None)
    await keys.ext.revoke_key(ALICE, desktop, None)
    keys.clock.now = START + 90 * DAY
    assert [(k["id"], k["name"], k["state"], k["expires_at"]) for k in await keys.ext.list_keys(ALICE)] == [
        (laptop, "laptop", "expired", START + 90 * DAY),
        (desktop, "desktop", "revoked", START + 91 * DAY),
        (phone, "phone", "active", START + 91 * DAY),
    ]


async def test_renewals_and_revocations_are_logged_with_the_key_its_owner_and_the_client_ip(keys):
    key_id, _ = await keys.ext.create_personal_key(ALICE, "laptop", None)
    await keys.ext.renew_key(ALICE, key_id, "203.0.113.7")
    await keys.ext.revoke_key(ALICE, key_id, "203.0.113.8")
    assert [(r["kind"], r["key_id"], r["email"], r["client_ip"]) for r in keys.events.rows[1:]] == [
        ("key_renewed", key_id, ALICE, "203.0.113.7"),
        ("key_revoked", key_id, ALICE, "203.0.113.8"),
    ]


async def test_an_admin_revoking_an_identity_disables_every_key_the_person_holds(keys):
    _, laptop = await keys.ext.create_personal_key(BOB, "laptop", None)
    _, desktop = await keys.ext.create_personal_key(BOB, "desktop", None)
    _, alices = await keys.ext.create_personal_key(ALICE, "laptop", None)
    for person in (ALICE, BOB):
        await sign_in(keys, person, START)
    assert await keys.ext.revoke_identity(ALICE, BOB, "203.0.113.9") == 2
    assert not await works(keys, laptop)
    assert not await works(keys, desktop)
    assert await works(keys, alices)
    logged = {"kind": "identity_revoked", "key_id": "(none)", "client_ip": "203.0.113.9", "email": BOB, "actor": ALICE, "team": None}
    assert logged in keys.events.rows


async def test_only_an_admin_can_revoke_an_identity(keys):
    _, key = await keys.ext.create_personal_key(BOB, "laptop", None)
    await sign_in(keys, BOB, START)
    with pytest.raises(Refused) as refusal:
        await keys.ext.revoke_identity("mallory@example.com", BOB, None)
    assert refusal.value.status == 403
    assert await works(keys, key)


async def test_an_admin_granted_on_the_admin_page_can_revoke_an_identity(keys):
    await keys.ext.set_role(ALICE, "carol@example.com", "admin", None)
    await keys.ext.create_personal_key(BOB, "laptop", None)
    assert await keys.ext.revoke_identity("carol@example.com", BOB, None) == 1


async def test_revoking_an_identity_also_disables_the_team_keys_the_person_holds(keys):
    _, team_key = await keys.ext.create_team_key(BOB, "public", "ci", None)
    await sign_in(keys, BOB, START)
    assert await works(keys, team_key)
    assert await keys.ext.revoke_identity(ALICE, BOB, None) == 1
    assert not await works(keys, team_key)
