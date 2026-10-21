"""Admins manage the Key Allowlist; people not on it can ask to join."""

from datetime import UTC, datetime

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.store import Refused

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
ADMIN = "alice@example.com"
CAROL = "carol@example.com"
DAVE = "dave@example.com"
ERIN = "erin@example.com"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


def extension():
    store, events = MemoryStore(), RecordedEvents()
    # Everyone has just signed in through Access; test_key_lifecycle covers sign-ins.
    store.sign_ins.update(dict.fromkeys((ADMIN, CAROL, DAVE, ERIN), datetime.now(UTC)))
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER}, store=store, events=events)
    ext.set_context(Migrations())
    return ext, events


async def works(ext, key):
    try:
        await ext.authenticate(RequestContext(api_key=key))
    except AuthenticationError:
        return False
    return True


async def test_someone_an_admin_adds_can_create_keys():
    ext, _ = extension()
    await ext.set_role(ADMIN, CAROL, "member", None)
    _, key = await ext.create_personal_key(CAROL, "laptop", None)
    assert await works(ext, key)


async def test_removing_someone_stops_them_creating_keys_and_disables_the_keys_they_hold():
    ext, _ = extension()
    await ext.set_role(ADMIN, CAROL, "member", None)
    _, key = await ext.create_personal_key(CAROL, "laptop", None)
    await ext.set_role(ADMIN, CAROL, None, None)
    assert not await works(ext, key)
    assert await ext.principal(key) is None
    with pytest.raises(Refused) as refusal:
        await ext.create_personal_key(CAROL, "desktop", None)
    assert refusal.value.status == 403
    # Disabled, not deleted: adding them back brings their keys back.
    await ext.set_role(ADMIN, CAROL, "member", None)
    assert await works(ext, key)


async def test_someone_removed_still_lists_and_revokes_their_keys_and_asks_to_be_added_back():
    ext, events = extension()
    await ext.set_role(ADMIN, CAROL, "member", None)
    key_id, _ = await ext.create_personal_key(CAROL, "laptop", None)
    await ext.set_role(ADMIN, CAROL, None, None)
    assert [(k["id"], k["state"]) for k in await ext.list_keys(CAROL)] == [(key_id, "active")]
    await ext.request_access(CAROL, None)
    assert (CAROL, "requested") in await ext.allowlist()
    await ext.revoke_key(CAROL, key_id, None)
    assert [(k["id"], k["state"]) for k in await ext.list_keys(CAROL)] == [(key_id, "revoked")]
    assert [(r["kind"], r["email"]) for r in events.rows[-2:]] == [("access_requested", CAROL), ("key_revoked", CAROL)]


async def test_someone_not_on_the_list_asks_to_join_and_an_admin_approves():
    ext, _ = extension()
    await ext.request_access(CAROL, None)
    assert (CAROL, "requested") in await ext.allowlist()
    with pytest.raises(Refused):
        await ext.create_personal_key(CAROL, "laptop", None)
    await ext.set_role(ADMIN, CAROL, "member", None)
    assert (CAROL, "member") in await ext.allowlist()
    _, key = await ext.create_personal_key(CAROL, "laptop", None)
    assert await works(ext, key)


async def test_an_admin_declines_a_request():
    ext, _ = extension()
    await ext.request_access(CAROL, None)
    await ext.set_role(ADMIN, CAROL, None, None)
    assert await ext.role(CAROL) is None
    assert await ext.allowlist() == [(ADMIN, "admin")]


async def test_an_admin_grants_and_removes_admin_rights():
    ext, _ = extension()
    await ext.set_role(ADMIN, CAROL, "admin", None)
    assert await ext.role(CAROL) == "admin"
    await ext.set_role(ADMIN, CAROL, "member", None)
    assert await ext.role(CAROL) == "member"


@pytest.mark.parametrize("role", [None, "member", "admin"])
async def test_the_bootstrap_admins_cannot_be_changed_from_the_page(role):
    ext, _ = extension()
    await ext.set_role(ADMIN, CAROL, "admin", None)
    listed = await ext.allowlist()
    with pytest.raises(Refused) as refusal:
        await ext.set_role(CAROL, ADMIN, role, None)
    assert refusal.value.status == 409
    assert "AGENT_KEYS_ADMIN_EMAILS" in str(refusal.value)
    assert await ext.allowlist() == listed


async def test_every_change_is_logged_with_whom_it_concerns_and_who_made_it():
    ext, events = extension()
    await ext.request_access(CAROL, "203.0.113.9")
    await ext.request_access(CAROL, "203.0.113.9")
    await ext.set_role(ADMIN, CAROL, "member", "203.0.113.1")
    await ext.set_role(ADMIN, CAROL, "admin", None)
    await ext.set_role(ADMIN, CAROL, "member", None)
    await ext.set_role(ADMIN, CAROL, "member", None)
    await ext.set_role(ADMIN, CAROL, None, None)
    await ext.set_role(ADMIN, DAVE, "member", None)
    await ext.request_access(ERIN, None)
    await ext.set_role(ADMIN, ERIN, None, None)
    # Asking twice, or setting the role someone already has, changes nothing and logs nothing.
    assert [(r["kind"], r["email"], r["actor"]) for r in events.rows] == [
        ("access_requested", CAROL, CAROL),
        ("access_approved", CAROL, ADMIN),
        ("admin_granted", CAROL, ADMIN),
        ("admin_removed", CAROL, ADMIN),
        ("allowlist_removed", CAROL, ADMIN),
        ("allowlist_added", DAVE, ADMIN),
        ("access_requested", ERIN, ERIN),
        ("access_declined", ERIN, ADMIN),
    ]
    assert [r["client_ip"] for r in events.rows[:2]] == ["203.0.113.9", "203.0.113.1"]
    assert {r["key_id"] for r in events.rows} == {"(none)"}


@pytest.mark.parametrize(("email", "role"), [(CAROL, "member"), (CAROL, "admin"), (ADMIN, "admin")])
async def test_asking_to_join_changes_nothing_for_someone_already_on_the_list(email, role):
    ext, _ = extension()
    if email != ADMIN:
        await ext.set_role(ADMIN, email, role, None)
    await ext.request_access(email, None)
    assert await ext.role(email) == role
    assert [r for r in await ext.allowlist() if r[0] == email] == [(email, role)]
