"""People on the Key Allowlist create personal Agent Keys that reach only their own schema."""

import base64
import hashlib
import hmac
import re
from datetime import UTC, datetime

import pytest
from conftest import MemoryStore, Migrations, RecordedEvents
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.store import Refused

PEPPER = "pepper-0123456789abcdef0123456789abcdef"
LEGACY = "legacy-key-0123456789abcdef0123456789abcdef"
ALICE = "alice@example.com"
BOB = "bob@example.com"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", " Alice@Example.com , bob@example.com,")


def extension(store=None, **config):
    store, migrations, events = store or MemoryStore(), Migrations(), RecordedEvents()
    # Both people have just signed in through Access; test_key_lifecycle covers sign-ins.
    store.sign_ins.update(dict.fromkeys((ALICE, BOB), datetime.now(UTC)))
    ext = AgentKeysTenantExtension({"key_pepper": PEPPER, "legacy_key": LEGACY, **config}, store=store, events=events)
    ext.set_context(migrations)
    return ext, store, migrations, events


async def schema_of(ext, key):
    return (await ext.authenticate(RequestContext(api_key=key))).schema_name


async def refused(ext, key):
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=key))


async def test_a_new_key_reaches_its_owners_own_schema():
    ext, store, migrations, _ = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", None)
    ctx = RequestContext(api_key=key)
    tenant = await ext.authenticate(ctx)
    assert tenant.schema_name == store.people[ALICE]
    assert migrations.schemas == [tenant.schema_name]
    assert ctx.api_key_id == key_id


async def test_a_key_acts_as_its_owner():
    ext, store, _, _ = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", None)
    principal = await ext.principal(key)
    assert (principal.kind, principal.email, principal.key_id) == ("personal", ALICE, key_id)
    assert principal.schema == store.people[ALICE]


async def test_a_key_has_an_id_and_a_256_bit_secret():
    ext, _, _, _ = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", None)
    match = re.fullmatch(r"hsk_([A-Za-z0-9]{1,32})_([A-Za-z0-9_-]+)", key)
    assert match and match.group(1) == key_id
    assert len(base64.urlsafe_b64decode(match.group(2) + "=")) == 32


async def test_a_key_is_stored_only_as_an_hmac_with_the_pepper():
    ext, store, _, _ = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", None)
    secret = key.split("_", 2)[2]
    assert secret not in repr(store.keys)
    assert store.keys[key_id]["digest"] == hmac.new(PEPPER.encode(), key.encode(), hashlib.sha256).digest()


async def test_a_key_with_the_wrong_secret_or_an_unknown_id_is_refused():
    ext, _, _, _ = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", None)
    await refused(ext, key[:-1] + ("A" if key[-1] != "A" else "B"))
    await refused(ext, f"hsk_{key_id}_")
    await refused(ext, key.replace(key_id, "0" * len(key_id)))


async def test_two_people_get_separate_schemas_and_each_keeps_one():
    ext, _, migrations, _ = extension()
    _, alice1 = await ext.create_personal_key(ALICE, "laptop", None)
    _, alice2 = await ext.create_personal_key(ALICE, "desktop", None)
    _, bob = await ext.create_personal_key(BOB, "laptop", None)
    assert await schema_of(ext, alice1) == await schema_of(ext, alice2)
    assert await schema_of(ext, alice1) != await schema_of(ext, bob)
    assert len(migrations.schemas) == 2


async def test_a_personal_schema_id_is_generated_never_derived_from_the_email():
    ext, store, _, _ = extension()
    await ext.create_personal_key(ALICE, "laptop", None)
    schema = store.people[ALICE]
    assert re.fullmatch(r"p_[0-9a-f]{16}", schema)
    assert "alice" not in schema


async def test_people_not_on_the_key_allowlist_cannot_create_keys():
    ext, store, migrations, _ = extension()
    with pytest.raises(Refused) as refusal:
        await ext.create_personal_key("mallory@example.com", "laptop", None)
    assert refusal.value.status == 403
    assert (store.people, store.keys, migrations.schemas) == ({}, {}, [])


async def test_without_a_pepper_no_key_is_created_and_agent_keys_are_refused_but_legacy_works():
    ext, store, _, _ = extension()
    _, key = await ext.create_personal_key(ALICE, "laptop", None)
    unpeppered, _, _, _ = extension(store, key_pepper="")
    await refused(unpeppered, key)
    with pytest.raises(Refused) as refusal:
        await unpeppered.create_personal_key(ALICE, "laptop", None)
    assert refusal.value.status == 503
    assert await schema_of(unpeppered, LEGACY) == "public"


async def test_a_different_pepper_refuses_every_existing_key():
    ext, store, _, _ = extension()
    _, key = await ext.create_personal_key(ALICE, "laptop", None)
    rotated, _, _, _ = extension(store, key_pepper="another-pepper-0123456789abcdef01234567")
    await refused(rotated, key)


def test_a_pepper_shorter_than_32_bytes_stops_startup():
    with pytest.raises(ValueError):
        extension(key_pepper="x" * 31)


async def test_key_creation_is_recorded_with_the_key_id_person_and_client_ip():
    ext, _, _, events = extension()
    key_id, key = await ext.create_personal_key(ALICE, "laptop", "203.0.113.7")
    assert events.rows == [
        {
            "kind": "key_created", "key_id": key_id, "client_ip": "203.0.113.7", "email": ALICE, "actor": ALICE,
            "team": None, "channel": None, "delegate": None,
        }
    ]
    assert key.split("_", 2)[2] not in repr(events.rows)


async def test_tenants_are_public_first_then_every_personal_schema():
    ext, store, _, _ = extension()
    assert [t.schema for t in await ext.list_tenants()] == ["public"]
    await ext.create_personal_key(ALICE, "laptop", None)
    await ext.create_personal_key(BOB, "laptop", None)
    assert [t.schema for t in await ext.list_tenants()] == ["public", store.people[ALICE], store.people[BOB]]


async def test_listing_tenants_fails_at_startup_if_the_database_does():
    ext, store, _, _ = extension()
    store.fail = True
    with pytest.raises(OSError):
        await ext.list_tenants()


async def test_listing_tenants_keeps_the_last_list_when_the_database_fails_later():
    ext, store, _, _ = extension()
    await ext.create_personal_key(ALICE, "laptop", None)
    listed = [t.schema for t in await ext.list_tenants()]
    store.fail = True
    assert [t.schema for t in await ext.list_tenants()] == listed
