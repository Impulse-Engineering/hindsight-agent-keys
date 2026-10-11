"""The tenant extension serves the Public Team to the legacy key and refuses every other key."""

from datetime import datetime, timedelta

import pytest
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext

from hindsight_agent_keys.extension import AgentKeysTenantExtension

LEGACY = "legacy-key-0123456789abcdef0123456789abcdef"


def extension(clock=None, **config):
    return AgentKeysTenantExtension({"legacy_key": LEGACY, **config}, clock=clock)


async def test_legacy_key_reaches_the_public_schema():
    ctx = RequestContext(api_key=LEGACY)
    tenant = await extension().authenticate(ctx)
    assert tenant.schema_name == "public"


@pytest.mark.parametrize("key", [None, "", "wrong-key", LEGACY + "x", LEGACY[:-1]])
async def test_any_other_key_is_refused(key):
    with pytest.raises(AuthenticationError):
        await extension().authenticate(RequestContext(api_key=key))


async def test_without_a_legacy_key_every_key_is_refused():
    ext = AgentKeysTenantExtension({})
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=""))
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=None))


async def test_legacy_key_is_identified_in_the_request_context():
    ctx = RequestContext(api_key=LEGACY)
    await extension().authenticate(ctx)
    assert ctx.api_key_id == "legacy"


async def test_tenant_list_is_the_public_schema():
    tenants = await extension().list_tenants()
    assert [t.schema for t in tenants] == ["public"]


async def test_banks_cannot_switch_on_upstream_audit_logging():
    allowed = await extension().get_allowed_config_fields(RequestContext(api_key=LEGACY), "any-bank")
    assert "audit_log_enabled" not in allowed
    assert {"retain_mission", "mcp_enabled_tools", "store_document_text"} <= allowed


def at(text):
    return lambda: datetime.fromisoformat(text)


async def test_legacy_key_works_until_its_expiry():
    ext = extension(legacy_key_expires="2026-11-10", clock=at("2026-11-09T23:59:59+00:00"))
    tenant = await ext.authenticate(RequestContext(api_key=LEGACY))
    assert tenant.schema_name == "public"


@pytest.mark.parametrize("now", ["2026-11-10T00:00:00+00:00", "2027-01-01T00:00:00+00:00"])
async def test_legacy_key_is_refused_from_its_expiry(now):
    ext = extension(legacy_key_expires="2026-11-10", clock=at(now))
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key=LEGACY))


def test_an_unreadable_expiry_stops_startup():
    with pytest.raises(ValueError):
        extension(legacy_key_expires="next month")


class RecordedEvents:
    def __init__(self, fail=False):
        self.rows = []
        self.fail = fail

    async def start(self, db_url):
        pass

    async def stop(self):
        pass

    async def record(self, kind, key_id, client_ip):
        if self.fail:
            raise RuntimeError("event store unavailable")
        self.rows.append({"kind": kind, "key_id": key_id, "client_ip": client_ip})


class Clock:
    def __init__(self, text="2026-10-11T12:00:00+00:00"):
        self.now = datetime.fromisoformat(text)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def watched(clock=None, **config):
    events = RecordedEvents()
    ext = AgentKeysTenantExtension({"legacy_key": LEGACY, **config}, clock=clock or Clock(), events=events)
    return ext, events


def request(key, ip="203.0.113.7"):
    return RequestContext(api_key=key, extra_headers={"x-real-ip": ip} if ip else {})


async def refuse(ext, ctx):
    with pytest.raises(AuthenticationError):
        await ext.authenticate(ctx)


async def test_a_refused_key_is_recorded_with_the_client_ip():
    ext, events = watched()
    await refuse(ext, request("not-a-key"))
    assert events.rows == [{"kind": "key_refused", "key_id": "unrecognized", "client_ip": "203.0.113.7"}]


async def test_a_missing_key_is_recorded_as_missing():
    ext, events = watched()
    await refuse(ext, request(None))
    assert [r["key_id"] for r in events.rows] == ["missing"]


async def test_an_agent_key_is_recorded_by_its_id_never_its_secret():
    ext, events = watched()
    secret = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5"
    await refuse(ext, request(f"hsk_k7Q2mX9a_{secret}"))
    assert [r["key_id"] for r in events.rows] == ["k7Q2mX9a"]
    assert secret not in repr(events.rows)


async def test_an_unknown_client_ip_is_recorded_as_none():
    ext, events = watched()
    await refuse(ext, request("not-a-key", ip=None))
    assert events.rows[0]["client_ip"] is None


async def test_repeat_refusals_from_one_ip_are_recorded_once_a_minute():
    clock = Clock()
    ext, events = watched(clock=clock)
    await refuse(ext, request("not-a-key"))
    await refuse(ext, request("not-a-key"))
    clock.advance(59)
    await refuse(ext, request("not-a-key"))
    assert len(events.rows) == 1
    clock.advance(1)
    await refuse(ext, request("not-a-key"))
    assert len(events.rows) == 2


async def test_rotating_key_ids_from_one_ip_does_not_add_rows():
    ext, events = watched()
    for n in range(20):
        await refuse(ext, request(f"hsk_rotating{n}_" + "z" * 43))
    assert len(events.rows) == 1


@pytest.mark.parametrize("header", ["not-an-ip", "203.0.113.7, 198.51.100.9", "x" * 500])
async def test_a_client_ip_that_is_not_an_address_is_recorded_as_none(header):
    ext, events = watched()
    await refuse(ext, request("not-a-key", ip=header))
    assert events.rows[0]["client_ip"] is None


async def test_an_ipv6_client_ip_is_recorded_in_canonical_form():
    ext, events = watched()
    await refuse(ext, request("not-a-key", ip="2001:DB8:0:0::1"))
    assert events.rows[0]["client_ip"] == "2001:db8::1"


async def test_refusals_from_different_ips_are_recorded_separately():
    ext, events = watched()
    await refuse(ext, request("not-a-key", ip="203.0.113.7"))
    await refuse(ext, request("not-a-key", ip="198.51.100.9"))
    assert [r["client_ip"] for r in events.rows] == ["203.0.113.7", "198.51.100.9"]


async def test_an_expired_legacy_key_is_recorded_as_expired():
    ext, events = watched(clock=Clock("2026-12-01T00:00:00+00:00"), legacy_key_expires="2026-11-10")
    await refuse(ext, request(LEGACY))
    assert [(r["kind"], r["key_id"]) for r in events.rows] == [("legacy_key_expired", "legacy")]


async def test_an_accepted_key_records_nothing():
    ext, events = watched()
    await ext.authenticate(request(LEGACY))
    assert events.rows == []


async def test_a_failing_event_store_still_refuses_the_key():
    events = RecordedEvents(fail=True)
    ext = AgentKeysTenantExtension({"legacy_key": LEGACY}, clock=Clock(), events=events)
    await refuse(ext, request("not-a-key"))


async def test_addresses_in_one_ipv6_64_are_throttled_as_one_client():
    ext, events = watched()
    for n in range(1, 30):
        await refuse(ext, request("not-a-key", ip=f"2001:db8:0:0::{n:x}"))
    assert len(events.rows) == 1


async def test_refusal_rows_are_capped_per_minute_across_all_clients():
    clock = Clock()
    ext, events = watched(clock=clock)
    for n in range(200):
        await refuse(ext, request("not-a-key", ip=f"198.51.{n // 250}.{n % 250}"))
    assert len(events.rows) == 60
    clock.advance(60)
    await refuse(ext, request("not-a-key", ip="203.0.113.99"))
    assert len(events.rows) == 61
