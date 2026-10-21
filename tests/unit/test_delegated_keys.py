"""A Delegate (WorkPlane) creates, lists, renews and revokes the signed-in person's own keys, marked as
created via WorkPlane; the person sees them, and can revoke them, on the key page."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import ACCESS_HOST, DELEGATE_ID, delegated_app, delegated_headers

from hindsight_agent_keys.store import Refused

ALICE = "alice@example.com"
BOB = "bob@example.com"
KEYS = "/ext/delegated/keys"
DAY = timedelta(days=1)
# A year back, so every Access token signed for these tests was issued in the past.
START = datetime.now(UTC).replace(microsecond=0) - timedelta(days=365)


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now


def issued(at):
    """Claims of an Access JWT issued at `at`: the sign-in it records."""
    return {"iat": int(at.timestamp())}


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", "admin@example.com")


def on_the_key_page(team, email=ALICE, **claims):
    """A request from the person on /ext, as the key page's script sends it."""
    return {
        "Host": ACCESS_HOST,
        "Cf-Access-Jwt-Assertion": team.token(email=email, **claims),
        "Content-Type": "application/json",
        "X-Agent-Keys": "1",
        "Origin": f"https://{ACCESS_HOST}",
    }


def create(client, team, name="workplane", idempotency_key="k1", email=ALICE, **claims):
    headers = {**delegated_headers(team, email, **claims), "Idempotency-Key": idempotency_key}
    return client.post(KEYS, json={"name": name}, headers=headers)


async def test_a_delegate_creates_a_key_marked_via_workplane_that_the_person_sees_and_revokes_on_the_key_page(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    resp = create(client, team)
    assert resp.status_code == 200, resp.text
    created = resp.json()
    assert (created["name"], resp.headers["cache-control"]) == ("workplane", "no-store")
    assert (await ext.principal(created["key"])).email == ALICE
    listed = client.get("/ext/keys", headers=on_the_key_page(team)).json()
    assert [(k["id"], k["via"], k["state"]) for k in listed] == [(created["id"], DELEGATE_ID, "active")]
    assert client.post(f"/ext/keys/{created['id']}/revoke", headers=on_the_key_page(team)).status_code == 200
    assert await ext.principal(created["key"]) is None
    assert [(r["kind"], r["email"], r["actor"], r["channel"], r["delegate"]) for r in events.rows] == [
        ("key_created", ALICE, ALICE, "delegated", DELEGATE_ID),
        ("key_revoked", ALICE, ALICE, "ext", None),
    ]


def seed(store, email, count, via=None):
    """`count` active keys the person created over an hour ago, so only the cap on active keys counts them."""
    store.people.setdefault(email, None)
    now = datetime.now(UTC)
    for _ in range(count):
        key_id = f"seed{len(store.keys)}"
        store.keys[key_id] = {
            "id": key_id, "digest": b"", "name": "earlier", "email": email, "schema": "p_0", "kind": "personal",
            "created_at": now - timedelta(hours=2), "expires_at": now + timedelta(days=30), "revoked_at": None, "via": via,
        }


def test_the_person_holds_25_active_workplane_keys_apart_from_their_own_10(team):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    seed(ext._store, ALICE, 24, via=DELEGATE_ID)
    seed(ext._store, ALICE, 9)
    assert create(client, team, idempotency_key="a").status_code == 200
    resp = create(client, team, idempotency_key="b")
    assert (resp.status_code, resp.json()["detail"]) == (429, "You already hold 25 active keys created via WorkPlane.")
    # The person's own keys are counted apart: the key page still creates their tenth, and no more.
    own = [client.post("/ext/keys", json={"name": "own"}, headers=on_the_key_page(team)).status_code for _ in range(2)]
    assert own == [200, 429]


def test_the_workplane_cap_and_hourly_limit_are_settings(team):
    client, ext, _ = delegated_app(team, workplane_active_keys=" 2 ", workplane_keys_per_hour="3")
    ext._store.roles[ALICE] = "member"
    ids = [create(client, team, idempotency_key=n).json().get("id") for n in "ab"]
    resp = create(client, team, idempotency_key="c")
    assert (resp.status_code, resp.json()["detail"]) == (429, "You already hold 2 active keys created via WorkPlane.")
    for key_id in ids:
        assert client.post(f"/ext/keys/{key_id}/revoke", headers=on_the_key_page(team)).status_code == 200
    assert create(client, team, idempotency_key="d").status_code == 200
    resp = create(client, team, idempotency_key="e")
    assert (resp.status_code, resp.json()["detail"]) == (429, "You can create at most 3 keys created via WorkPlane an hour.")


def test_workplane_onboarding_is_not_held_up_by_the_persons_own_5_an_hour(team):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    own = [client.post("/ext/keys", json={"name": "own"}, headers=on_the_key_page(team)).status_code for _ in range(6)]
    assert own == [200] * 5 + [429]
    assert [create(client, team, idempotency_key=str(n)).status_code for n in range(6)] == [200] * 6


@pytest.mark.parametrize("value", ["-1", "ten", "2.5", "1_0", "25 keys"])
@pytest.mark.parametrize("setting", ["workplane_active_keys", "workplane_keys_per_hour"])
def test_a_workplane_limit_that_is_not_a_whole_number_stops_startup(team, setting, value):
    with pytest.raises(ValueError, match=setting.upper()):
        delegated_app(team, **{setting: value})


async def test_lowering_the_cap_revokes_nothing_and_refuses_only_new_creations(team):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    keys = [create(client, team, idempotency_key=n).json()["key"] for n in "abc"]
    lowered, ext, _ = delegated_app(team, ext._store, workplane_active_keys="1")
    listed = lowered.get("/ext/keys", headers=on_the_key_page(team)).json()
    assert [k["state"] for k in listed] == ["active"] * 3
    assert [(await ext.principal(key)).email for key in keys] == [ALICE] * 3
    assert create(lowered, team, idempotency_key="d").status_code == 429


def test_a_repeated_creation_returns_the_same_key_id_without_the_key_and_another_body_is_refused(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    first = create(client, team, idempotency_key="onboarding").json()
    again = create(client, team, idempotency_key="onboarding")
    assert (again.status_code, again.json()) == (200, {"id": first["id"], "name": "workplane"})
    assert create(client, team, name="another", idempotency_key="onboarding").status_code == 409
    # Scoped to (Delegate, person): another person, or another Delegate, gets a key of their own.
    bobs = create(client, team, idempotency_key="onboarding", email=BOB).json()
    other, _, _ = delegated_app(team, ext._store, delegate_client_id="other.access")
    theirs = create(other, team, idempotency_key="onboarding", delegate={"common_name": "other.access"}).json()
    assert ("key" in bobs, "key" in theirs, len({first["id"], bobs["id"], theirs["id"]})) == (True, True, 3)
    assert [(r["kind"], r["email"]) for r in events.rows] == [("key_created", ALICE), ("key_created", BOB)]


def test_an_idempotency_key_is_kept_for_24_hours(team):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    first = create(client, team, idempotency_key="onboarding").json()
    for row in ext._store.idempotency.values():
        row["created_at"] -= timedelta(hours=24)
    again = create(client, team, idempotency_key="onboarding").json()
    assert "key" in again and again["id"] != first["id"]


@pytest.mark.parametrize("idempotency_key", [None, "", "k" * 201])
def test_a_creation_needs_an_idempotency_key(team, idempotency_key):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    headers = {k: v for k, v in {**delegated_headers(team), "Idempotency-Key": idempotency_key}.items() if v is not None}
    assert client.post(KEYS, json={"name": "workplane"}, headers=headers).status_code == 422
    assert (ext._store.keys, events.rows) == ({}, [])


def test_delegated_list_renew_and_revoke_reach_only_the_persons_own_workplane_keys(team):
    client, ext, events = delegated_app(team)
    ext._store.roles.update({ALICE: "member", BOB: "member"})
    mine = create(client, team).json()["id"]
    own = client.post("/ext/keys", json={"name": "own"}, headers=on_the_key_page(team)).json()["id"]
    bobs = create(client, team, email=BOB).json()["id"]
    assert [k["id"] for k in client.get(KEYS, headers=delegated_headers(team)).json()] == [mine]
    for key_id in (own, bobs):
        for action in ("renew", "revoke"):
            assert client.post(f"{KEYS}/{key_id}/{action}", headers=delegated_headers(team)).status_code == 404
    assert {k["id"]: k["revoked_at"] for k in ext._store.keys.values()} == dict.fromkeys((mine, own, bobs))
    assert [r["kind"] for r in events.rows] == ["key_created"] * 3


def test_each_key_shows_days_to_expiry_and_renewal_sets_expiry_90_days_from_the_renewal(team):
    clock = Clock()
    client, ext, events = delegated_app(team, clock=clock)
    ext._store.roles[ALICE] = "member"
    key_id = create(client, team, person=issued(START)).json()["id"]

    def listed():
        keys = client.get(KEYS, headers=delegated_headers(team, person=issued(clock.now))).json()
        return [(k["id"], datetime.fromisoformat(k["expires_at"]), k["days_to_expiry"]) for k in keys]

    assert listed() == [(key_id, START + 90 * DAY, 90)]
    clock.now = START + 80 * DAY + timedelta(hours=1)
    assert listed() == [(key_id, START + 90 * DAY, 10)]
    # Renewing again at once still ends 90 days from the renewal, never later.
    for _ in range(2):
        resp = client.post(f"{KEYS}/{key_id}/renew", headers=delegated_headers(team, person=issued(clock.now)))
        assert resp.status_code == 200, resp.text
        assert datetime.fromisoformat(resp.json()["expires_at"]) == clock.now + 90 * DAY
    assert listed() == [(key_id, clock.now + 90 * DAY, 90)]
    assert [(r["kind"], r["channel"]) for r in events.rows] == [("key_created", "delegated")] + [("key_renewed", "delegated")] * 2


@pytest.mark.parametrize("channel", ["delegated", "ext"])
def test_renewal_is_refused_once_the_30_day_sign_in_window_has_closed(team, channel):
    clock = Clock()
    client, ext, _ = delegated_app(team, clock=clock)
    ext._store.roles[ALICE] = "member"
    key_id = create(client, team, person=issued(START)).json()["id"]
    clock.now = START + 30 * DAY

    def renew(signed_in_at):
        if channel == "delegated":
            return client.post(f"{KEYS}/{key_id}/renew", headers=delegated_headers(team, person=issued(signed_in_at)))
        return client.post(f"/ext/keys/{key_id}/renew", headers=on_the_key_page(team, **issued(signed_in_at)))

    resp = renew(START)
    assert (resp.status_code, ext._store.keys[key_id]["expires_at"]) == (403, START + 90 * DAY)
    assert "sign" in resp.json()["detail"]
    # Signing in again opens the window, and the renewal with it.
    assert renew(clock.now).status_code == 200


async def test_a_repeated_revoke_answers_the_current_state_and_is_recorded_once(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    key = create(client, team).json()
    for _ in range(2):
        resp = client.post(f"{KEYS}/{key['id']}/revoke", headers=delegated_headers(team))
        assert (resp.status_code, resp.json()) == (200, {"id": key["id"], "state": "revoked"})
    assert await ext.principal(key["key"]) is None
    assert [r["kind"] for r in events.rows] == ["key_created", "key_revoked"]


def test_a_revoke_refused_for_another_reason_answers_that_refusal(team, monkeypatch):
    client, ext, _ = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    key_id = create(client, team).json()["id"]

    async def unavailable(*args, **kwargs):
        raise Refused(503, "Try again later.")

    monkeypatch.setattr(ext._store, "revoke_keys", unavailable)
    resp = client.post(f"{KEYS}/{key_id}/revoke", headers=delegated_headers(team))
    assert (resp.status_code, resp.json()) == (503, {"detail": "Try again later."})
    assert ext._store.keys[key_id]["revoked_at"] is None


def test_every_delegated_key_change_names_the_channel_the_delegate_and_the_person(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    key_id = create(client, team).json()["id"]
    for action in ("renew", "revoke"):
        assert client.post(f"{KEYS}/{key_id}/{action}", headers=delegated_headers(team)).status_code == 200
    assert [(r["kind"], r["key_id"], r["email"], r["actor"], r["channel"], r["delegate"]) for r in events.rows] == [
        (kind, key_id, ALICE, ALICE, "delegated", DELEGATE_ID) for kind in ("key_created", "key_renewed", "key_revoked")
    ]


def test_a_revoked_key_has_no_days_to_expiry_and_an_expired_one_has_none_left(team):
    clock = Clock()
    client, ext, _ = delegated_app(team, clock=clock)
    ext._store.roles[ALICE] = "member"
    revoked, expired = (create(client, team, idempotency_key=n, person=issued(START)).json()["id"] for n in "ab")
    assert client.post(f"{KEYS}/{revoked}/revoke", headers=delegated_headers(team)).status_code == 200
    clock.now = START + 90 * DAY
    # WorkPlane renews keys near expiry, so a revoked key must not look like one; the key page shows the same.
    on_the_page = client.get("/ext/keys", headers=on_the_key_page(team)).json()
    delegated = client.get(KEYS, headers=delegated_headers(team)).json()
    for listed in (on_the_page, delegated):
        assert {k["id"]: (k["state"], k["days_to_expiry"]) for k in listed} == {
            revoked: ("revoked", None),
            expired: ("expired", 0),
        }


def test_a_retry_after_an_unrecorded_creation_returns_the_key_and_records_nothing(team):
    client, ext, events = delegated_app(team)
    ext._store.roles[ALICE] = "member"
    # The key is stored but its key_created event is not (the event log failed, or the process stopped between them).
    events.fail = True
    key_id = create(client, team).json()["id"]
    events.fail = False
    assert create(client, team).json() == {"id": key_id, "name": "workplane"}
    assert events.rows == []
    assert [k["id"] for k in client.get(KEYS, headers=delegated_headers(team)).json()] == [key_id]
