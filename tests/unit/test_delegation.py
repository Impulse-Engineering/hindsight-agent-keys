"""A Delegate (WorkPlane) acts for a signed-in person only with both credentials, each verified on its own,
and only as the person the second one names."""

import time
from datetime import UTC, datetime

import pytest
from conftest import (
    ACCESS_HOST,
    AUD,
    DELEGATE_ID,
    DELEGATION_AUD,
    DELEGATION_HOST,
    WORKPLANE_AUD,
    MemoryStore,
    delegated_app,
    delegated_headers,
)

ALICE = "alice@example.com"
REQUESTS = "/ext/delegated/access-requests"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", "admin@example.com")


def logged(events):
    return [(r["kind"], r["email"], r["actor"], r["channel"], r["delegate"]) for r in events.rows]


def test_a_delegate_files_a_key_allowlist_request_for_the_signed_in_person(team):
    client, _, events = delegated_app(team)
    resp = client.post(REQUESTS, headers=delegated_headers(team, "Alice@Example.com"))
    assert (resp.status_code, resp.json()) == (200, {"email": ALICE, "role": "requested"})
    assert logged(events) == [("access_requested", ALICE, ALICE, "delegated", DELEGATE_ID)]


def test_a_repeated_request_returns_the_current_state_and_files_nothing_new(team):
    store = MemoryStore()
    store.roles["bob@example.com"] = "member"
    client, _, events = delegated_app(team, store)
    for _ in range(2):
        resp = client.post(REQUESTS, headers=delegated_headers(team))
        assert (resp.status_code, resp.json()) == (200, {"email": ALICE, "role": "requested"})
    resp = client.post(REQUESTS, headers=delegated_headers(team, "bob@example.com"))
    assert (resp.status_code, resp.json()) == (200, {"email": "bob@example.com", "role": "member"})
    assert [r["kind"] for r in events.rows] == ["access_requested"]


def test_identity_headers_and_the_body_cannot_name_another_person(team):
    store = MemoryStore()
    client, _, _ = delegated_app(team, store)
    headers = {**delegated_headers(team), "Cf-Access-Authenticated-User-Email": "bob@example.com"}
    resp = client.post(REQUESTS, headers=headers, json={"email": "bob@example.com"})
    assert resp.json() == {"email": ALICE, "role": "requested"}
    assert store.roles == {ALICE: "requested"}


def refused(client, events, headers, delegate):
    resp = client.post(REQUESTS, headers=headers)
    assert resp.status_code == 403
    # Recorded like a refused key; the Delegate is named only once its own credential held.
    assert logged(events) == [("delegation_refused", None, None, "delegated", delegate)]


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": ["another-application"]},
        {"aud": [AUD]},
        # The audience must be exactly the delegation application's.
        {"aud": [DELEGATION_AUD, "another-application"]},
        {"iss": "https://other-team.cloudflareaccess.com"},
        {"exp": int(time.time()) - 60},
        # A person's JWT for the delegation application in place of the service token.
        {"email": ALICE, "common_name": None, "sub": "0f6a1c2e-person"},
        {"common_name": "someone-else.access"},
        {"common_name": None},
        # Access never issues these, but a token with an email claim, even an empty one, is never the Delegate.
        {"email": ALICE},
        {"email": ""},
    ],
)
def test_a_delegate_credential_that_fails_any_check_is_refused(team, claims):
    store = MemoryStore()
    client, _, events = delegated_app(team, store)
    refused(client, events, delegated_headers(team, delegate=claims), None)
    assert store.roles == {}
    # A refused Delegate's request is not a sign-in either.
    assert store.sign_ins == {}


def test_a_missing_delegate_credential_is_refused(team):
    client, _, events = delegated_app(team)
    headers = delegated_headers(team)
    del headers["Cf-Access-Jwt-Assertion"]
    refused(client, events, headers, None)


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": ["another-application"]},
        # The /ext application's JWT, and the Delegate's own audience, are not WorkPlane's.
        {"aud": [AUD]},
        {"aud": [DELEGATION_AUD]},
        {"aud": [WORKPLANE_AUD, "another-application"]},
        {"iss": "https://other-team.cloudflareaccess.com"},
        {"exp": int(time.time()) - 60},
        {"email": None},
        {"email": ""},
        {"email": "  "},
        {"email": 42},
        {"email": None, "common_name": DELEGATE_ID},
        {"iat": None},
        {"iat": str(int(time.time()))},
    ],
)
def test_a_person_credential_that_fails_any_check_is_refused(team, claims):
    store = MemoryStore()
    client, _, events = delegated_app(team, store)
    refused(client, events, delegated_headers(team, person=claims), DELEGATE_ID)
    assert store.roles == {}


@pytest.mark.parametrize("identity", [{}, {"Cf-Access-Authenticated-User-Email": ALICE}])
def test_a_missing_person_credential_is_refused_whatever_identity_header_comes_with_it(team, identity):
    client, _, events = delegated_app(team)
    headers = {**delegated_headers(team), **identity}
    del headers["X-Delegated-Access-Jwt"]
    refused(client, events, headers, DELEGATE_ID)


def test_refusals_are_throttled_per_client_like_refused_keys(team):
    client, _, events = delegated_app(team)
    headers = {**delegated_headers(team, person={"email": None}), "X-Real-IP": "203.0.113.7"}
    for _ in range(3):
        assert client.post(REQUESTS, headers=headers).status_code == 403
    assert [(r["kind"], r["client_ip"]) for r in events.rows] == [("delegation_refused", "203.0.113.7")]


def test_the_row_marking_a_used_up_refusal_budget_names_no_channel_or_delegate(team):
    client, _, events = delegated_app(team)
    headers = delegated_headers(team, person={"email": None})
    for n in range(61):
        assert client.post(REQUESTS, headers={**headers, "X-Real-IP": f"203.0.113.{n}"}).status_code == 403
    # The budget is shared by every channel's refusals, so its row belongs to none of them.
    assert [(r["kind"], r["channel"], r["delegate"]) for r in events.rows[60:]] == [
        ("refusal_log_saturated", None, None)
    ]


def test_the_person_jwt_dates_the_sign_in_and_an_older_one_does_not_move_it(team):
    store = MemoryStore()
    client, _, _ = delegated_app(team, store)
    hour_ago = int(time.time()) - 3600
    assert client.post(REQUESTS, headers=delegated_headers(team, person={"iat": hour_ago})).status_code == 200
    # Dated by when Access issued the token, not by when the request was made.
    assert store.sign_ins == {ALICE: datetime.fromtimestamp(hour_ago, UTC)}
    assert client.post(REQUESTS, headers=delegated_headers(team, person={"iat": hour_ago - 60})).status_code == 200
    assert store.sign_ins == {ALICE: datetime.fromtimestamp(hour_ago, UTC)}


@pytest.mark.parametrize("host", [ACCESS_HOST, "hindsight-api.example.test", ""])
def test_delegated_requests_answer_only_on_the_delegation_host(team, host):
    client, _, events = delegated_app(team)
    assert client.post(REQUESTS, headers={**delegated_headers(team), "Host": host}).status_code == 404
    assert events.rows == []


@pytest.mark.parametrize(
    "missing", ["access_team_domain", "delegation_host", "delegation_aud", "workplane_aud", "delegate_client_id"]
)
def test_without_full_delegation_configuration_delegated_requests_are_refused(team, missing):
    client, _, _ = delegated_app(team, **{missing: None})
    assert client.post(REQUESTS, headers=delegated_headers(team)).status_code == 404


@pytest.mark.parametrize(
    "blank", ["access_team_domain", "delegation_host", "delegation_aud", "workplane_aud", "delegate_client_id"]
)
def test_a_blank_delegation_setting_turns_delegated_requests_off(team, blank):
    client, _, events = delegated_app(team, **{blank: "   "})
    for host in (DELEGATION_HOST, ""):
        assert client.post(REQUESTS, headers={**delegated_headers(team), "Host": host}).status_code == 404
    assert events.rows == []


def test_the_key_pages_do_not_answer_on_the_delegation_host(team):
    client, _, _ = delegated_app(team)
    assert client.post("/ext/access-requests", headers=delegated_headers(team)).status_code == 404


@pytest.mark.parametrize("content_type", [None, "text/plain"])
def test_a_delegated_state_change_needs_json(team, content_type):
    client, _, events = delegated_app(team)
    headers = {k: v for k, v in {**delegated_headers(team), "Content-Type": content_type}.items() if v is not None}
    assert client.post(REQUESTS, headers=headers).status_code == 403
    assert events.rows == []
