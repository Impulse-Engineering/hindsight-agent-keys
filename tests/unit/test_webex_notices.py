"""Owners, admins and requesters hear of requests and decisions in a Webex direct message: best effort, at most one
message per person per 15 minutes, grouping what arrived meanwhile, and never in the way of the request that caused it.
The Webex client is a fake at its one seam (`send_message`); the real client is in test_webex_client.py."""

import asyncio
import contextlib
import re
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import (
    ACCESS_HOST,
    DELEGATE_ID,
    DELEGATION_AUD,
    DELEGATION_HOST,
    PEPPER,
    WORKPLANE_AUD,
    MemoryStore,
    Migrations,
    RecordedEvents,
    delegated_headers,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_teams_page import as_person

from hindsight_agent_keys import notices
from hindsight_agent_keys.extension import AgentKeysTenantExtension
from hindsight_agent_keys.notices import WebexError, plain
from hindsight_agent_keys.web import AgentKeysHttpExtension

ADMIN = "admin@example.com"  # a bootstrap admin
FRANK = "frank@example.com"  # an admin on the Key Allowlist
ALICE = "alice@example.com"  # owns Platform
BOB = "bob@example.com"  # owns Platform too
CAROL = "carol@example.com"  # a member of Platform
DAVE = "dave@example.com"  # listed, not in Platform
GINA = "gina@example.com"  # listed, not in Platform
HANK = "hank@example.com"  # listed, not in Platform
IVAN = "ivan@example.com"  # listed, not in Platform
ERIN = "erin@example.com"  # not on the Key Allowlist
TEAMS = f"https://{ACCESS_HOST}/ext/teams"
KEYS = f"https://{ACCESS_HOST}/ext/admin"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


class Stopped(BaseException):
    """The process stopping: not an Exception, so nothing in the code under test may catch it."""


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def later(self, **delta):
        self.now += timedelta(**delta)


class Webex:
    """The fake client: records what it is asked to send, then fails or stops as told."""

    def __init__(self):
        self.sent = []  # (to, text)
        self.fail = None  # an exception to raise instead of delivering
        self.stop_before_sending = False
        self.gate = None  # an asyncio.Event a send waits for, to hold it in flight
        self.entered = asyncio.Event()  # set as a send begins
        self.entered_for = []  # everyone a send began for, delivered or not

    async def send_message(self, to_email, text):
        self.entered.set()
        self.entered_for.append(to_email)
        if self.gate:
            await self.gate.wait()
        if self.stop_before_sending:
            raise Stopped
        if self.fail:
            raise self.fail
        self.sent.append((to_email, text))


class NoticeStore(MemoryStore):
    """MemoryStore with the Webex notice tables; the same contract as PostgresKeyStore (tests/integration runs it there)."""

    def __init__(self):
        super().__init__()
        self.queue = []  # (recipient, kind, team, line, path)
        self.log = []  # the send log: id, recipient, at, items, status, detail
        self.optouts = set()
        self.locks = {}  # email -> the person's notice lock
        self.break_on = {}  # method name -> exception it raises
        self.hang = 0.0  # seconds queue_notice takes
        self.opts_out_after_claim = None  # a person whose opt-out commits right after their notices are claimed
        self.after_claim = None  # called with the person, right after their notices are claimed: a change committing then

    def _break(self, name):
        if name in self.break_on:
            raise self.break_on[name]

    async def queue_notice(self, recipients, kind, team, line, path):
        self._break("queue_notice")
        await asyncio.sleep(self.hang)
        self.queue += [(r, kind, team, line, path) for r in recipients]

    async def queued_recipients(self):
        return sorted({q[0] for q in self.queue})

    def _eligible(self, recipient, kind, team, admins):
        listed = recipient in admins or self.roles.get(recipient) in ("member", "admin")
        if kind == "owner":
            return listed and self.team_roles.get((team, recipient)) == "owner"
        return kind != "admin" or recipient in admins or self.roles.get(recipient) == "admin"

    async def claim_notice(self, recipient, now, since, admins):
        if any(row["recipient"] == recipient and row["at"] > since for row in self.log):
            return None
        mine = [q for q in self.queue if q[0] == recipient]
        # A stop here is a stop inside the transaction: it rolls back, and the queue is as it was.
        self._break("claim_notice")
        self.queue = [q for q in self.queue if q[0] != recipient]
        mine = [q for q in mine if self._eligible(recipient, q[1], q[2], admins)]
        if not mine or recipient in self.optouts:
            return None
        row = {"id": len(self.log) + 1, "recipient": recipient, "at": now, "items": len(mine), "status": "sending", "detail": None}
        self.log.append(row)
        if self.opts_out_after_claim == recipient:
            self.optouts.add(recipient)
        if self.after_claim:
            self.after_claim(recipient)
        return row["id"], [(line, path, kind, team) for _, kind, team, line, path in mine]

    async def still_eligible(self, recipient, items, admins):
        return [self._eligible(recipient, kind, team, admins) for _, _, kind, team in items]

    async def finish_notice(self, log_id, status, detail):
        self._break("finish_notice")
        self.log[log_id - 1].update(status=status, detail=detail)

    @contextlib.asynccontextmanager
    async def notice_lock(self, email):
        async with self.locks.setdefault(email, asyncio.Lock()):
            yield

    async def notices_enabled(self, email):
        return email not in self.optouts

    async def set_notices_enabled(self, email, enabled):
        if enabled:
            self.optouts.discard(email)
            return
        async with self.notice_lock(email):
            self.optouts.add(email)


class World:
    """One extension over a fake store, clock and Webex, reached on the Teams page and by Delegated Request."""

    def __init__(self, team, store=None, clock=None, webex=None, **config):
        self.team, self.store, self.clock, self.webex = team, store or NoticeStore(), clock or Clock(), webex or Webex()
        self.events = RecordedEvents()
        self.config = {
            "key_pepper": PEPPER,
            "access_team_domain": team.url,
            "access_aud": team.aud,
            "access_host": ACCESS_HOST,
            "delegation_host": DELEGATION_HOST,
            "delegation_aud": DELEGATION_AUD,
            "workplane_aud": WORKPLANE_AUD,
            "delegate_client_id": DELEGATE_ID,
            "webex_bot_token": "bot-token",
            **config,
        }
        self.ext = AgentKeysTenantExtension(
            {k: v for k, v in self.config.items() if v is not None},
            store=self.store,
            events=self.events,
            clock=self.clock,
            webex=self.webex,
        )
        self.ext.set_context(Migrations())
        app = FastAPI()
        app.include_router(AgentKeysHttpExtension({}).get_router(SimpleNamespace(tenant_extension=self.ext)), prefix="/ext")
        self.client = TestClient(app)

    async def start(self):
        self.store.roles.update({**dict.fromkeys((ALICE, BOB, CAROL, DAVE, GINA, HANK, IVAN), "member"), FRANK: "admin"})
        self.schema = await self.ext.create_team(ALICE, "Platform", None)
        await self.ext.set_member(ALICE, self.schema, BOB, "owner", None)
        await self.ext.set_member(ALICE, self.schema, CAROL, "member", None)
        return self

    def restarted(self, **config):
        """The same data and Webex under a new process: nothing in memory survives."""
        return World(self.team, self.store, self.clock, self.webex, **config)

    def ask(self, email, name="Platform", channel="ext"):
        if channel == "delegated":
            headers = {**delegated_headers(self.team, email)}
            return self.client.post("/ext/delegated/join-requests", json={"name": name}, headers=headers)
        return self.client.post("/ext/join-requests", json={"name": name}, headers=as_person(self.team, email))

    def post(self, email, path, body):
        return self.client.post(f"/ext{path}", json=body, headers=as_person(self.team, email))

    def heard(self, person):
        return [text for to, text in self.webex.sent if to == person]

    async def send(self):
        if self.ext.notices:
            await self.ext.notices.send_due()


@pytest.fixture
async def world(team):
    return await World(team).start()


# Who hears what


@pytest.mark.parametrize("channel", ["ext", "delegated"])
async def test_team_owners_on_the_key_allowlist_hear_of_a_join_request_naming_the_requester_and_the_team(world, channel):
    world.store.roles.pop(BOB)  # an owner who is no longer on the Key Allowlist cannot answer it
    assert world.ask(DAVE, " platform ", channel).status_code == 200
    await world.send()
    assert world.webex.sent == [
        (ALICE, f"Hindsight:\n- {DAVE} asked to join your Team \"Platform\".\nSee {TEAMS}"),
    ]


async def test_a_request_that_stores_nothing_tells_nobody(world):
    assert world.ask(ERIN).status_code == 403  # not on the Key Allowlist
    assert world.ask(DAVE, "Nonesuch").status_code == 200  # a Team that does not exist: dropped
    assert world.ask(CAROL).status_code == 200  # already in the Team
    world.ask(DAVE)
    await world.send()
    world.clock.later(minutes=20)
    world.ask(DAVE)  # asking again leaves the open request as it is
    await world.send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB]


async def test_admins_hear_of_a_key_allowlist_request_and_nobody_else_does(world):
    assert world.post(ERIN, "/access-requests", {}).status_code == 204
    await world.send()
    assert sorted(world.webex.sent) == [
        (ADMIN, f"Hindsight:\n- {ERIN} asked to be added to the Key Allowlist.\nSee {KEYS}"),
        (FRANK, f"Hindsight:\n- {ERIN} asked to be added to the Key Allowlist.\nSee {KEYS}"),
    ]
    world.post(ERIN, "/access-requests", {})  # a repeat files nothing new
    world.clock.later(minutes=20)
    await world.send()
    assert len(world.webex.sent) == 2


@pytest.mark.parametrize(
    ("role", "heard"),
    [
        ("member", "An admin added you to the Key Allowlist. You can create Agent Keys now."),
        ("admin", "An admin added you to the Key Allowlist. You can create Agent Keys now."),
        (None, "An admin declined your request to join the Key Allowlist."),
    ],
)
async def test_the_person_who_asked_for_access_hears_the_decision(world, role, heard):
    world.post(ERIN, "/access-requests", {})
    await world.send()
    world.webex.sent.clear()
    assert world.post(ADMIN, "/admin/people", {"email": ERIN, "role": role}).status_code == 204
    await world.send()
    assert world.webex.sent == [(ERIN, f"Hindsight:\n- {heard}\nSee https://{ACCESS_HOST}/ext/")]


async def test_a_change_to_someone_who_did_not_ask_tells_them_nothing(world):
    world.post(ADMIN, "/admin/people", {"email": ERIN, "role": "member"})
    world.post(ADMIN, "/admin/people", {"email": ERIN, "role": None})
    await world.send()
    assert world.webex.sent == []


@pytest.mark.parametrize(("path", "heard"), [("/confirmations", "approved"), ("/requests", "declined")])
async def test_the_person_who_asked_to_join_hears_whether_an_owner_approved_or_declined(world, path, heard):
    world.ask(DAVE)
    await world.send()
    world.webex.sent.clear()
    request = ("POST", {"email": DAVE, "role": "member"}) if path == "/confirmations" else ("DELETE", {"email": DAVE})
    resp = world.client.request(request[0], f"/ext/teams/{world.schema}{path}", json=request[1], headers=as_person(world.team, ALICE))
    assert resp.status_code == 200
    await world.send()
    assert world.webex.sent == [(DAVE, f"Hindsight:\n- Your request to join the Team \"Platform\" was {heard}.\nSee {TEAMS}")]


async def test_whoever_filed_a_request_for_someone_else_hears_it_decided_unless_they_decided_it_themselves(world):
    await world.ext.request_member(ALICE, world.schema, DAVE, "member", None)
    await world.ext.request_member(ALICE, world.schema, GINA, "member", None)
    await world.send()  # the other owner hears of the requests
    world.webex.sent.clear()
    world.clock.later(minutes=20)
    await world.ext.confirm_member(BOB, world.schema, DAVE, "member", None)
    await world.ext.confirm_member(ALICE, world.schema, GINA, "member", None)
    await world.send()
    assert world.webex.sent == [
        (ALICE, f"Hindsight:\n- Your request to add {DAVE} to the Team \"Platform\" was approved.\nSee {TEAMS}")
    ]


async def test_nothing_is_sent_to_anyone_without_the_bot_token(team):
    bare = await World(team, webex_bot_token=None).start()
    bare.ask(DAVE)
    bare.post(ERIN, "/access-requests", {})
    await bare.send()
    assert (bare.webex.sent, bare.store.queue) == ([], [])


async def test_nothing_is_sent_without_the_key_pages_hostname_the_links_name(team):
    bare = await World(team, access_host=None).start()
    await bare.ext.request_access(ERIN, None)
    await bare.ext.request_to_join(DAVE, "Platform", None)
    await bare.send()
    assert (bare.webex.sent, bare.store.queue) == ([], [])


# What a message may say


async def test_a_team_name_cannot_add_lines_or_links_to_a_message(world):
    name = "Evil\nYour keys are revoked: see https://evil.test and www.evil.test, or evil.test"
    await world.ext.create_team(DAVE, name, None)
    assert world.ask(GINA, name).status_code == 200
    await world.send()
    [(to, text)] = world.webex.sent
    assert to == DAVE
    shown = "Evil Your keys are revoked: see hxxps://evil[.]test and www[.]evil[.]test, or evil[.]test"
    assert text.splitlines() == [
        "Hindsight:",
        f'- {GINA} asked to join your Team "{shown}".',
        f"See {TEAMS}",
    ]
    # Nothing Webex would turn into a link is left in the name: no scheme, and no dot between two word characters.
    assert not re.search(r"\w\.\w", shown) and "https" not in shown


async def test_a_requesters_email_cannot_add_lines_or_links_to_a_message_either(world):
    mallory = "mallory@evil.test\nSee https://evil.test/x"
    world.store.roles[mallory] = "member"
    await world.ext.request_to_join(mallory, "Platform", None)
    await world.send()
    expected = (
        "Hindsight:\n"
        '- mallory@evil[.]test See hxxps://evil[.]test/x asked to join your Team "Platform".\n'
        f"See {TEAMS}"
    )
    assert world.heard(ALICE) == [expected]


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        ("dave@example.com", "dave@example.com"),
        ("o'connor@example.com", "o'connor@example.com"),
        ("Platform", "Platform"),
        ("two\r\nlines\u2028here\x00\x1b[31m", "two lines here [31m"),
        ("a\u202eb\u200bc", "a b c"),
        ("ftp://evil.test/x", "ftp[://]evil[.]test/x"),
        ("HTTPS://Evil.test", "hxxps://Evil[.]test"),
        ("Http://x", "hxxp://x"),
        ("evil\uff0etest \uff48ttps://x", "evil[.]test hxxps://x"),
        ("v1.2 of 3.4.5.", "v1[.]2 of 3[.]4[.]5."),
        ("name@evil.test is here", "name@evil[.]test is here"),
    ],
)
def test_every_value_a_person_wrote_is_shown_as_one_line_without_anything_webex_would_link(value, shown):
    assert plain(value) == shown


async def test_a_long_wait_lists_ten_people_and_counts_the_rest(world):
    crowd = [f"p{n:02}@example.com" for n in range(12)]
    world.store.roles.update(dict.fromkeys(crowd, "member"))
    for person in crowd:
        await world.ext.request_to_join(person, "Platform", None)
    await world.send()
    [(_, text)] = [m for m in world.webex.sent if m[0] == ALICE]
    lines = text.splitlines()
    assert (lines[0], len(lines), lines[-2]) == ("Hindsight:", 13, "...and 2 more.")
    assert lines[1] == f"- {crowd[0]} asked to join your Team \"Platform\"."
    assert lines[-1] == f"See {TEAMS}"


# At most one a person every 15 minutes, grouping what arrived meanwhile


async def test_a_person_hears_at_most_once_in_15_minutes_and_then_of_everything_that_waited(world):
    world.ask(DAVE)
    await world.send()
    assert len(world.heard(ALICE)) == 1
    world.clock.later(minutes=5)
    world.ask(GINA)
    world.clock.later(minutes=5)
    world.ask(HANK)
    await world.send()
    world.clock.later(minutes=4, seconds=59)
    await world.send()
    assert len(world.heard(ALICE)) == 1
    world.clock.later(seconds=1)
    await world.send()
    assert len(world.heard(ALICE)) == 2
    grouped = world.heard(ALICE)[1]
    assert [DAVE in grouped, GINA in grouped, HANK in grouped, grouped.count("asked to join")] == [False, True, True, 2]
    # The window runs from that message.
    world.ask(IVAN)
    world.clock.later(minutes=14, seconds=59)
    await world.send()
    assert len(world.heard(ALICE)) == 2
    world.clock.later(seconds=1)
    await world.send()
    assert len(world.heard(ALICE)) == 3


async def test_the_limit_is_for_each_person_not_for_everyone(world):
    world.ask(DAVE)
    await world.send()
    world.clock.later(minutes=1)
    world.post(ERIN, "/access-requests", {})
    world.ask(GINA)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB, ADMIN, FRANK]


async def test_what_waited_survives_a_restart_and_goes_out_when_the_window_allows(world):
    world.ask(DAVE)
    await world.send()
    world.clock.later(minutes=1)
    world.ask(GINA)
    after_restart = world.restarted()
    await after_restart.send()
    assert len(world.heard(ALICE)) == 1
    world.clock.later(minutes=15)
    await after_restart.send()
    assert len(world.heard(ALICE)) == 2


# Best effort: never in the way of the request, a failure logged and not retried


async def test_a_failed_send_is_logged_and_never_retried_and_blocks_the_next_message_for_15_minutes(world):
    world.webex.fail = WebexError("HTTP 429, retry after 30 s")
    assert world.ask(DAVE).status_code == 200
    await world.send()
    assert [(row["recipient"], row["items"], row["status"], row["detail"]) for row in world.store.log] == [
        (ALICE, 1, "failed", "HTTP 429, retry after 30 s"),
        (BOB, 1, "failed", "HTTP 429, retry after 30 s"),
    ]
    # Webex is back, but those two people were messaged (an attempt counts) less than 15 minutes ago.
    world.webex.fail = None
    world.clock.later(minutes=5)
    world.ask(GINA)
    await world.send()
    assert world.webex.sent == [] and len(world.webex.entered_for) == 2
    # After the 15 minutes the next message goes out, with what arrived since; the failed notices are not in it.
    world.clock.later(minutes=10)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB]
    assert all(GINA in text and DAVE not in text for _, text in world.webex.sent)


async def test_an_unexpected_failure_of_the_client_is_logged_without_its_text(world):
    world.webex.fail = RuntimeError("token bot-token rejected")
    world.ask(DAVE)
    await world.send()
    assert {row["detail"] for row in world.store.log} == {"RuntimeError"}


async def test_a_request_is_answered_whether_or_not_its_notice_can_be_queued(world):
    world.store.break_on["queue_notice"] = OSError("database unavailable")
    assert world.ask(DAVE).status_code == 200
    assert [q["email"] for q in await world.store.member_requests(world.schema)] == [DAVE]
    assert world.store.queue == []


async def test_a_request_is_not_held_up_by_a_notice_that_hangs(world, monkeypatch):
    monkeypatch.setattr(notices, "QUEUE_DEADLINE", 0.1)
    world.store.hang = 5.0
    started = time.monotonic()
    assert world.ask(DAVE).status_code == 200
    assert time.monotonic() - started < 2.0
    assert [q["email"] for q in await world.store.member_requests(world.schema)] == [DAVE]


async def test_the_sweep_survives_a_store_that_fails(world):
    world.ask(DAVE)

    async def broken():
        raise OSError("database unavailable")

    world.store.queued_recipients = broken
    await world.send()
    assert world.webex.sent == []


# Interrupted states (README, "Webex notices")


async def test_a_stop_after_a_request_is_stored_and_before_its_notice_is_queued_leaves_the_request_unannounced(world):
    world.store.break_on["queue_notice"] = Stopped()
    with pytest.raises(Stopped):
        await world.ext.request_to_join(DAVE, "Platform", None)
    world.store.break_on.clear()
    # The request and its event are stored, and the owners can answer it on the page.
    assert [q["email"] for q in await world.store.member_requests(world.schema)] == [DAVE]
    assert [r["kind"] for r in world.events.rows if r["email"] == DAVE] == ["join_requested"]
    assert world.store.queue == []
    # A repeat of the request is no new request, so nobody is told of it now; the answer to it still reaches DAVE.
    await world.ext.request_to_join(DAVE, "Platform", None)
    await world.send()
    assert world.webex.sent == []
    await world.ext.confirm_member(ALICE, world.schema, DAVE, "member", None)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [DAVE]


async def test_a_stop_after_a_notice_is_queued_and_before_it_is_sent_loses_nothing(world):
    world.ask(DAVE)
    after_restart = world.restarted()
    assert len(world.store.queue) == 2 and world.webex.sent == []
    await after_restart.send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB]


async def test_a_stop_after_a_notice_is_claimed_and_before_the_message_leaves_sends_nothing_and_never_resends(world):
    world.ask(DAVE)
    world.webex.stop_before_sending = True
    with pytest.raises(Stopped):
        await world.send()
    assert [(row["recipient"], row["status"]) for row in world.store.log] == [(ALICE, "sending")]
    assert world.webex.sent == []
    # No process resends it, and the window runs from the claim: the next message waits for it.
    world.webex.stop_before_sending = False
    world.ask(GINA)
    await world.restarted().send()
    assert world.heard(ALICE) == []
    [for_bob] = world.heard(BOB)
    assert DAVE in for_bob and GINA in for_bob
    world.clock.later(minutes=15)
    await world.restarted().send()
    [for_alice] = world.heard(ALICE)
    assert GINA in for_alice and DAVE not in for_alice


async def test_a_stop_after_the_message_leaves_and_before_the_send_log_says_so_does_not_send_it_twice(world):
    world.ask(DAVE)
    world.store.break_on["finish_notice"] = Stopped()
    with pytest.raises(Stopped):
        await world.send()
    world.store.break_on.clear()
    assert [row["status"] for row in world.store.log] == ["sending"]
    assert [to for to, _ in world.webex.sent] == [ALICE]
    world.clock.later(hours=1)
    await world.restarted().send()
    assert [to for to, _ in world.webex.sent].count(ALICE) == 1


async def test_a_send_log_that_cannot_be_written_after_the_send_is_logged_and_the_sweep_goes_on(world):
    world.ask(DAVE)
    world.store.break_on["finish_notice"] = OSError("database unavailable")
    await world.send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB]
    assert [row["status"] for row in world.store.log] == ["sending", "sending"]


# Turning them off


async def test_a_person_turns_webex_notices_off_and_on_on_their_page(world):
    page = world.client.get("/ext/", headers={"Host": ACCESS_HOST, "Cf-Access-Jwt-Assertion": world.team.token(email=ALICE)})
    assert "Webex notices are on" in page.text and 'data-enable="false"' in page.text
    assert world.post(ALICE, "/webex-notices", {"enabled": False}).status_code == 204
    page = world.client.get("/ext/", headers={"Host": ACCESS_HOST, "Cf-Access-Jwt-Assertion": world.team.token(email=ALICE)})
    assert "Webex notices are off" in page.text and 'data-enable="true"' in page.text
    world.ask(DAVE)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB]
    assert world.post(ALICE, "/webex-notices", {"enabled": True}).status_code == 204
    world.clock.later(minutes=20)
    world.ask(GINA)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB, ALICE, BOB]


async def test_turning_notices_off_drops_what_was_already_waiting(world):
    world.ask(DAVE)
    world.post(ALICE, "/webex-notices", {"enabled": False})
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB]
    assert world.store.queue == []


async def test_the_opt_out_is_for_the_signed_in_person_alone_and_needs_a_sign_in(world):
    unsigned = {k: v for k, v in as_person(world.team, ALICE).items() if k != "Cf-Access-Jwt-Assertion"}
    assert world.client.post("/ext/webex-notices", json={"enabled": False}, headers=unsigned).status_code == 403
    world.post(ALICE, "/webex-notices", {"enabled": False})
    assert world.store.optouts == {ALICE}


async def test_without_the_bot_token_the_page_offers_no_switch_and_the_route_answers_404(team):
    bare = await World(team, webex_bot_token=None).start()
    page = bare.client.get("/ext/", headers={"Host": ACCESS_HOST, "Cf-Access-Jwt-Assertion": team.token(email=ALICE)})
    assert page.status_code == 200 and "Webex" not in page.text
    assert bare.post(ALICE, "/webex-notices", {"enabled": False}).status_code == 404
    assert bare.store.optouts == set()


# The background task

class Engine:
    db_url = "postgresql://unused"


class Running(Migrations):
    def get_memory_engine(self):
        return Engine()


async def test_the_extension_sends_in_the_background_from_startup_to_shutdown(world):
    world.ext.set_context(Running())
    await world.ext.on_startup()
    try:
        # The sweep is woken by the notice; it does not wait for its 30 seconds.
        await world.ext.request_to_join(DAVE, "Platform", None)
        for _ in range(200):
            if world.webex.sent:
                break
            await asyncio.sleep(0.01)
        assert [to for to, _ in world.webex.sent] == [ALICE, BOB]
    finally:
        await world.ext.on_shutdown()
    world.clock.later(minutes=20)
    await world.ext.request_to_join(GINA, "Platform", None)
    await asyncio.sleep(0.2)
    assert len(world.webex.sent) == 2


async def test_the_sweep_runs_again_when_nothing_woke_it(world, monkeypatch):
    monkeypatch.setattr(notices, "SWEEP_EVERY", 0.05)
    await world.ext.request_to_join(DAVE, "Platform", None)
    await world.send()
    await world.ext.request_to_join(GINA, "Platform", None)
    world.ext.set_context(Running())
    await world.ext.on_startup()
    try:
        world.clock.later(minutes=15)
        for _ in range(200):
            if len(world.webex.sent) >= 4:
                break
            await asyncio.sleep(0.01)
        assert [to for to, _ in world.webex.sent] == [ALICE, BOB, ALICE, BOB]
    finally:
        await world.ext.on_shutdown()


async def test_shutdown_ends_the_background_task_even_as_a_notice_arrives(world):
    world.ext.set_context(Running())
    await world.ext.on_startup()
    await asyncio.sleep(0.05)
    await world.ext.request_to_join(DAVE, "Platform", None)
    async with asyncio.timeout(2):
        await world.ext.on_shutdown()


# Who else is told, and who is no longer eligible


async def test_the_other_owners_hear_when_an_owner_or_an_admin_files_a_request_for_someone_else(world):
    await world.ext.request_member(ALICE, world.schema, DAVE, "member", None)
    await world.ext.request_member(FRANK, world.schema, GINA, "owner", None)
    await world.send()
    assert world.webex.sent == [
        (ALICE, f'Hindsight:\n- {FRANK} asked to add {GINA} to your Team "Platform" as an owner.\nSee {TEAMS}'),
        (BOB, "\n".join([
            "Hindsight:",
            f'- {ALICE} asked to add {DAVE} to your Team "Platform".',
            f'- {FRANK} asked to add {GINA} to your Team "Platform" as an owner.',
            f"See {TEAMS}",
        ])),
    ]


async def test_a_direct_add_that_settles_a_request_tells_whoever_asked_unless_they_added_the_person(world):
    await world.ext.request_to_join(DAVE, "Platform", None)  # DAVE asked for themselves
    await world.ext.request_member(ALICE, world.schema, GINA, "member", None)  # ALICE asked for GINA
    await world.ext.request_member(ALICE, world.schema, HANK, "member", None)  # ALICE asked for HANK
    await world.send()
    world.webex.sent.clear()
    world.clock.later(minutes=20)
    assert world.post(ALICE, f"/teams/{world.schema}/members", {"email": DAVE, "role": "member"}).status_code == 200
    await world.ext.set_member(BOB, world.schema, GINA, "member", None)
    await world.ext.set_member(ALICE, world.schema, HANK, "member", None)
    await world.send()
    assert world.webex.sent == [
        (ALICE, f'Hindsight:\n- Your request to add {GINA} to the Team "Platform" was approved.\nSee {TEAMS}'),
        (DAVE, f'Hindsight:\n- Your request to join the Team "Platform" was approved.\nSee {TEAMS}'),
    ]


@pytest.mark.parametrize("leaves", ["the Team", "the Key Allowlist"])
async def test_a_notice_waiting_for_an_owner_who_has_since_left_is_dropped_unsent(world, leaves):
    world.ask(DAVE)
    if leaves == "the Team":
        world.store.team_roles.pop((world.schema, BOB))
    else:
        world.store.roles.pop(BOB)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [ALICE]
    assert world.store.queue == [] and [row["recipient"] for row in world.store.log] == [ALICE]


async def test_a_notice_waiting_for_an_admin_who_has_since_been_demoted_is_dropped_unsent(world):
    world.post(ERIN, "/access-requests", {})
    world.store.roles[FRANK] = "member"
    await world.send()
    # The bootstrap admin is an admin whatever the Key Allowlist says.
    assert [to for to, _ in world.webex.sent] == [ADMIN]
    assert world.store.queue == []


async def test_joining_an_open_team_tells_nobody_but_joining_a_closed_one_files_a_join_request_the_owners_hear_of(world):
    # Closed: the Team's join route files the person's Join Request, as asking by name does.
    resp = world.post(DAVE, f"/teams/{world.schema}/join", {})
    assert (resp.status_code, resp.json()["status"]) == (200, "pending")
    await world.send()
    assert [(to, DAVE in text) for to, text in world.webex.sent] == [(ALICE, True), (BOB, True)]
    # Open: the person is in at once, and nothing waits for anyone.
    await world.ext.set_open(ADMIN, world.schema, True, None)
    world.webex.sent.clear()
    world.clock.later(minutes=20)
    resp = world.post(GINA, f"/teams/{world.schema}/join", {})
    assert (resp.status_code, resp.json()["role"]) == (200, "member")
    await world.send()
    assert world.webex.sent == [] and world.store.queue == []


@pytest.mark.parametrize("change", ["leaves the Team", "is demoted to a member of it"])
async def test_an_owner_who_loses_the_team_between_the_claim_and_the_send_is_not_sent_to(world, change):
    world.ask(DAVE)

    def lose(person):
        if person == ALICE:
            if change == "leaves the Team":
                world.store.team_roles.pop((world.schema, ALICE))
            else:
                world.store.team_roles[world.schema, ALICE] = "member"

    world.store.after_claim = lose
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB]
    assert [(row["recipient"], row["status"], row["detail"]) for row in world.store.log] == [
        (ALICE, "skipped", "no longer eligible"),
        (BOB, "sent", None),
    ]


async def test_an_owner_who_loses_the_key_allowlist_or_an_admin_who_is_demoted_between_the_claim_and_the_send_is_not_sent_to(world):
    world.ask(DAVE)
    world.post(ERIN, "/access-requests", {})

    def lose(person):
        if person == ALICE:
            world.store.roles.pop(ALICE)
        elif person == FRANK:
            world.store.roles[FRANK] = "member"

    world.store.after_claim = lose
    await world.send()
    assert sorted(to for to, _ in world.webex.sent) == [ADMIN, BOB]
    assert {row["recipient"]: row["status"] for row in world.store.log} == {
        ADMIN: "sent",
        ALICE: "skipped",
        BOB: "sent",
        FRANK: "skipped",
    }


async def test_a_message_lists_only_what_the_person_is_still_eligible_for(world):
    ops = await world.ext.create_team(ALICE, "Ops", None)
    world.ask(DAVE)
    world.ask(DAVE, "Ops")
    world.store.after_claim = lambda person: world.store.team_roles.pop((ops, ALICE)) if person == ALICE else None
    await world.send()
    [for_alice] = world.heard(ALICE)
    assert '"Platform"' in for_alice and '"Ops"' not in for_alice
    assert [(row["items"], row["status"]) for row in world.store.log if row["recipient"] == ALICE] == [(2, "sent")]


# A decision never waits on a notice


@pytest.mark.parametrize("decide", ["confirm", "decline"])
async def test_a_decision_is_not_held_up_by_anything_a_notice_reads(world, monkeypatch, decide):
    monkeypatch.setattr(notices, "QUEUE_DEADLINE", 0.1)
    await world.ext.request_to_join(DAVE, "Platform", None)

    async def hangs(*args):
        await asyncio.sleep(30)

    # Who asked, and the Team's name: neither is read before the decision, and the notice's reads have a deadline.
    world.store.member_requests = hangs
    world.store.team_name = hangs
    started = time.monotonic()
    async with asyncio.timeout(5):
        if decide == "confirm":
            await world.ext.confirm_member(ALICE, world.schema, DAVE, "member", None)
        else:
            await world.ext.decline_member(ALICE, world.schema, DAVE, None)
    assert time.monotonic() - started < 2
    assert await world.store.team_role(world.schema, DAVE) == ("member" if decide == "confirm" else None)
    # The notice of the decision, whose reads hung, was dropped at its deadline.
    assert [q for q in world.store.queue if q[1] == "asker"] == []


# Turning them off, against a send in flight


async def test_an_opt_out_waits_for_a_send_in_flight_and_nothing_is_sent_after_it(world):
    world.ask(DAVE)
    world.webex.gate = asyncio.Event()
    sending = asyncio.create_task(world.send())
    await asyncio.wait_for(world.webex.entered.wait(), 2)  # ALICE's message is on its way
    opting_out = asyncio.create_task(world.ext.set_webex_notices(ALICE, False))
    await asyncio.sleep(0.05)
    assert not opting_out.done()
    world.webex.gate.set()
    await asyncio.wait_for(asyncio.gather(sending, opting_out), 2)
    assert len(world.heard(ALICE)) == 1  # the one in flight arrived
    # The opt-out has committed: nothing more goes to ALICE.
    world.clock.later(minutes=20)
    world.ask(GINA)
    await world.send()
    assert len(world.heard(ALICE)) == 1


async def test_an_opt_out_that_commits_between_the_claim_and_the_send_stops_the_send(world):
    world.ask(DAVE)
    world.store.opts_out_after_claim = ALICE
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB]
    assert [(row["recipient"], row["status"], row["detail"]) for row in world.store.log] == [
        (ALICE, "skipped", "turned off"),
        (BOB, "sent", None),
    ]


async def test_an_opt_out_that_cannot_get_the_notice_lock_in_time_asks_to_try_again(world):
    @contextlib.asynccontextmanager
    async def stuck(email):
        raise TimeoutError
        yield

    world.store.notice_lock = stuck
    assert world.post(ALICE, "/webex-notices", {"enabled": False}).status_code == 503
    assert world.store.optouts == set()


async def test_a_stop_inside_the_claim_changes_nothing(world):
    world.ask(DAVE)
    world.store.break_on["claim_notice"] = Stopped()
    with pytest.raises(Stopped):
        await world.send()
    world.store.break_on.clear()
    # The claim is one transaction: it rolled back, the notices are still queued and nothing is logged.
    assert len(world.store.queue) == 2 and world.store.log == []
    await world.restarted().send()
    assert [to for to, _ in world.webex.sent] == [ALICE, BOB]
