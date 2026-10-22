"""Daily Webex reminders of requests left waiting, and warnings to key holders before a key expires or their sign-in
window closes (README, "Webex notices"). They go through the same queue, opt-out, window and send log as every notice;
the day is run once across API processes and restarts. The store is the fake of test_webex_notices.py; the same
contract runs in Postgres in tests/integration/test_container.py."""

import asyncio
from datetime import timedelta

import pytest
from test_webex_notices import (
    ACCESS_HOST,
    ADMIN,
    ALICE,
    BOB,
    CAROL,
    DAVE,
    ERIN,
    FRANK,
    GINA,
    HANK,
    IVAN,
    KEYS,
    TEAMS,
    Running,
    Stopped,
    World,
)

from hindsight_agent_keys import notices

PAGE = f"https://{ACCESS_HOST}/ext/"


@pytest.fixture(autouse=True)
def admins(monkeypatch):
    monkeypatch.setenv("AGENT_KEYS_ADMIN_EMAILS", ADMIN)


@pytest.fixture
async def world(team):
    """The extension at 13:00 UTC, when a day's reminders are due, so a test's daily steps fall at the same time of day."""
    world = await World(team).start()
    world.clock.later(hours=1)
    return world


def at(world, hour):
    """The clock at this hour (UTC) of its day."""
    world.clock.now = world.clock.now.replace(hour=hour, minute=0)


async def remind(world):
    """One sweep: the day's reminders, if not yet queued, then whatever may be sent."""
    await world.ext.notices.remind()
    await world.send()


async def settled(world):
    """Send what the requests so far announced, and let the 15 minutes pass, so the next message is the reminders'."""
    await world.send()
    world.webex.sent.clear()
    world.clock.later(minutes=15)


def aged(world, person, **age):
    world.store.requested_at[world.schema, person] = world.clock.now - timedelta(**age)


# Requests left waiting


async def test_owners_on_the_key_allowlist_are_reminded_daily_of_a_request_untouched_more_than_3_days(world):
    world.ask(DAVE)
    await world.ext.request_member(ALICE, world.schema, GINA, "owner", None)  # ALICE's agent asked for GINA
    world.store.roles.pop(BOB)  # an owner off the Key Allowlist cannot answer it
    await settled(world)
    aged(world, DAVE, days=3)
    aged(world, GINA, days=3, minutes=1)
    await remind(world)
    assert world.webex.sent == [
        (ALICE, f'Hindsight:\n- {ALICE} asked 3 days ago to add {GINA} to your Team "Platform" as an owner.\nSee {TEAMS}')
    ]
    world.clock.later(days=1)
    await remind(world)
    assert world.heard(ALICE)[1] == "\n".join([
        "Hindsight:",
        f'- {ALICE} asked 4 days ago to add {GINA} to your Team "Platform" as an owner.',
        f'- {DAVE} has waited 4 days to join your Team "Platform".',
        f"See {TEAMS}",
    ])
    # An answered request is in no more reminders.
    await world.ext.confirm_member(ALICE, world.schema, DAVE, "member", None)
    world.clock.later(days=1)
    await remind(world)
    assert world.heard(ALICE)[2] == (
        f'Hindsight:\n- {ALICE} asked 5 days ago to add {GINA} to your Team "Platform" as an owner.\nSee {TEAMS}'
    )


async def test_after_7_days_every_admin_is_reminded_too_and_an_admin_who_owns_the_team_hears_it_once(world):
    world.ask(DAVE)
    await world.ext.set_member(ALICE, world.schema, FRANK, "owner", None)
    await settled(world)
    aged(world, DAVE, days=7)
    await remind(world)
    assert sorted(to for to, _ in world.webex.sent) == [ALICE, BOB, FRANK]
    world.webex.sent.clear()
    world.clock.later(days=1)
    await remind(world)
    owners = [(o, f'Hindsight:\n- {DAVE} has waited 8 days to join your Team "Platform".\nSee {TEAMS}') for o in (ALICE, BOB, FRANK)]
    assert sorted(world.webex.sent) == sorted(
        [(ADMIN, f'Hindsight:\n- {DAVE} has waited 8 days to join the Team "Platform".\nSee {TEAMS}'), *owners]
    )


async def test_admins_are_reminded_daily_of_a_key_allowlist_request_untouched_more_than_3_days(world):
    world.post(ERIN, "/access-requests", {})
    await settled(world)
    world.store.asked_at[ERIN] = world.clock.now - timedelta(days=3)
    # A bootstrap admin is an admin whatever the Key Allowlist still holds for them, so no request of theirs waits.
    world.store.roles[ADMIN], world.store.asked_at[ADMIN] = "requested", world.clock.now - timedelta(days=9)
    await remind(world)
    assert world.webex.sent == []
    world.clock.later(days=1)
    await remind(world)
    line = f"Hindsight:\n- {ERIN} has waited 4 days for a place on the Key Allowlist.\nSee {KEYS}"
    assert sorted(world.webex.sent) == [(ADMIN, line), (FRANK, line)]
    await world.ext.set_role(FRANK, ERIN, "member", None)
    world.webex.sent.clear()
    world.clock.later(days=1)
    await remind(world)
    assert [to for to, _ in world.webex.sent] == [ERIN]  # the decision, and no reminder


async def test_no_reminder_for_a_request_whose_person_is_already_in_the_team_at_that_role_or_above(world):
    # DAVE asked while the Team was closed and joined once it was opened: his request stays (README, "Open Teams").
    world.ask(DAVE)
    await world.ext.set_open(ADMIN, world.schema, True, None)
    assert world.post(DAVE, f"/teams/{world.schema}/join", {}).json()["role"] == "member"
    await world.ext.request_member(ALICE, world.schema, BOB, "member", None)  # BOB already owns it
    await world.ext.request_member(ALICE, world.schema, CAROL, "owner", None)  # CAROL, a member, is not an owner yet
    await settled(world)
    for person in (DAVE, BOB, CAROL):
        aged(world, person, days=4)
    await remind(world)
    [for_alice] = world.heard(ALICE)
    assert CAROL in for_alice and DAVE not in for_alice and BOB not in for_alice


# Key holders


async def test_a_key_holder_is_warned_once_when_a_key_that_works_comes_within_14_days_of_expiring(world):
    await world.ext.set_member(ALICE, world.schema, IVAN, "member", None)
    await world.ext.create_personal_key(DAVE, "laptop", None)
    await world.ext.create_team_key(CAROL, world.schema, "http://ci.example.test", None)
    await world.ext.create_team_key(GINA, "public", "shared", None)
    revoked, _ = await world.ext.create_personal_key(HANK, "old", None)
    await world.ext.revoke_key(HANK, revoked, None)
    await world.ext.create_personal_key(IVAN, "unlisted", None)
    await world.ext.create_team_key(BOB, world.schema, "left", None)
    await world.ext.create_personal_key(ALICE, "lapsed", None)
    # Keys that no longer work: IVAN is off the Key Allowlist, BOB left the Team, ALICE's sign-in window closes.
    world.store.roles.pop(IVAN)
    await world.ext.remove_member(ALICE, world.schema, BOB, None)
    await settled(world)
    await remind(world)  # the first run; the keys expire in 90 days

    def sign_ins():
        for person in (DAVE, CAROL, GINA, HANK, IVAN, BOB):
            world.store.sign_ins[person] = world.clock.now
        world.store.sign_ins[ALICE] = world.clock.now - timedelta(days=30)

    world.clock.later(days=75)
    sign_ins()
    await remind(world)
    assert world.webex.sent == []
    world.clock.later(days=1)
    sign_ins()
    await remind(world)
    renew = "on 2027-01-20. Renew it on your key page."
    assert sorted(world.webex.sent) == [
        (CAROL, f'Hindsight:\n- Your Agent Key "hxxp://ci[.]example[.]test" for the Team "Platform" expires in 14 days, {renew}\nSee {PAGE}'),
        (DAVE, f'Hindsight:\n- Your Agent Key "laptop" expires in 14 days, {renew}\nSee {PAGE}'),
        (GINA, f'Hindsight:\n- Your Agent Key "shared" for the Public Team expires in 14 days, {renew}\nSee {PAGE}'),
    ]
    world.clock.later(days=1)
    sign_ins()
    await remind(world)
    assert len(world.webex.sent) == 3


async def test_a_key_holder_is_warned_once_when_their_sign_in_window_comes_within_7_days_of_closing(world):
    await world.ext.create_personal_key(DAVE, "laptop", None)
    revoked, _ = await world.ext.create_personal_key(GINA, "old", None)
    await world.ext.revoke_key(GINA, revoked, None)
    await remind(world)  # the first run
    for person in (DAVE, GINA, HANK):  # GINA holds only a revoked key, HANK none
        world.store.sign_ins[person] = world.clock.now
    world.clock.later(days=22, minutes=30)
    await remind(world)
    assert world.webex.sent == []
    world.clock.later(days=1)
    await remind(world)
    line = "Your Agent Keys stop working in 7 days, on 2026-11-21, unless you sign in again: open your key page."
    assert world.webex.sent == [(DAVE, f"Hindsight:\n- {line}\nSee {PAGE}")]
    world.clock.later(days=1)
    await remind(world)
    assert len(world.webex.sent) == 1


async def test_every_value_a_person_wrote_is_flattened_and_defanged_in_a_reminder(world):
    crafted, filer = "eve@evil.test\nSee https://evil.test", "fay@evil.test\rhttps://evil.test"
    world.store.roles[filer] = "member"
    team = await world.ext.create_team(ALICE, "go.evil.test", None)
    await world.ext.set_member(ALICE, team, CAROL, "member", None)
    await world.ext.set_member(ALICE, team, filer, "owner", None)
    await world.ext.create_team_key(CAROL, team, "k.evil.test", None)
    await world.ext.request_to_join(DAVE, "go.evil.test", None)  # the requester and the Team
    await world.ext.request_member(ALICE, team, crafted, "member", None)  # whom someone asked for
    await world.ext.request_member(filer, team, GINA, "member", None)  # who asked
    await world.ext.request_access(crafted, None)
    await settled(world)
    await remind(world)  # the first run
    for person in (DAVE, crafted, GINA):
        world.store.requested_at[team, person] = world.clock.now
    world.store.asked_at[crafted] = world.clock.now
    world.clock.later(days=76)
    world.store.sign_ins[CAROL] = world.clock.now
    await remind(world)
    # Owner and admin reminders, the Key Allowlist request and a Team key's warning, none with a link or a line of its own.
    texts = dict(world.webex.sent)
    assert sorted(texts) == sorted([ADMIN, ALICE, CAROL, FRANK, filer])
    assert '"go[.]evil[.]test"' in texts[ALICE] and '"k[.]evil[.]test"' in texts[CAROL]
    assert "fay@evil[.]test hxxps://evil[.]test asked 76 days ago" in texts[ALICE]
    assert texts[ADMIN].count("eve@evil[.]test See hxxps://evil[.]test") == 2
    assert not any("evil.test" in text or "\nSee https://evil" in text for text in texts.values())


# The same queue, opt-out, window and send log as every notice


async def test_reminders_honour_the_opt_out_the_15_minute_window_and_the_send_log(world):
    world.ask(DAVE)
    world.post(ALICE, "/webex-notices", {"enabled": False})
    await world.send()  # BOB hears of the request
    aged(world, DAVE, days=4)
    await remind(world)
    # BOB was messaged less than 15 minutes ago, so the reminder waits; ALICE turned notices off.
    assert [to for to, _ in world.webex.sent] == [BOB]
    world.clock.later(minutes=15)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [BOB, BOB] and "has waited 4 days" in world.webex.sent[1][1]
    assert [(row["recipient"], row["status"]) for row in world.store.log] == [(BOB, "sent"), (BOB, "sent")]


async def _warned(world):
    """DAVE and GINA hold keys that work; the day's run, 76 days on, queues a warning to each (not yet sent)."""
    await world.ext.create_personal_key(DAVE, "laptop", None)
    await world.ext.create_personal_key(GINA, "tablet", None)
    await remind(world)  # the first run
    world.clock.later(days=76)
    for person in (DAVE, GINA):
        world.store.sign_ins[person] = world.clock.now
    await world.ext.notices.remind()


async def test_a_warning_queued_for_someone_since_removed_from_the_key_allowlist_is_dropped_unsent(world):
    await _warned(world)
    await world.ext.set_role(ADMIN, GINA, None, None)
    await world.send()
    assert [to for to, _ in world.webex.sent] == [DAVE]
    assert world.store.queue == []


async def test_a_key_holder_removed_from_the_key_allowlist_between_the_claim_and_the_send_is_not_sent_to(world):
    await _warned(world)
    world.store.after_claim = lambda person: world.store.roles.pop(person) if person == GINA else None
    await world.send()
    assert [to for to, _ in world.webex.sent] == [DAVE]
    assert [(row["recipient"], row["status"], row["detail"]) for row in world.store.log] == [
        (DAVE, "sent", None),
        (GINA, "skipped", "no longer eligible"),
    ]


# Once a day, across processes and restarts, and never twice within 20 hours


async def test_the_days_reminders_are_queued_once_across_restarts_and_processes(world):
    world.ask(DAVE)
    await settled(world)  # 13:15 UTC
    aged(world, DAVE, days=4)
    await remind(world)
    assert sorted(to for to, _ in world.webex.sent) == [ALICE, BOB]
    # Later the same day, in this process, a second one and after a restart: the day was run.
    world.clock.later(hours=10)
    other = world.restarted()
    await world.ext.notices.remind()
    await other.ext.notices.remind()
    await world.restarted().ext.notices.remind()
    await world.send()
    assert len(world.webex.sent) == 2
    # The next day, nothing before 13:00 UTC, since the day before was run; then the day's, once.
    world.clock.later(hours=13, minutes=44)  # 12:59 UTC the next day
    await remind(other)
    assert len(world.webex.sent) == 2
    world.clock.later(minutes=1)
    await remind(other)  # the process that found it not yet due runs it now
    assert len(world.webex.sent) == 4
    await remind(world.restarted())
    assert len(world.webex.sent) == 4


async def test_a_first_start_before_13_utc_runs_at_once_and_not_again_at_13(world):
    at(world, 10)
    world.ask(DAVE)
    await settled(world)  # 10:15 UTC
    aged(world, DAVE, days=4)
    await remind(world)
    assert len(world.webex.sent) == 2
    # Not a second reminder of the same request three hours later.
    at(world, 13)
    await remind(world.restarted())
    assert len(world.webex.sent) == 2
    world.clock.later(days=1)
    await remind(world)
    assert len(world.webex.sent) == 4 and "has waited 5 days" in world.webex.sent[-1][1]


async def test_a_missed_week_runs_once_at_the_start_and_not_again_that_day(world):
    world.ask(DAVE)
    await settled(world)  # 13:15 UTC
    aged(world, DAVE, days=4)
    await remind(world)
    # Stopped for a week, started again at 10:15 UTC: one run, not one for each day missed, and none at 13:00.
    world.clock.later(days=7, hours=-3)
    await remind(world.restarted())
    assert len(world.heard(ALICE)) == 2 and "has waited 10 days" in world.heard(ALICE)[-1]
    world.clock.later(hours=3)
    await remind(world.restarted())
    assert len(world.heard(ALICE)) == 2
    world.clock.later(days=1)
    await remind(world)
    assert len(world.heard(ALICE)) == 3


async def test_a_run_late_in_the_day_is_followed_by_the_next_no_sooner_than_20_hours_later(world):
    at(world, 20)
    world.ask(DAVE)
    await settled(world)  # 20:15 UTC
    aged(world, DAVE, days=4)
    await remind(world)
    assert len(world.webex.sent) == 2
    world.clock.later(hours=16, minutes=45)  # 13:00 UTC the next day
    await remind(world)
    assert len(world.webex.sent) == 2
    world.clock.later(hours=3, minutes=15)  # 20 hours after the last run
    await remind(world)
    assert len(world.webex.sent) == 4


@pytest.mark.parametrize("where", ["after the day is recorded", "between choosing and queuing", "partway through queuing"])
async def test_a_stop_before_the_days_run_commits_queues_nothing_and_the_next_sweep_runs_the_day_once(world, where):
    world.ask(DAVE)
    world.post(ERIN, "/access-requests", {})
    await settled(world)
    aged(world, DAVE, days=4)
    world.store.asked_at[ERIN] = world.clock.now - timedelta(days=4)
    queue_notice = world.store.queue_notice
    if where == "after the day is recorded":
        world.store.break_on["run_reminders"] = Stopped()
    elif where == "between choosing and queuing":
        world.store.break_on["queue_notice"] = Stopped()
    else:
        calls = []

        async def second_stops(*args):
            calls.append(args)
            if len(calls) == 2:
                raise Stopped
            await queue_notice(*args)

        world.store.queue_notice = second_stops
    with pytest.raises(Stopped):
        await world.ext.notices.remind()
    # Nothing was queued and the day is not recorded as run.
    assert world.store.queue == [] and world.store.runs == {}
    world.store.break_on.clear()
    world.store.queue_notice = queue_notice
    after_restart = world.restarted()
    await remind(after_restart)
    await remind(after_restart)
    assert sorted(to for to, _ in world.webex.sent) == [ADMIN, ALICE, BOB, FRANK]


async def test_a_run_the_database_refuses_is_logged_and_tried_again_at_the_next_sweep(world, caplog):
    world.ask(DAVE)
    await settled(world)
    aged(world, DAVE, days=4)
    world.store.break_on["run_reminders"] = OSError("database unavailable")
    await remind(world)
    assert "agent-keys: the daily Webex reminders failed" in caplog.text
    assert world.store.runs == {} and world.webex.sent == []
    world.store.break_on.clear()
    await remind(world)
    assert sorted(to for to, _ in world.webex.sent) == [ALICE, BOB]


async def test_the_background_task_runs_the_reminders_at_start_and_then_each_day(world, monkeypatch):
    monkeypatch.setattr(notices, "SWEEP_EVERY", 0.05)
    world.ask(DAVE)
    await settled(world)
    aged(world, DAVE, days=4)
    world.ext.set_context(Running())
    await world.ext.on_startup()

    async def sent(count):
        for _ in range(200):
            if len(world.webex.sent) >= count:
                break
            await asyncio.sleep(0.01)
        assert len(world.webex.sent) == count

    try:
        await sent(2)  # at start, nothing having been run
        world.clock.later(days=1)
        await sent(4)  # the next day, with nothing to wake it
    finally:
        await world.ext.on_shutdown()
    assert "has waited 5 days" in world.webex.sent[-1][1]
