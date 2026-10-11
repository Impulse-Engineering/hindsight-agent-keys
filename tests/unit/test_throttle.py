"""The throttle's memory is bounded, and a full table never re-allows a throttled key."""

from datetime import datetime, timedelta

from hindsight_agent_keys.events import Throttle

T0 = datetime.fromisoformat("2026-10-11T12:00:00+00:00")


def test_a_full_table_drops_new_keys_instead_of_forgetting_old_ones():
    throttle = Throttle(window_seconds=60, max_entries=2)
    assert throttle.allow("a", T0)
    assert throttle.allow("b", T0)
    assert not throttle.allow("c", T0)
    assert not throttle.allow("a", T0 + timedelta(seconds=1))


def test_expired_entries_make_room():
    throttle = Throttle(window_seconds=60, max_entries=2)
    assert throttle.allow("a", T0)
    assert throttle.allow("b", T0)
    assert throttle.allow("c", T0 + timedelta(seconds=60))
