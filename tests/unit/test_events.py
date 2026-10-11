"""The event log never stops Hindsight from serving requests."""

from hindsight_agent_keys.events import PostgresEventLog


async def test_an_unreachable_database_leaves_the_log_inert_instead_of_failing_startup(caplog):
    log = PostgresEventLog()
    await log.start("postgresql://nobody:nothing@127.0.0.1:1/none")
    await log.record("key_refused", "missing", None)
    await log.stop()
    assert "agent-keys" in caplog.text


async def test_recording_before_start_does_nothing():
    await PostgresEventLog().record("key_refused", "missing", None)
