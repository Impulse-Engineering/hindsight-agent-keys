"""A message to a person is sent under their notice lock, and every change that can end their eligibility for a notice takes
the same lock before it commits (README, "Webex notices"). This fails when a store method that changes a Team role or a
place on the Key Allowlist skips the lock, so a future change cannot slip past the sender's final check."""

import inspect
import re

from hindsight_agent_keys.store import PostgresKeyStore

WRITES = re.compile(r"(INSERT INTO|UPDATE|DELETE FROM) \{SCHEMA\}\.(members|allowlist)\b")
# These only ever add a row where there was none (nothing is updated or deleted), so they cannot end anyone's eligibility.
ADDS_ONLY = {"create_team", "join_open_team", "add_request"}


def test_every_store_method_that_changes_a_role_takes_the_notice_lock():
    writers = {}
    for name, method in inspect.getmembers(PostgresKeyStore, inspect.iscoroutinefunction):
        source = inspect.getsource(method)
        if WRITES.search(source):
            writers[name] = source
    # The methods this guard exists for are found, so it cannot pass by matching nothing.
    assert {"set_member", "remove_member", "confirm_member", "set_role"} <= writers.keys()
    for name, source in writers.items():
        if name in ADDS_ONLY:
            assert {m[0] for m in WRITES.findall(source)} == {"INSERT INTO"} and "DO UPDATE" not in source, name
        else:
            locked = "_lock_notices(" in source or re.search(r"who=(?!None)\w", source)
            assert locked, f"{name} changes a role without taking the person's notice lock"
