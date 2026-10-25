"""Collection order for the container tests."""

# Removes the module's container, so every test after it would fail with "No such container" (PR #44 retro).
LAST = "test_stock_hindsight_starts_on_the_same_database"


def pytest_collection_modifyitems(items):
    items.sort(key=lambda item: item.name == LAST)
