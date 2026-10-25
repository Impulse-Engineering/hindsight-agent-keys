"""The integration test that removes the shared container is collected last, wherever it sits in its file
(tests/integration/conftest.py, PR #44 retro)."""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFTEST = ROOT / "tests" / "integration" / "conftest.py"


def test_the_test_that_removes_the_container_is_collected_last(tmp_path):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_order.py").write_text(
        "def test_stock_hindsight_starts_on_the_same_database():\n    pass\n\n\ndef test_added_after_it():\n    pass\n"
    )
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-c", "/dev/null", "--rootdir", str(tmp_path),
         "--collect-only", "-q", str(tmp_path)],
        capture_output=True, text=True, check=True,
    ).stdout
    names = [line.split("::")[-1] for line in out.splitlines() if "::" in line]
    assert names == ["test_added_after_it", "test_stock_hindsight_starts_on_the_same_database"]


def test_the_name_the_hook_moves_is_still_a_test_in_the_container_file():
    container = (ROOT / "tests" / "integration" / "test_container.py").read_text()
    assert "\ndef test_stock_hindsight_starts_on_the_same_database(" in container
