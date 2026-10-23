"""requirements-ci.txt is compiled from requirements-ci.in (its header has the command); CI installs only the .txt.

Dependabot's uv updater bumps a top-level pin in the .in and recompiles the .txt from it (a transitive pin changes in
the .txt alone). A hand edit to one file alone leaves CI on versions the .in does not name, so each pin in the .in must
sit in the .txt at the same version.
"""

import os
import re

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(name):
    with open(os.path.join(ROOT, name)) as f:
        return f.read()


def pins(name):
    """{name: specifier} for each requirement line, skipping comments and a pin's --hash continuation lines."""
    lines = map(str.strip, read(name).splitlines())
    reqs = [Requirement(s.split()[0]) for s in lines if s and not s.startswith(("#", "--"))]
    return {canonicalize_name(r.name): str(r.specifier) for r in reqs}


def test_every_pin_in_the_in_file_is_compiled_at_the_same_version():
    wanted, compiled = pins("requirements-ci.in"), pins("requirements-ci.txt")
    assert wanted
    assert {n: compiled.get(n) for n in wanted} == wanted


def test_the_txt_names_the_python_version_dependabot_compiles_for():
    """Without it, Dependabot compiles for its own Python, not CI's. The regex is dependabot-core's
    PYTHON_VERSION_REGEX (uv/lib/dependabot/uv/file_updater/compile_file_updater.rb), matched anywhere in the .txt."""
    assert re.search(r"--python-version[=\s]+\d+\.\d+", read("requirements-ci.txt"))
