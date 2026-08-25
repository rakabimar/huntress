"""Bootstrap + packaging regression tests (P0.14).

Asserts that the packaging declares a ``full`` extra (so a single
``pip install -e '.[full]'`` delivers every optional capability + the test
toolchain) and that ``scripts/bootstrap.sh`` uses it and does **not** mask a
broken install with ``|| true``.
"""

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_full_extra_covers_all_optional_deps():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    assert "full" in extras, "missing `full` optional-dependency extra"
    full = extras["full"]
    # The full extra must pull in every optional group without self-referencing
    # the project (defensive against a setuptools circular-extra pitfall).
    assert all(not pkg.startswith("bughunt-harness") for pkg in full)
    assert any(pkg.startswith("mcp") for pkg in full)
    assert any(pkg.startswith("cvss") for pkg in full)
    assert any(pkg.startswith("pytest") for pkg in full)


def test_bootstrap_installs_full_and_does_not_swallow_doctor_failure():
    script = (REPO_ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
    # `.[full]` install, not a bare coverage-less `.[full]` vs `-e .`.
    assert "-e '.[full]'" in script or '-e ".[full]"' in script
    # No `|| true` masking anywhere in the script — a broken install must fail.
    assert "|| true" not in script
    # The doctor step runs and the script is responsible for its exit code.
    assert "harness\" doctor" in script or "harness' doctor" in script