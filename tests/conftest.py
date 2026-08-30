"""Shared pytest fixtures for the harness test suite.

Everything here is synthetic: local-only fixtures, loopback HTTP servers, and
in-memory workspace trees.  No test in this suite performs real reconnaissance,
scanning, exploitation, or HTTP against a public/external target (spec §95).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the package is importable when running pytest from the repo root
# without an editable install.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bughunt_harness.config import HarnessConfig  # noqa: E402
from bughunt_harness.engagement.models import (  # noqa: E402
    AccountsModel,
    Engagement,
    HeadersModel,
    ProgramModel,
    ReportingModel,
    ROEModel,
    ScopeModel,
    ScopeSet,
)
from bughunt_harness.state.db import HuntDB  # noqa: E402


_INTEGRATION_LOCAL_MODULES = {
    "test_autonomous_synthetic.py", "test_e2e.py", "test_source.py",
    "test_whitebox_e2e.py", "test_broker.py", "test_broker_hardening.py",
}


def pytest_collection_modifyitems(items):
    """Attach one primary deterministic category to every collected test."""
    for item in items:
        if item.get_closest_marker("model") or item.get_closest_marker("external_tool"):
            continue
        if item.path.name in _INTEGRATION_LOCAL_MODULES:
            item.add_marker(pytest.mark.integration_local)
        else:
            item.add_marker(pytest.mark.unit)


@pytest.fixture
def config(tmp_path) -> HarnessConfig:
    """An isolated global home + programs dir under a temp tree."""
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def scope() -> ScopeModel:
    return ScopeModel(
        include=ScopeSet(
            domains=["example.test"],
            wildcards=["*.example.test"],
        ),
        exclude=ScopeSet(domains=["admin.example.test"]),
    )


@pytest.fixture
def roe() -> ROEModel:
    return ROEModel()


@pytest.fixture
def engagement(scope, roe) -> Engagement:
    return Engagement(
        program=ProgramModel(name="fixture", platform="custom", status="active"),
        scope=scope,
        roe=roe,
        headers=HeadersModel(),
        accounts=AccountsModel(),
        reporting=ReportingModel(),
    )


@pytest.fixture
def db(tmp_path) -> HuntDB:
    d = HuntDB(tmp_path / "state" / "hunt.db", program_slug="acme-test")
    yield d
    d.close()


@pytest.fixture
def allowed_engagement() -> Engagement:
    """Engagement whose scope covers loopback and whose ROE permits automation —
    used to exercise the broker's happy path against a *local* fixture server."""
    scope = ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"]))
    return Engagement(
        program=ProgramModel(name="loopback", platform="custom", status="active"),
        scope=scope,
        roe=ROEModel(automation_allowed=True),
        headers=HeadersModel(),
        accounts=AccountsModel(),
        reporting=ReportingModel(),
    )
