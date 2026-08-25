"""Policy engine tests: R0–R4 taxonomy, ROE gates, approval/deny decisions."""

import pytest

from bughunt_harness.engagement.models import ROEModel, ScopeModel, ScopeSet
from bughunt_harness.errors import (
    ActionForbiddenError,
    ApprovalRequiredError,
    PolicyError,
)
from bughunt_harness.policy.engine import (
    ALLOW,
    APPROVAL_REQUIRED,
    DENY,
    PolicyEngine,
)

TARGET = "https://api.example.test"


def _engine(roe=None, scope=None) -> PolicyEngine:
    if scope is None:
        scope = ScopeModel(
            include=ScopeSet(domains=["example.test"], wildcards=["*.example.test"])
        )
    return PolicyEngine(scope, roe or ROEModel())


def test_analysis_always_allowed():
    eng = _engine()  # automation disabled
    assert eng.check("analyze").decision == ALLOW


def test_r4_actions_denied_by_default():
    eng = _engine(ROEModel(automation_allowed=True))
    assert eng.check("dos", TARGET).decision == DENY
    assert eng.check("destructive", TARGET).decision == DENY


def test_network_read_requires_automation():
    assert _engine().check("read_http", TARGET).decision == APPROVAL_REQUIRED
    assert _engine(ROEModel(automation_allowed=True)).check("read_http", TARGET).decision == ALLOW


def test_out_of_scope_denied_even_with_automation():
    eng = _engine(ROEModel(automation_allowed=True))
    d = eng.check("read_http", "https://evil.org")
    assert d.decision == DENY
    assert "out_of_scope" in d.reason


def test_forbidden_actions_deny_first():
    eng = _engine(ROEModel(automation_allowed=True, forbidden_actions=["read_http"]))
    assert eng.check("read_http", TARGET).decision == DENY
    assert eng.check("read_http", TARGET).reason == "forbidden_for_program"


def test_manual_approval_list():
    eng = _engine(ROEModel(manual_approval_actions=["read_http"], automation_allowed=True))
    assert eng.check("read_http", TARGET).decision == APPROVAL_REQUIRED


def test_r3_requires_approval():
    # R3 actions whose *activity flag* is enabled still require human approval
    # (the R3 gate sits below the ROE activity-flag gate).
    eng = _engine(
        ROEModel(
            automation_allowed=True,
            race_conditions=True,
            out_of_band_testing=True,
            brute_force=True,
        )
    )
    assert eng.check("race_test", TARGET).decision == APPROVAL_REQUIRED
    assert eng.check("oob_test", TARGET).decision == APPROVAL_REQUIRED
    assert eng.check("brute_force", TARGET).decision == APPROVAL_REQUIRED


def test_roe_activity_flag_gate():
    # authorization_testing defaults True; authentication_testing defaults False.
    eng = _engine(ROEModel(automation_allowed=True))
    assert eng.check("authorization_test", TARGET).decision == ALLOW
    d = eng.check("authentication_test", TARGET)
    assert d.decision == DENY
    assert "not_allowed_by_roe" in d.reason


def test_unknown_action_raises():
    with pytest.raises(PolicyError):
        _engine().check("definitely_not_an_action", TARGET)


def test_require_allow_raises_typed_errors():
    eng = _engine(ROEModel(automation_allowed=True))
    with pytest.raises(ActionForbiddenError):
        eng.require_allow("dos", TARGET)
    eng2 = _engine()  # automation disabled
    with pytest.raises(ApprovalRequiredError):
        eng2.require_allow("read_http", TARGET)
    assert eng.require_allow("read_http", TARGET).allowed