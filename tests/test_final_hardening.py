"""Focused regressions for the final policy/autonomy/recon hardening pass."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from bughunt_harness.acceptance import _usage_from_output
from bughunt_harness.autonomy import goal_reached, start_autonomous_hunt, usage_snapshot
from bughunt_harness.config import HarnessConfig
from bughunt_harness.engagement.models import (
    AccountModel, AccountsModel, AutonomyModel, Engagement, ProgramModel, ROEModel,
    ScopeModel, ScopeSet,
)
from bughunt_harness.integrations.playwright import (
    browser_policy_preflight, classify_browser_action, write_program_mcp_config,
)
from bughunt_harness.mcp.server import _require_autonomous_test_binding, tool_names_for_role
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.recon import detect_recon_tools, generate_contextual_leads, get_recon_summary
from bughunt_harness.requests.broker import burp_proxy_status, detected_burp_proxy
from bughunt_harness.requests.broker import RequestBroker, request_params_hash
from bughunt_harness.scope.engine import ScopeEngine
from bughunt_harness.skills.registry import resolve_skill_slug


def _ctx(db, tmp_path, *, roe=None, autonomy=None, accounts=None):
    scope = ScopeModel(include=ScopeSet(domains=["example.test"]))
    engagement = Engagement(
        program=ProgramModel(name="fixture", status="active"), scope=scope,
        roe=roe or ROEModel(automation_allowed=True),
        autonomy=autonomy or AutonomyModel(enabled=True),
        accounts=accounts or AccountsModel(),
    )
    return SimpleNamespace(
        slug="acme-test", db=db, workspace=tmp_path, engagement=engagement,
        scope=ScopeEngine(scope), policy=PolicyEngine(scope, engagement.roe),
        record=SimpleNamespace(status="active"),
    )


def test_browser_semantics_auto_ask_deny_and_autonomous_raw_bypass_absent(db, tmp_path, monkeypatch):
    roe = ROEModel(
        automation_allowed=True, state_changing_actions=True,
        manual_approval_actions=["browser_financial_operation"],
    )
    accounts = AccountsModel(accounts=[AccountModel(id="account_a", enabled=True)])
    ctx = _ctx(db, tmp_path, roe=roe, accounts=accounts)
    assert ctx.policy.check("browser_observe", "https://example.test").as_dict()["mode"] == "AUTO"
    assert browser_policy_preflight(
        ctx, target_url="https://example.test/profile",
        action_semantics="test_account_mutation", account="account_a",
    )["mode"] == "AUTO"
    assert browser_policy_preflight(
        ctx, target_url="https://example.test/redeem",
        action_semantics="financial_operation", account="account_a",
    )["mode"] == "ASK"
    assert browser_policy_preflight(
        ctx, target_url="https://example.test/delete",
        action_semantics="irreversible_action", account="account_a",
    )["mode"] == "DENY"
    fake = tmp_path / "playwright-mcp"; fake.write_text("#!/bin/sh\n", encoding="utf-8"); fake.chmod(0o755)
    monkeypatch.setattr("bughunt_harness.integrations.playwright.playwright_command", lambda: [str(fake)])
    path = write_program_mcp_config(ctx, autonomous=True)
    assert list(json.loads(path.read_text())["mcpServers"]) == ["bughunt"]


def test_browser_model_cannot_downgrade_derived_risk():
    financial = classify_browser_action(
        target_url="https://example.test/redeem", declared_semantics="test_account_mutation",
        expected_effect="update profile", operation="click",
    )
    destructive = classify_browser_action(
        target_url="https://example.test/delete/account", declared_semantics="test_account_mutation",
        expected_effect="save", operation="click",
    )
    assert financial["action"] == "browser_financial_operation" and not financial["classification_confirmed"]
    assert destructive["action"] == "browser_irreversible_action"


def test_unknown_browser_mutation_is_ask_by_default(db, tmp_path):
    accounts = AccountsModel(accounts=[AccountModel(id="account_a", enabled=True)])
    ctx = _ctx(
        db, tmp_path, accounts=accounts,
        roe=ROEModel(automation_allowed=True, state_changing_actions=True),
    )
    decision = browser_policy_preflight(
        ctx, target_url="https://example.test/profile",
        action_semantics="looks_safe", account="account_a",
        expected_effect="unknown state change", operation="click",
    )
    assert decision["mode"] == "ASK"
    assert decision["classification"]["unknown_mutation"] is True


def test_burp_open_8080_is_candidate_not_enabled(monkeypatch, tmp_path):
    config = HarnessConfig(home=tmp_path / "home", burp_proxy="disabled")
    monkeypatch.setattr("bughunt_harness.requests.broker._tcp_open", lambda *a, **k: True)
    assert detected_burp_proxy(config) is None
    status = burp_proxy_status(config)
    assert status["candidate_8080"] and not status["configured"] and not status["verified"]
    explicit = HarnessConfig(home=tmp_path / "other", burp_proxy="http://127.0.0.1:8080")
    assert burp_proxy_status(explicit)["verified"]


def test_approval_bounds_are_atomic_and_temporal(db):
    session = db.start_session("pytest", "researcher", "acme-test")
    approval = db.request_approval(
        "race_test", "https://example.test/redeem", program="acme-test",
        method="POST", params_hash="fixed", session_id=session.id,
        auth_context="account_a",
        constraints={"max_requests": 2, "max_concurrency": 3, "duration_seconds": 30},
    )
    db.approve_approval(approval.id, "human")
    assert db.record_approval_use(approval.id).usage_count == 1
    consumed = db.record_approval_use(approval.id)
    assert consumed.usage_count == 2 and consumed.status == "consumed"
    try:
        db.record_approval_use(approval.id)
    except Exception as exc:
        assert "not approved" in str(exc)
    else:
        raise AssertionError("exhausted approval was reused")

    expired = db.request_approval(
        "race_test", "https://example.test/redeem", program="acme-test",
        method="POST", session_id=session.id, auth_context="account_a",
        expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        constraints={"max_requests": 1},
    )
    db.approve_approval(expired.id, "human")
    assert db.find_valid_approval(
        "race_test", target=expired.target, program="acme-test",
        method="POST", auth_context="account_a",
    ) is None
    assert db.find_valid_approval(
        "race_test", target=expired.target, program="acme-test",
        method="POST", auth_context="account_b",
    ) is None


def test_broker_uses_approved_concurrency_minimum(db, tmp_path, monkeypatch):
    engagement = Engagement(
        program=ProgramModel(name="fixture", status="active"),
        scope=ScopeModel(include=ScopeSet(domains=["example.test"])),
        roe=ROEModel(
            automation_allowed=True, race_conditions=True,
            max_rps=100, max_concurrency=10,
        ),
    )
    broker = RequestBroker(
        engagement, program_slug="acme-test", workspace=tmp_path, hunt_db=db,
    )
    broker.config = HarnessConfig(home=tmp_path / "home", burp_proxy="disabled")
    session = db.start_session("pytest", "researcher", "acme-test")
    target = "https://example.test/redeem"
    approval = db.request_approval(
        "race_test", target, program="acme-test", method="POST",
        params_hash=request_params_hash("POST", target, None, None, None),
        session_id=session.id, constraints={
            "max_requests": 2, "max_concurrency": 3, "duration_seconds": 30,
        },
    )
    db.approve_approval(approval.id, "human")
    observed = []
    monkeypatch.setattr(
        broker.limiter, "acquire",
        lambda host, rps, concurrency, **kwargs: observed.append(concurrency) or "lease",
    )
    monkeypatch.setattr(broker.limiter, "release", lambda *_args, **_kwargs: None)
    response = SimpleNamespace(
        status_code=200, text="ok", headers={}, content=b"ok", url=target,
    )
    monkeypatch.setattr("bughunt_harness.requests.broker.requests.request", lambda *a, **k: response)
    result = broker.execute(
        target=target, method="POST", action="race_test", session_id=session.id,
    )
    assert result.ok and observed == [3]


def test_broker_uses_configured_burp_ca_without_disabling_tls(db, tmp_path, monkeypatch):
    engagement = Engagement(
        program=ProgramModel(name="fixture", status="active"),
        scope=ScopeModel(include=ScopeSet(domains=["example.test"])),
        roe=ROEModel(automation_allowed=True),
    )
    broker = RequestBroker(
        engagement, program_slug="acme-test", workspace=tmp_path, hunt_db=db,
    )
    broker.config = HarnessConfig(
        home=tmp_path / "home", burp_proxy="http://127.0.0.1:8080",
        burp_ca=str(tmp_path / "burp-ca.pem"),
    )
    session = db.start_session("pytest", "researcher", "acme-test")
    observed = {}
    monkeypatch.setattr(
        "bughunt_harness.requests.broker.validate_ca_bundle",
        lambda value: (str(tmp_path / "burp-ca.pem"), "valid"),
    )
    monkeypatch.setattr(broker.limiter, "acquire", lambda *a, **k: "lease")
    monkeypatch.setattr(broker.limiter, "release", lambda *a, **k: None)
    response = SimpleNamespace(
        status_code=200, text="ok", headers={}, content=b"ok",
        url="https://example.test/",
    )
    def fake_request(*args, **kwargs):
        observed.update(kwargs)
        return response
    monkeypatch.setattr("bughunt_harness.requests.broker.requests.request", fake_request)
    result = broker.execute(
        target="https://example.test/", action="read_http", session_id=session.id,
    )
    assert result.ok
    assert observed["verify"] == str(tmp_path / "burp-ca.pem")
    assert observed["proxies"]["https"] == "http://127.0.0.1:8080"


def test_autonomy_activity_is_run_scoped_after_release_and_between_runs(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    first_session = db.start_session("pytest", "orchestrator", "acme-test")
    first = start_autonomous_hunt(ctx, first_session.id)
    lead = db.add_lead("one")
    db.claim_lead(lead.id, first_session.id)
    db.release_lead(lead.id)
    db.create_hypothesis("old run", lead_id=lead.id, autonomy_run_id=first.id)
    assert usage_snapshot(ctx, first)["leads_visited"] == 1
    db.stop_autonomy_run(first.id, "done")
    db.end_session(first_session.id)

    second_session = db.start_session("pytest", "orchestrator", "acme-test")
    second = start_autonomous_hunt(ctx, second_session.id)
    usage = usage_snapshot(ctx, second)
    assert usage["leads_visited"] == 0
    assert usage["hypotheses_per_lead"] == {}


def test_goal_precedence_does_not_stop_report_goal_at_validated(db, tmp_path):
    autonomy = AutonomyModel(
        enabled=True, goal="report_ready", stop_on_validated_finding=True,
    )
    ctx = _ctx(db, tmp_path, autonomy=autonomy)
    session = db.start_session("pytest", "orchestrator", "acme-test")
    run = start_autonomous_hunt(ctx, session.id)
    finding = db.create_finding("candidate", "https://example.test/x", creator_session_id=session.id)
    db._conn.execute("UPDATE finding SET status='validated' WHERE id=?", (finding.id,)); db._conn.commit()
    assert not goal_reached(ctx, run)
    db._conn.execute("UPDATE finding SET status='report_ready' WHERE id=?", (finding.id,)); db._conn.commit()
    assert goal_reached(ctx, run)


def test_role_surfaces_and_skill_aliases():
    orchestrator = tool_names_for_role("orchestrator")
    validator = tool_names_for_role("finding-validator")
    reporter = tool_names_for_role("reporter")
    assert "submit_validation_review" not in orchestrator
    assert "finalize_validation_review" in orchestrator
    assert "submit_validation_review" in validator
    assert "finalize_validation_review" not in tool_names_for_role("whitebox-audit-specialist")
    assert "run_recon_profile" not in reporter and "browser_action" not in reporter
    assert resolve_skill_slug("sqli") == "sql-injection"
    assert resolve_skill_slug("idor") == "api-authorization"
    assert resolve_skill_slug("jwt-misuse") == "jwt"


def test_autonomous_http_requires_matching_planned_test(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    lead = db.add_lead("lead")
    hypothesis = db.create_hypothesis("If X then Y", "bounded", lead.id)
    test = db.add_test(
        hypothesis.id, "compare", "GET", expected_if_true="different owner",
        expected_if_false="access denied",
    )
    with pytest.raises(RuntimeError, match="requires both"):
        _require_autonomous_test_binding(ctx, None, None)
    with pytest.raises(RuntimeError, match="not linked"):
        other = db.create_hypothesis("Other", "bounded", lead.id)
        _require_autonomous_test_binding(ctx, test.public_id, other.public_id)
    assert _require_autonomous_test_binding(ctx, test.public_id, hypothesis.public_id) == (
        test.id, hypothesis.id,
    )


def test_httpx_detector_continues_past_python_collision(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir(); second.mkdir()
    py_httpx = first / "httpx"
    pd_httpx = second / "httpx"
    py_httpx.write_text("#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL'\n", encoding="utf-8")
    pd_httpx.write_text("#!/bin/sh\necho 'ProjectDiscovery httpx current version v9.9.9'\n", encoding="utf-8")
    py_httpx.chmod(0o755); pd_httpx.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(second)]))
    detected = detect_recon_tools()["httpx"]
    assert detected["available"] and detected["path"] == str(pd_httpx.resolve())
    assert detected["candidates"][0]["selected"] is False
    assert detected["candidates"][1]["selected"] is True


def test_recon_summary_counts_over_1000_and_paginates(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    for index in range(1005):
        db.upsert_asset(
            type="host", value=f"h{index}.example.test",
            normalized_value=f"h{index}.example.test", scope_status="in_scope",
        )
    summary = get_recon_summary(ctx)
    first = db.list_assets(limit=1000, offset=0)
    second = db.list_assets(limit=1000, offset=1000)
    assert summary["hosts"]["total"] == 1005
    assert len(first) == 1000 and len(second) == 5


def test_new_parameter_reopens_and_reprioritizes_existing_recon_lead(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    run1 = db.start_recon_run(profile="standard")
    host, _ = db.upsert_asset(type="host", value="example.test", normalized_value="example.test", scope_status="in_scope")
    endpoint, _ = db.upsert_endpoint(
        host_asset_id=host["id"], scheme="https", method="PATCH",
        normalized_path="/api/orders/{id}", auth_observed=True,
        metadata={"suggested_skills": ["api-authorization"], "interest_reasons": ["API surface"]},
    )
    db.update_surface_score("endpoint", endpoint["id"], 70, ["API surface"])
    made = generate_contextual_leads(ctx, run1["id"])
    lead = db.get_lead(int(made[0].split("-")[1]))
    db.claim_lead(lead.id, db.start_session("pytest", "researcher", "acme-test").id)
    db.close_lead(lead.id)

    run2 = db.start_recon_run(profile="standard")
    parameter, _ = db.upsert_endpoint_parameter(
        endpoint_id=endpoint["id"], name="user_id", location="json",
        user_controlled=True, object_identifier_candidate=True,
    )
    change = db.add_recon_change(
        recon_run_id=run2["id"], change_type="NEW_PARAMETER",
        entity_type="endpoint_parameter", entity_id=parameter["id"],
        new_value="user_id", interest_score=30,
    )
    reopened = generate_contextual_leads(ctx, run2["id"])
    assert lead.public_id in reopened
    updated = db.get_lead(lead.id)
    assert updated.status == "open" and updated.priority == "high"
    assert change["public_id"] in updated.rationale


def test_model_smoke_usage_reads_configured_model_from_claude_result():
    stdout = json.dumps({
        "usage": {"input_tokens": 12, "output_tokens": 3},
        "modelUsage": {"provider-model": {"inputTokens": 12}},
    })
    model, usage = _usage_from_output("claude", stdout)
    assert model == "provider-model"
    assert usage == {"input_tokens": 12, "output_tokens": 3}
