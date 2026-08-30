"""Bounded autonomous controller stop/continue/lead-selection tests."""

from types import SimpleNamespace

from bughunt_harness.autonomy import (
    build_checkpoint_from_current_state, refresh_autonomy, start_autonomous_hunt,
)
from bughunt_harness.engagement.models import (
    AutonomyModel, Engagement, ProgramModel, ROEModel, ScopeModel, ScopeSet,
)
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.scope.engine import ScopeEngine


def _ctx(db, **budgets):
    autonomy = AutonomyModel(enabled=True, **budgets)
    engagement = Engagement(
        program=ProgramModel(name="local", status="active"),
        scope=ScopeModel(include=ScopeSet(domains=["example.test"])),
        roe=ROEModel(automation_allowed=True), autonomy=autonomy,
    )
    return SimpleNamespace(
        db=db, engagement=engagement, slug="acme-test",
        record=SimpleNamespace(status="active"),
    )


def _start(db, ctx):
    session = db.start_session("pytest", "orchestrator", "acme-test")
    run = start_autonomous_hunt(ctx, session.id)
    return session, run


def test_rejected_hypothesis_does_not_stop_session(db):
    ctx = _ctx(db)
    session, _run = _start(db, ctx)
    lead = db.add_lead("lead")
    db.claim_lead(lead.id, session.id)
    rejected = db.create_hypothesis("rejected", lead_id=lead.id)
    db.set_hypothesis_status(rejected.id, "rejected")
    db.create_hypothesis("next justified hypothesis", lead_id=lead.id)
    decision = refresh_autonomy(ctx, session.id)
    assert decision["mode"] == "CONTINUE"


def test_closed_lead_moves_to_next_ranked_lead(db):
    ctx = _ctx(db)
    session, _run = _start(db, ctx)
    first = db.add_lead("first", priority="medium")
    second = db.add_lead("second", priority="high")
    db.claim_lead(first.id, session.id)
    db.close_lead(first.id)
    decision = refresh_autonomy(ctx, session.id)
    assert decision["mode"] == "CONTINUE"
    assert decision["active_lead"] == second.public_id
    assert db.get_lead(second.id).claimed_session == str(session.id)


def test_total_request_budget_stops_and_checkpoints(db):
    ctx = _ctx(db, max_total_requests=1)
    session, _run = _start(db, ctx)
    db.record_request("acme-test", "GET", "https://example.test", session_id=session.id)
    decision = refresh_autonomy(ctx, session.id)
    assert decision["mode"] == "STOP"
    assert decision["budget"] == "max_total_requests"
    checkpoint = db.latest_checkpoint()
    assert checkpoint.session_id == session.id
    assert "budget exhausted" in checkpoint.next_action


def test_pending_ask_pauses_with_bounded_plan_checkpoint(db):
    ctx = _ctx(db)
    session, _run = _start(db, ctx)
    approval = db.request_approval(
        "race_test", "https://example.test/redeem", requested_by="orchestrator",
        program="acme-test", method="POST", session_id=session.id,
        auth_context="account_a",
        constraints={"max_requests": 10, "max_concurrency": 5, "duration_seconds": 30},
    )
    decision = refresh_autonomy(ctx, session.id)
    assert decision["mode"] == "ASK"
    assert decision["approval"] == approval.public_id
    checkpoint = db.latest_checkpoint()
    assert checkpoint.pending_approval_id == approval.id


def test_pending_approval_from_old_run_does_not_pause_new_run(db):
    ctx = _ctx(db)
    session_a, run_a = _start(db, ctx)
    old = db.request_approval(
        "race_test", "https://example.test/redeem", requested_by="orchestrator",
        program="acme-test", method="POST", session_id=session_a.id,
        constraints={"max_requests": 1},
    )
    assert old.autonomy_run_id == run_a.id
    db.stop_autonomy_run(run_a.id, "fixture rollover", "stopped")
    db.end_session(session_a.id)
    session_b, run_b = _start(db, ctx)
    db.add_lead("new-run lead")
    decision = refresh_autonomy(ctx, session_b.id)
    assert decision["mode"] == "CONTINUE"
    assert db.list_pending_approvals(autonomy_run_id=run_a.id)[0].id == old.id
    assert db.list_pending_approvals(autonomy_run_id=run_b.id) == []


def test_checkpoint_builder_restores_actual_research_state(db):
    ctx = _ctx(db)
    session, _run = _start(db, ctx)
    lead = db.add_lead("active")
    db.claim_lead(lead.id, session.id)
    hypothesis = db.create_hypothesis("open", lead_id=lead.id)
    planned = db.add_test(hypothesis.id, "planned distinguishing test")
    checkpoint = build_checkpoint_from_current_state(ctx, session.id)
    assert checkpoint.active_lead_id == lead.id
    assert hypothesis.id in checkpoint.active_hypotheses
    assert planned.id in checkpoint.pending_tests
    assert "TEST-" in checkpoint.next_action


def test_program_inactive_is_legitimate_stop(db):
    ctx = _ctx(db)
    session, _run = _start(db, ctx)
    ctx.record.status = "paused"
    decision = refresh_autonomy(ctx, session.id)
    assert decision == {
        "mode": "STOP", "reason": "program_inactive", "run": "RUN-001",
    }


def test_validated_finding_goal_stops(db):
    ctx = _ctx(db)
    creator, _run = _start(db, ctx)
    validator = db.start_session("pytest", "finding-validator", "acme-test")
    lead = db.add_lead("candidate")
    hypothesis = db.create_hypothesis("cross-boundary result", lead_id=lead.id)
    evidence = db.add_evidence("request_response", "fixture")
    test = db.add_test(hypothesis.id, "distinguish")
    db.complete_test(test.id, "protected result", "supports", [evidence.public_id])
    finding = db.create_finding(
        "validated", "https://example.test/object", "CWE-639",
        "read another account's private object", [evidence.public_id],
        lead_id=lead.id, hypothesis_id=hypothesis.id, test_ids=[test.id],
        creator_session_id=creator.id,
    )
    db.transition_finding(finding.id, "validation")
    review = db.begin_validation(finding.id)
    checks = {
        "scope_eligible": {"passed": True}, "reproducible": {"passed": True},
        "prerequisites": {"value": "regular account"},
        "security_boundary": {"value": "ownership"},
        "attacker_control": {"value": "object id"},
        "demonstrated_impact": {"value": finding.impact_summary},
        "intended_behavior": {"passed": True},
        "false_positive_analysis": {"passed": True},
        "evidence_quality": {"passed": True}, "minimal_impact": {"passed": True},
        "program_exclusions": {"passed": True},
    }
    db.submit_validation_review(
        review.id, "supported", check_results=checks,
        evidence_refs=finding.evidence_refs, reviewer_role="finding-validator",
        reviewer_session_id=validator.id,
    )
    db.finalize_validation(
        finding.id, scope_engine=ScopeEngine(ctx.engagement.scope), program_active=True,
    )
    decision = refresh_autonomy(ctx, creator.id)
    assert decision["mode"] == "STOP" and decision["reason"] == "goal_reached"


def test_stale_recon_is_eligible_again_in_a_new_session(db, monkeypatch):
    ctx = _ctx(db)
    ctx.policy = PolicyEngine(ctx.engagement.scope, ctx.engagement.roe)
    previous = db.start_recon_run(profile="passive", metadata={"session_id": 999})
    db.finish_recon_run(previous["id"], status="completed", metadata={"session_id": 999})
    session, _run = _start(db, ctx)
    called = []

    monkeypatch.setattr("bughunt_harness.recon.recon_is_fresh", lambda *_args, **_kwargs: False)

    def fake_recon(_ctx, **kwargs):
        called.append(kwargs["profile"])
        return SimpleNamespace(run_id="RECON-002", reason="completed")

    monkeypatch.setattr("bughunt_harness.recon.run_authorized_recon", fake_recon)
    decision = refresh_autonomy(ctx, session.id)

    assert called == ["passive"]
    assert decision["reason"] == "recon_executed"
