"""State-machine and HuntDB persistence tests (per-program research state)."""

import pytest

from bughunt_harness.errors import InvalidTransitionError, StateError
from bughunt_harness.state.constants import (
    FINDING_HUMAN_APPROVED,
    HYPO_REJECTED,
    LEAD_CLAIMED,
    RESULT_SUPPORTS,
    TEST_EXECUTED,
    validate_transition,
)


def test_legal_finding_pipeline():
    chain = [
        "candidate",
        "validation",
        "validated",
        "poc_ready",
        "scored",
        "report_ready",
        "qa_passed",
        "human_approved",
    ]
    for a, b in zip(chain, chain[1:]):
        assert validate_transition("finding", a, b)


def test_illegal_finding_jump_rejected():
    with pytest.raises(InvalidTransitionError):
        validate_transition("finding", "candidate", "validated")
    with pytest.raises(InvalidTransitionError):
        validate_transition("finding", "human_approved", "candidate")


def test_unknown_entity_rejected():
    with pytest.raises(InvalidTransitionError):
        validate_transition("nonsense", "a", "b")


# -- HuntDB end-to-end ---------------------------------------------------------


def test_hypothesis_loop(db):
    h = db.create_hypothesis("if X then Y", lead_id=None, confidence=0.6)
    assert h.status == "open"
    t = db.add_test(h.id, "send controlled request", expected_if_true="Y observed")
    assert t.status == "planned"
    t2 = db.complete_test(t.id, "Y observed", RESULT_SUPPORTS)
    assert t2.status == TEST_EXECUTED
    assert t2.result == RESULT_SUPPORTS
    # open -> testing -> supported (the legal chain; open -> supported is illegal)
    testing = db.set_hypothesis_status(h.id, "testing")
    assert testing.status == "testing"
    supported = db.set_hypothesis_status(h.id, "supported")
    assert supported.status == "supported"
    rej = db.create_hypothesis("bad idea")
    assert db.set_hypothesis_status(rej.id, HYPO_REJECTED).status == HYPO_REJECTED


def test_lead_lifecycle(db):
    lead = db.add_lead("interesting endpoint", entity="example.test")
    assert lead.public_id.startswith("LEAD-")
    sess = db.start_session("pytest", "attacker", "acme-test")
    claimed = db.claim_lead(lead.id, sess.id)
    assert claimed.status == LEAD_CLAIMED
    released = db.release_lead(lead.id)
    assert released.status == "open"
    # close is only legal from 'claimed', so re-claim then close.
    db.claim_lead(lead.id, sess.id)
    assert db.close_lead(lead.id).status == "closed"


def test_finding_full_pipeline(db):
    from bughunt_harness.engagement.models import ScopeModel, ScopeSet
    from bughunt_harness.scope.engine import ScopeEngine

    creator = db.start_session("pytest", "researcher", "acme-test")
    validator = db.start_session("pytest", "finding-validator", "acme-test")
    lead = db.add_lead("users")
    hyp = db.create_hypothesis("cross-account read", lead_id=lead.id)
    db.set_hypothesis_status(hyp.id, "testing")
    evidence = db.add_evidence("request_response", "fixture")
    test = db.add_test(hyp.id, "differential")
    db.complete_test(test.id, "other account data", "supports", [evidence.public_id])
    f = db.create_finding(
        "IDOR in /users", affected_target="https://example.test/users",
        impact_summary="read another test account's private record",
        evidence_refs=[evidence.public_id], lead_id=lead.id,
        hypothesis_id=hyp.id, test_ids=[test.id], creator_session_id=creator.id,
    )
    assert f.status == "candidate"
    f = db.transition_finding(f.id, "validation")
    review = db.begin_validation(f.id)
    checks = {
        "scope_eligible": {"passed": True}, "reproducible": {"passed": True},
        "prerequisites": {"value": "regular account"},
        "security_boundary": {"value": "cross-account ownership"},
        "attacker_control": {"value": "user id"},
        "demonstrated_impact": {"value": f.impact_summary},
        "intended_behavior": {"passed": True},
        "false_positive_analysis": {"passed": True},
        "evidence_quality": {"passed": True}, "minimal_impact": {"passed": True},
        "program_exclusions": {"passed": True},
    }
    db.submit_validation_review(
        review.id, "supported", check_results=checks,
        evidence_refs=f.evidence_refs, reviewer_role="finding-validator",
        reviewer_session_id=validator.id,
    )
    f = db.finalize_validation(
        f.id, scope_engine=ScopeEngine(ScopeModel(include=ScopeSet(domains=["example.test"]))),
        program_active=True,
    )
    assert f.status == "validated"
    stages = ["poc_ready", "scored", "report_ready", "qa_passed", "human_approved"]
    for s in stages:
        f = db.transition_finding(f.id, s)
        assert f.status == s
    assert f.status == FINDING_HUMAN_APPROVED
    # Once human_approved, no further transition is legal.
    with pytest.raises(InvalidTransitionError):
        db.transition_finding(f.id, "candidate")


def test_illegal_finding_transition_raises(db):
    f = db.create_finding("blocked finding")
    with pytest.raises(StateError):
        db.transition_finding(f.id, "validated")  # candidate -> validated is illegal


def test_checkpoint_roundtrip(db):
    lead = db.add_lead("checkpoint lead")
    hyp = db.create_hypothesis("checkpoint hypothesis", lead_id=lead.id)
    test_a = db.add_test(hyp.id, "a")
    test_b = db.add_test(hyp.id, "b")
    cp = db.save_checkpoint(
        active_lead_id=lead.id,
        completed_tests=[test_a.id, test_b.id],
        recent_observations=["odd redirect observed"],
        next_action="retest with account_b",
    )
    latest = db.latest_checkpoint()
    assert latest.id == cp.id
    assert latest.completed_tests == [test_a.id, test_b.id]
    assert latest.next_action == "retest with account_b"


def test_approval_roundtrip(db):
    a = db.request_approval("race_test", "https://example.test", requested_by="attacker")
    assert a.status == "pending"
    assert db.decide_approval(a.id, "approved", decided_by="human").status == "approved"


def test_evidence(db):
    e = db.add_evidence("request_response", "GET https://example.test/x", preview="HTTP 200")
    assert e.public_id.startswith("EVD-")
    assert len(db.list_evidence()) == 1


def test_missing_row_raises(db):
    with pytest.raises(StateError):
        db.get_finding(9999)
