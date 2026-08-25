"""Regression tests for finding validation provenance, linkage, approvals,
auth contexts, and structured request records (P0.5 / P0.7 / P0.8 / P0.9)."""

import pytest

from bughunt_harness.errors import StateError
from bughunt_harness.state.constants import (
    APPROVAL_APPROVED,
    APPROVAL_CONSUMED,
    VREVIEW_SUBMITTED,
)


# -- validation review workflow (P0.7) ---------------------------------------


def test_validation_review_supported_finalizes_to_validated(db):
    f = db.create_finding("IDOR", affected_target="https://example.test/u")
    f = db.transition_finding(f.id, "validation")
    review = db.begin_validation(f.id, requested_by="validator", reviewer_type="agent")
    assert review.status == "open"
    assert review.verdict == "inconclusive"
    submitted = db.submit_validation_review(review.id, "supported", reasoning_summary="repro")
    assert submitted.status == VREVIEW_SUBMITTED
    assert submitted.verdict == "supported"
    finalized = db.finalize_validation(f.id)
    assert finalized.status == "validated"


def test_validation_review_rejected_finalizes_to_killed(db):
    f = db.create_finding("false positive", affected_target="https://example.test/u")
    f = db.transition_finding(f.id, "validation")
    review = db.begin_validation(f.id)
    db.submit_validation_review(review.id, "rejected")
    assert db.finalize_validation(f.id).status == "killed"


def test_validation_review_inconclusive_stays_in_validation(db):
    f = db.create_finding("unclear", affected_target="https://example.test/u")
    f = db.transition_finding(f.id, "validation")
    review = db.begin_validation(f.id)
    db.submit_validation_review(review.id, "inconclusive")
    assert db.finalize_validation(f.id).status == "validation"


def test_finalize_without_review_raises(db):
    f = db.create_finding("no review")
    db.transition_finding(f.id, "validation")
    with pytest.raises(StateError):
        db.finalize_validation(f.id)


def test_submit_review_twice_raises(db):
    f = db.create_finding("double submit")
    db.transition_finding(f.id, "validation")
    review = db.begin_validation(f.id)
    db.submit_validation_review(review.id, "supported")
    with pytest.raises(StateError):
        db.submit_validation_review(review.id, "rejected")


# -- finding linkage (P0.8) --------------------------------------------------


def test_finding_linkage_roundtrip(db):
    lead = db.add_lead("L", entity="example.test")
    hyp = db.create_hypothesis("H", lead_id=lead.id)
    test = db.add_test(hyp.id, "T")
    f = db.create_finding(
        "IDOR", affected_target="https://example.test/u",
        evidence_refs=["EVD-1"],
        lead_id=lead.id, hypothesis_id=hyp.id, test_ids=[test.id],
    )
    got = db.get_finding(f.id)
    assert got.lead_id == lead.id
    assert got.hypothesis_id == hyp.id
    assert got.test_ids == [test.id]
    assert got.evidence_refs == ["EVD-1"]
    # update_finding can rewire linkage without touching status.
    updated = db.update_finding(f.id, test_ids=[], lead_id=None)
    assert updated.test_ids == []
    assert updated.lead_id is None
    assert updated.status == "candidate"


# -- approval lifecycle (P0.5) -----------------------------------------------


def test_approval_consume_makes_it_invalid(db):
    a = db.request_approval("race_test", "https://example.test", requested_by="attacker")
    db.approve_approval(a.id, approved_by="tester")
    assert db.find_valid_approval("race_test", target="https://example.test").id == a.id
    db.consume_approval(a.id)
    assert db.get_approval(a.id).status == APPROVAL_CONSUMED
    # consumed approvals are no longer usable
    assert db.find_valid_approval("race_test", target="https://example.test") is None


def test_approval_expiry_invalidates(db):
    a = db.request_approval(
        "race_test", "https://example.test", requested_by="attacker",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    db.approve_approval(a.id)
    assert db.find_valid_approval("race_test", target="https://example.test") is None


def test_approval_list_pending(db):
    a = db.request_approval("race_test", "https://example.test", requested_by="attacker")
    pending = db.list_pending_approvals()
    assert any(p.id == a.id for p in pending)
    db.approve_approval(a.id)
    assert all(p.id != a.id for p in db.list_pending_approvals())


# -- auth contexts (P0.9) ----------------------------------------------------


def test_auth_context_crud(db):
    ac = db.create_auth_context("account_a", secret_refs=["env:TOKEN"])
    assert ac.enabled is True
    assert ac.secret_refs == ["env:TOKEN"]
    assert db.get_auth_context_by_account("account_a").id == ac.id
    db.update_auth_context(ac.id, enabled=False)
    assert db.get_auth_context(ac.id).enabled is False
    assert db.list_auth_contexts(enabled=True) == []
    assert len(db.list_auth_contexts(enabled=False)) == 1


# -- structured request records (P0.9) ---------------------------------------


def test_record_request_metadata(db):
    r = db.record_request(
        "acme-test", "GET", "https://example.test/x",
        auth_context="header_bundle", request_metadata={"hdr_count": 2},
        response_metadata={"status": 200}, body_hash="abc123", evidence_ref="EVD-1",
    )
    assert r.public_id.startswith("REQ-")
    assert r.method == "GET"
    assert r.url == "https://example.test/x"
    assert r.response_metadata == {"status": 200}
    assert r.body_hash == "abc123"