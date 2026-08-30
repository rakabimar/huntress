"""Finding linkage, independent validation, approvals, auth, and requests."""

import json
from types import SimpleNamespace

import pytest

from bughunt_harness.engagement.models import ScopeModel, ScopeSet
from bughunt_harness.errors import StateError
from bughunt_harness.scope.engine import ScopeEngine
from bughunt_harness.state.constants import APPROVAL_CONSUMED, VREVIEW_SUBMITTED


SCOPE = ScopeEngine(ScopeModel(include=ScopeSet(domains=["example.test"])))


def _checks(finding, passed=True):
    return {
        "scope_eligible": {"passed": passed}, "reproducible": {"passed": passed},
        "prerequisites": {"value": "regular test account"},
        "security_boundary": {"value": "cross-account ownership"},
        "attacker_control": {"value": "object id"},
        "demonstrated_impact": {"value": finding.impact_summary or "not demonstrated"},
        "intended_behavior": {"passed": passed},
        "false_positive_analysis": {"passed": passed},
        "evidence_quality": {"passed": passed}, "minimal_impact": {"passed": passed},
        "program_exclusions": {"passed": passed},
    }


def _linked_finding(db, title="IDOR", evidence=None):
    creator = db.start_session("pytest", "researcher", "acme-test")
    validator = db.start_session("pytest", "finding-validator", "acme-test")
    lead = db.add_lead(title, entity="example.test")
    hypothesis = db.create_hypothesis("Account B can read Account A object", lead_id=lead.id)
    db.set_hypothesis_status(hypothesis.id, "testing")
    evidence = evidence or db.add_evidence("request_response", f"{title}-artifact")
    test = db.add_test(hypothesis.id, "paired account differential")
    db.complete_test(test.id, "cross-account data returned", "supports", [evidence.public_id])
    finding = db.create_finding(
        title, affected_target="https://example.test/u", category="CWE-639",
        impact_summary="read another test account's private object",
        evidence_refs=[evidence.public_id], lead_id=lead.id,
        hypothesis_id=hypothesis.id, test_ids=[test.id],
        creator_session_id=creator.id,
    )
    return finding, creator, validator, evidence, test


def _submit(db, finding, validator, verdict="supported"):
    db.transition_finding(finding.id, "validation")
    review = db.begin_validation(finding.id, requested_by="researcher")
    submitted = db.submit_validation_review(
        review.id, verdict, reasoning_summary="attempted to disprove",
        check_results=_checks(finding, verdict == "supported"),
        evidence_refs=finding.evidence_refs if verdict == "supported" else [],
        reviewer_role="finding-validator", reviewer_session_id=validator.id,
    )
    return review, submitted


def test_validation_review_supported_finalizes_to_validated(db):
    finding, _creator, validator, _evidence, _test = _linked_finding(db)
    _review, submitted = _submit(db, finding, validator)
    assert submitted.status == VREVIEW_SUBMITTED
    finalized = db.finalize_validation(finding.id, scope_engine=SCOPE, program_active=True)
    assert finalized.status == "validated"


def test_validation_review_rejected_finalizes_to_killed(db):
    finding, _creator, validator, _evidence, _test = _linked_finding(db, "false positive")
    _submit(db, finding, validator, "rejected")
    assert db.finalize_validation(finding.id, scope_engine=SCOPE, program_active=True).status == "killed"


def test_validation_review_inconclusive_stays_in_validation(db):
    finding, _creator, validator, _evidence, _test = _linked_finding(db, "unclear")
    _submit(db, finding, validator, "inconclusive")
    assert db.finalize_validation(finding.id, scope_engine=SCOPE, program_active=True).status == "validation"


def test_finalize_without_review_raises(db):
    finding, *_ = _linked_finding(db, "no review")
    db.transition_finding(finding.id, "validation")
    with pytest.raises(StateError):
        db.finalize_validation(finding.id, scope_engine=SCOPE, program_active=True)


def test_submit_review_twice_raises(db):
    finding, _creator, validator, *_ = _linked_finding(db, "double submit")
    review, _submitted = _submit(db, finding, validator)
    with pytest.raises(StateError):
        db.submit_validation_review(
            review.id, "rejected", check_results=_checks(finding, False),
            reviewer_role="finding-validator", reviewer_session_id=validator.id,
        )


def test_researcher_cannot_self_validate(db):
    finding, creator, _validator, *_ = _linked_finding(db, "self review")
    db.transition_finding(finding.id, "validation")
    review = db.begin_validation(finding.id)
    with pytest.raises(StateError, match="finding-validator|creator"):
        db.submit_validation_review(
            review.id, "supported", check_results=_checks(finding),
            evidence_refs=finding.evidence_refs, reviewer_role="finding-validator",
            reviewer_session_id=creator.id,
        )


def test_validator_role_and_structured_checks_required(db):
    finding, _creator, validator, *_ = _linked_finding(db, "structured")
    db.transition_finding(finding.id, "validation")
    review = db.begin_validation(finding.id)
    with pytest.raises(StateError, match="finding-validator"):
        db.submit_validation_review(review.id, "supported", reviewer_session_id=validator.id)
    with pytest.raises(StateError, match="missing required checks"):
        db.submit_validation_review(
            review.id, "supported", reviewer_role="finding-validator",
            reviewer_session_id=validator.id, check_results={},
        )


def test_finding_a_cannot_use_finding_b_evidence(db):
    finding_a, _creator_a, validator_a, evidence_a, _test_a = _linked_finding(db, "A")
    finding_b, _creator_b, _validator_b, evidence_b, _test_b = _linked_finding(db, "B")
    db.transition_finding(finding_a.id, "validation")
    review = db.begin_validation(finding_a.id)
    with pytest.raises(StateError, match="only evidence linked"):
        db.submit_validation_review(
            review.id, "supported", check_results=_checks(finding_a),
            evidence_refs=[evidence_b.public_id], reviewer_role="finding-validator",
            reviewer_session_id=validator_a.id,
        )
    assert evidence_a.public_id in finding_a.evidence_refs
    assert evidence_b.public_id in finding_b.evidence_refs


def test_finding_linkage_roundtrip_and_integrity(db):
    finding, _creator, _validator, evidence, test = _linked_finding(db)
    got = db.get_finding(finding.id)
    assert got.linkage_state == "complete"
    assert got.test_ids == [test.id] and got.evidence_refs == [evidence.public_id]
    with pytest.raises(StateError, match="hypothesis does not belong"):
        db.update_finding(finding.id, lead_id=None)


def test_approval_consume_makes_it_invalid(db):
    approval = db.request_approval("race_test", "https://example.test", requested_by="attacker")
    db.approve_approval(approval.id, approved_by="tester")
    assert db.find_valid_approval("race_test", target="https://example.test").id == approval.id
    db.consume_approval(approval.id)
    assert db.get_approval(approval.id).status == APPROVAL_CONSUMED
    assert db.find_valid_approval("race_test", target="https://example.test") is None


def test_approval_expiry_invalidates(db):
    approval = db.request_approval(
        "race_test", "https://example.test", requested_by="attacker",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    db.approve_approval(approval.id)
    assert db.find_valid_approval("race_test", target="https://example.test") is None


def test_approval_security_principal_and_bounded_use(db):
    approval = db.request_approval(
        "race_test", "https://example.test", requested_by="attacker",
        program="acme-test", method="POST", params_hash="body-a",
        auth_context="account_a", constraints={"max_requests": 2},
    )
    db.approve_approval(approval.id)
    assert db.find_valid_approval(
        "race_test", "https://example.test", "acme-test", "POST", "body-a", "account_a",
    )
    assert db.find_valid_approval(
        "race_test", "https://example.test", "acme-test", "POST", "body-a", "account_b",
    ) is None
    assert db.record_approval_use(approval.id).status == "approved"
    assert db.record_approval_use(approval.id).status == "consumed"


def test_approval_list_pending(db):
    approval = db.request_approval("race_test", "https://example.test", requested_by="attacker")
    assert any(p.id == approval.id for p in db.list_pending_approvals())
    db.approve_approval(approval.id)
    assert all(p.id != approval.id for p in db.list_pending_approvals())


def test_auth_context_crud(db):
    context = db.create_auth_context("account_a", "bearer", ["env:TOKEN"], role="regular")
    assert context.enabled and context.role == "regular"
    assert db.get_auth_context_by_account("account_a").id == context.id
    db.update_auth_context(context.id, enabled=False)
    assert db.list_auth_contexts(enabled=True) == []
    assert len(db.list_auth_contexts(enabled=False)) == 1


def test_record_request_metadata(db):
    record = db.record_request(
        "acme-test", "GET", "https://example.test/x",
        auth_context="account_a", request_metadata={"hdr_count": 2},
        response_metadata={"status": 200}, body_hash="abc123", evidence_ref="EVD-1",
        controlled_mutation={"id": "other"},
    )
    assert record.public_id.startswith("REQ-")
    assert record.response_metadata == {"status": 200}
    assert record.controlled_mutation == {"id": "other"}


@pytest.mark.parametrize("runtime_returncode", [0, 1])
def test_independent_validator_launcher_uses_separate_role_bound_process(
    db, tmp_path, monkeypatch, runtime_returncode,
):
    from bughunt_harness.findings.independent import run_independent_validator
    import bughunt_harness.findings.independent as independent

    finding, creator, _unused_validator, *_ = _linked_finding(db, "launcher")
    ctx = SimpleNamespace(
        db=db, slug="acme-test", workspace=tmp_path,
        scope=SCOPE, record=SimpleNamespace(status="active"),
    )
    monkeypatch.setattr(independent.shutil, "which", lambda name: "/usr/bin/claude")

    def fake_run(argv, **kwargs):
        validator = db.latest_session()
        assert validator.id != creator.id
        assert validator.agent_role == "finding-validator"
        config_path = argv[argv.index("--mcp-config") + 1]
        config = json.loads(open(config_path, encoding="utf-8").read())
        server_env = config["mcpServers"]["bughunt"]["env"]
        assert server_env["BUGHUNT_SESSION_ID"] == str(validator.id)
        assert server_env["BUGHUNT_AGENT_ROLE"] == "finding-validator"
        review = db.latest_validation_review(finding.id)
        db.submit_validation_review(
            review.id, "supported", reasoning_summary="independent replay was unnecessary",
            check_results=_checks(finding), evidence_refs=finding.evidence_refs,
            reviewer_role="finding-validator", reviewer_session_id=validator.id,
        )
        return SimpleNamespace(returncode=runtime_returncode, stdout="submitted", stderr="budget ended")

    monkeypatch.setattr(independent.subprocess, "run", fake_run)
    result = run_independent_validator(ctx, finding.id, timeout_seconds=10)
    assert result["status"] == "validated"
    assert result["validator_session"] != creator.public_id
    assert ("runtime_warning" in result) is (runtime_returncode != 0)
    assert db.get_session(db.latest_session().id).status == "ended"


def test_independent_validator_recovers_exact_submitted_review_without_retry(
    db, tmp_path, monkeypatch,
):
    from bughunt_harness.findings.independent import run_independent_validator
    import bughunt_harness.findings.independent as independent

    finding, creator, validator, *_ = _linked_finding(db, "recovery")
    db.update_finding(finding.id, affected_target=f"GET {finding.affected_target}")
    finding = db.get_finding(finding.id)
    db.transition_finding(finding.id, "validation")
    review = db.begin_validation(
        finding.id, requested_by="autonomous-researcher",
        reviewer_type="finding-validator",
    )
    db.submit_validation_review(
        review.id, "supported", reasoning_summary="durable independent review",
        check_results=_checks(finding), evidence_refs=finding.evidence_refs,
        reviewer_role="finding-validator", reviewer_session_id=validator.id,
    )
    ctx = SimpleNamespace(
        db=db, slug="acme-test", workspace=tmp_path,
        scope=SCOPE, record=SimpleNamespace(status="active"),
    )
    monkeypatch.setattr(
        independent.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("submitted review must not launch another model"),
    )
    result = run_independent_validator(ctx, finding.id)
    assert result["status"] == "validated"
    assert result["review"] == review.public_id
    assert result["validator_session"] != creator.public_id
    assert result["recovered_submitted_review"] is True
