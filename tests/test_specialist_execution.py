import json
import subprocess
from types import SimpleNamespace

import pytest

from bughunt_harness.mcp.server import _active_run_id, _autonomy_gate
from bughunt_harness.specialists import SpecialistResult, run_specialist_task


def _task(db, timeout_seconds=30):
    creator = db.start_session("claude", "orchestrator", "acme-test")
    run = db.start_autonomy_run(creator.id, "budget_exhausted", {"max_total_requests": 10})
    lead = db.add_lead("bounded whitebox lead")
    task = db.create_specialist_task(
        created_by_role="orchestrator",
        assigned_role="whitebox-audit-specialist",
        goal="determine whether centralized authorization protects the route",
        session_id=creator.id,
        autonomy_run_id=run.id,
        lead_id=lead.id,
        input_summary="Inspect only the registered repository and linked route.",
        timeout_seconds=timeout_seconds,
        metadata={"skills": ["source-authorization-analysis"]},
    )
    return creator, run, lead, task


def test_specialist_launches_fresh_exact_role_session_and_persists_contract(
    db, tmp_path, monkeypatch,
):
    creator, run, lead, task = _task(db)
    ctx = SimpleNamespace(db=db, slug="acme-test", workspace=tmp_path)
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update({"argv": argv, "env": kwargs["env"]})
        payload = {
            "status": "completed",
            "summary": "No centralized ownership control was found.",
            "observations": ["Middleware establishes identity only."],
            "lead_refs": [lead.public_id],
            "hypothesis_refs": [],
            "test_recommendations": ["Compare the same owned object across two test accounts."],
            "evidence_refs": [],
            "unresolved_questions": ["Dynamic policy provider remains unknown."],
            "recommended_next_action": "Create one runtime authorization hypothesis.",
            "confidence": "medium",
        }
        wrapper = {
            "model": "fixture-model",
            "usage": {"input_tokens": 40, "output_tokens": 20, "total_cost_usd": 0.01},
            "result": json.dumps(payload),
        }
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(wrapper), stderr="")

    monkeypatch.setattr("bughunt_harness.specialists.shutil.which", lambda name: f"/fixture/{name}")
    monkeypatch.setattr("bughunt_harness.specialists.subprocess.run", fake_run)
    result = run_specialist_task(ctx, task["id"])

    assert result["status"] == "COMPLETED"
    assert result["creator_session_id"] == creator.id
    assert result["claimed_session_id"] != creator.id
    assert result["result_refs"] == [lead.public_id]
    assert result["metadata"]["structured_result"]["confidence"] == "medium"
    assert captured["env"]["BUGHUNT_AGENT_ROLE"] == "whitebox-audit-specialist"
    assert captured["env"]["BUGHUNT_PROGRAM"] == "acme-test"
    assert captured["env"]["BUGHUNT_SESSION_ID"] == str(result["claimed_session_id"])
    assert "--strict-mcp-config" in captured["argv"]
    claimed = db.get_session(result["claimed_session_id"])
    assert claimed.agent_role == "whitebox-audit-specialist" and claimed.status == "ended"
    turn = db.latest_agent_turn(claimed.id)
    assert turn["specialist_task_id"] == task["id"]
    assert turn["input_tokens"] == 40 and turn["output_tokens"] == 20
    assert db.hunt_metrics(run.id)["specialist_tasks"] == 1


def test_specialist_invalid_result_fails_without_retry_or_privilege_change(
    db, tmp_path, monkeypatch,
):
    _creator, _run, _lead, task = _task(db)
    ctx = SimpleNamespace(db=db, slug="acme-test", workspace=tmp_path)
    monkeypatch.setattr("bughunt_harness.specialists.shutil.which", lambda name: f"/fixture/{name}")
    monkeypatch.setattr(
        "bughunt_harness.specialists.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, stdout='{"summary":"missing fields","extra":true}', stderr=""),
    )
    result = run_specialist_task(ctx, task["id"])
    assert result["status"] == "FAILED"
    assert "invalid structured result" in result["error"]
    assert result["result_refs"] == []


def test_claimed_specialist_uses_only_its_parent_autonomy_run(db, monkeypatch):
    creator, run, _lead, task = _task(db)
    specialist = db.start_session("claude", "whitebox-audit-specialist", "acme-test")
    db.update_specialist_task(
        task["id"], status="RUNNING", claimed_session_id=specialist.id,
    )
    ctx = SimpleNamespace(db=db, slug="acme-test")
    monkeypatch.setenv("BUGHUNT_AUTONOMOUS", "1")
    monkeypatch.setenv("BUGHUNT_SESSION_ID", str(specialist.id))
    monkeypatch.setenv("BUGHUNT_AGENT_ROLE", "whitebox-audit-specialist")
    refreshed = []

    def fake_refresh(_ctx, session_id):
        refreshed.append(session_id)
        return {"mode": "CONTINUE"}

    monkeypatch.setattr("bughunt_harness.autonomy.refresh_autonomy", fake_refresh)
    assert _active_run_id(ctx) == run.id
    _autonomy_gate(ctx)
    assert refreshed == [creator.id]

    unrelated = db.start_session("claude", "whitebox-audit-specialist", "acme-test")
    monkeypatch.setenv("BUGHUNT_SESSION_ID", str(unrelated.id))
    with pytest.raises(RuntimeError, match="autonomous run is not active"):
        _active_run_id(ctx)


def test_specialist_result_canonicalizes_only_recognized_leading_public_refs():
    result = SpecialistResult.model_validate({
        "summary": "bounded result",
        "lead_refs": ["LEAD-3 — descriptive suffix"],
        "hypothesis_refs": ["hyp-12: suffix"],
        "evidence_refs": ["SOBS-2 source observation", "SRMAP-1", "EVD-9"],
    })
    assert result.lead_refs == ["LEAD-003"]
    assert result.hypothesis_refs == ["HYP-012"]
    assert result.evidence_refs == ["SOBS-002", "SRMAP-001", "EVD-009"]
    with pytest.raises(ValueError, match="reference must begin"):
        SpecialistResult.model_validate({"summary": "bad", "lead_refs": ["other LEAD-003"]})
