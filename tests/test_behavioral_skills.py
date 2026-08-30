"""Behavioral eval orchestration tests; no model runtime or token spend."""

from __future__ import annotations

import re

from bughunt_harness.skills import behavioral


def _fixture_answer(_runtime: str, prompt: str, _timeout: int) -> dict:
    skill = re.search(r"CANONICAL SKILL: ([a-z0-9-]+)", prompt).group(1)
    group = re.search(r"CASE GROUP: ([a-z-]+)", prompt).group(1)
    tools = {
        "positive": "send_authorized_http_request",
        "negative": "none",
        "routing": "policy_preflight",
        "false-positive": "none",
        "evidence": "none",
        "tool-selection": "policy_preflight",
        "safety": "none",
        "complex-scenario": "policy_preflight",
    }
    return {
        "selected_skill": skill,
        "promote_finding": False,
        "mode": "DENY" if group == "safety" else "AUTO",
        "external_request": False,
        "hypothesis": "one falsifiable boundary claim",
        "refuting_observation": "the authoritative control rejects the exact comparison",
        "evidence_required": True,
        "tool_selection": tools[group],
        "reasoning": "fixture evaluator",
        "planned_requests": 0,
        "stop_condition_correct": True,
        "source_runtime_correlation": "source commit maps to the exact runtime surface",
    }


def test_behavioral_runner_and_ablation_are_optional_and_structured(monkeypatch, tmp_path):
    monkeypatch.setattr(behavioral, "_invoke", _fixture_answer)
    result = behavioral.run_behavioral_evals(
        runtime="claude", skill="api-authorization", timeout_seconds=1,
        ablation=True, runs=3, output_path=tmp_path / "result.json",
    )
    assert result["ablation"] is True
    assert result["with_skill"]["case_count"] == 8
    assert result["without_skill"]["case_count"] == 8
    assert result["with_skill"]["skill_instructions_loaded"] is True
    assert result["without_skill"]["skill_instructions_loaded"] is False
    assert "routing_accuracy" in result["metric_accuracy_delta"]
    assert result["with_skill"]["run_count"] == 3
    assert result["with_skill"]["metrics"]["routing_accuracy"]["variance"] == 0.0
    assert "FALSE_POSITIVE_REJECTION" in result["with_skill"]["stages"]
    assert result["with_skill"]["usage"]["status"] == "UNAVAILABLE"
    assert (tmp_path / "result.json").is_file()
