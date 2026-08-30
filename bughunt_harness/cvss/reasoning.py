"""Evidence-linked CVSS metric reasoning validation."""

from __future__ import annotations

from ..errors import StateError
from .engine import score_vector


def vector_metrics(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    metrics = {}
    for part in parts[1:]:
        if ":" in part:
            name, value = part.split(":", 1)
            metrics[name] = value
    return metrics


def score_with_reasoning(vector: str, reasoning: dict, *, finding_evidence: list[str]) -> dict:
    """Validate each selected vector metric before deterministic calculation."""
    metrics = vector_metrics(vector)
    missing = set(metrics) - set(reasoning)
    if missing:
        raise StateError(f"CVSS reasoning missing vector metrics: {sorted(missing)}")
    normalized = {}
    for metric, selected in metrics.items():
        item = reasoning.get(metric)
        if not isinstance(item, dict):
            raise StateError(f"CVSS {metric} reasoning must be an object")
        if str(item.get("value", "")) != selected:
            raise StateError(f"CVSS {metric} rationale value does not match vector ({selected})")
        rationale = str(item.get("rationale", "")).strip()
        if not rationale:
            raise StateError(f"CVSS {metric} requires a rationale")
        evidence = item.get("evidence_refs", item.get("evidence", [])) or []
        if not isinstance(evidence, list) or not set(evidence).issubset(set(finding_evidence)):
            raise StateError(f"CVSS {metric} references evidence outside the finding")
        normalized[metric] = {
            "value": selected,
            "rationale": rationale,
            "evidence_refs": evidence,
            "uncertainty": str(item.get("uncertainty", "none")),
        }
    result = score_vector(vector).as_dict()
    result["metric_reasoning"] = normalized
    result["uncertainties"] = [
        f"{metric}: {item['uncertainty']}" for metric, item in normalized.items()
        if item["uncertainty"].lower() not in {"", "none", "no", "n/a"}
    ]
    return result


__all__ = ["vector_metrics", "score_with_reasoning"]
