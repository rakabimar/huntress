"""Deterministic CVSS scoring facade.

Metric *choices* and their rationale are the AI skill's job; the *number* is
always computed by the maintained FIRST calculator library (``cvss``), never by
the model's arithmetic.  Severity banding is applied here, deterministically,
for both CVSS v4.0 and v3.1.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CVSSResult:
    version: str
    vector: str
    base_score: float
    severity: str
    metric_rationale: dict = field(default_factory=dict)
    uncertainties: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "vector": self.vector,
            "base_score": round(self.base_score, 1),
            "severity": self.severity,
            "metric_rationale": self.metric_rationale,
            "uncertainties": self.uncertainties,
        }


def severity_from_score(score: float) -> str:
    """Qualitative severity from a 0.0-10.0 CVSS score (v3.1 and v4.0 bands)."""
    if score is None:
        return "Unknown"
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _detect_version(vector: str) -> str:
    if vector.strip().startswith("CVSS:4.0"):
        return "4.0"
    if vector.strip().startswith("CVSS:3.1"):
        return "3.1"
    if vector.strip().startswith("CVSS:3.0"):
        return "3.0"
    raise ValueError(
        f"vector must start with CVSS:4.0 / CVSS:3.1 / CVSS:3.0, got: {vector[:16]!r}"
    )


def score_vector(vector: str) -> CVSSResult:
    """Score a CVSS vector, returning base score + severity."""
    v = vector.strip()
    version = _detect_version(v)

    # Managed library import (installed in the harness venv).
    from cvss import CVSS3, CVSS4  # type: ignore

    if version == "4.0":
        calculator = CVSS4(v)
    else:
        calculator = CVSS3(v)

    base = float(calculator.scores()[0])  # scores()[0] == base (v3.1 & v4.0)
    return CVSSResult(version=version, vector=v, base_score=base, severity=severity_from_score(base))


def validate_vector(vector: str) -> list[str]:
    """Return a list of validation errors (empty == valid)."""
    try:
        score_vector(vector)
        return []
    except Exception as exc:  # noqa: BLE001 - bounded by library exceptions
        return [str(exc)]


__all__ = ["CVSSResult", "severity_from_score", "score_vector", "validate_vector"]