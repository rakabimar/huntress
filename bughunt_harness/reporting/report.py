"""Report building and rendering (spec §61).

Reports are generated ONLY from structured, validated finding state.  The
wording explicitly separates demonstrated facts from interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReportData:
    title: str
    summary: str
    affected_asset: str = ""
    weakness: str = ""
    cwe: str = ""
    severity: str = ""
    cvss_vector: str = ""
    prerequisites: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    poc: str = ""
    expected_result: str = ""
    actual_result: str = ""
    impact: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    interpretation: list[str] = field(default_factory=list)  # reasoned, not demonstrated
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        out: list[str] = []
        out.append(f"# {self.title or 'Untitled Finding'}")
        out.append("")

        def sec(title: str, body: str) -> None:
            out.append(f"## {title}")
            out.append(body or "_not provided_")
            out.append("")

        out.append("## Summary")
        out.append(self.summary or "_not provided_")
        out.append("")
        sec("Affected Asset", self.affected_asset)
        if self.weakness or self.cwe:
            sec("Weakness", f"{self.weakness} ({self.cwe})" if self.cwe else self.weakness)
        sec("Severity", self.severity or "_not provided_")
        if self.cvss_vector:
            sec("CVSS Vector", f"`{self.cvss_vector}`")
        if self.prerequisites:
            out.append("## Prerequisites")
            out.extend(f"- {p}" for p in self.prerequisites)
            out.append("")
        if self.steps:
            out.append("## Steps to Reproduce")
            out.extend(f"{i}. {s}" for i, s in enumerate(self.steps, 1))
            out.append("")
        if self.poc:
            out.append("## Proof of Concept")
            out.append(self.poc.strip())
            out.append("")
        sec("Expected Result", self.expected_result)
        sec("Actual Result", self.actual_result)
        sec("Security Impact", self.impact)

        if self.interpretation:
            out.append("## Interpretation")
            out.append("> The following points are reasoned inferences, distinct from demonstrated facts:")
            out.extend(f"- {i}" for i in self.interpretation)
            out.append("")

        if self.evidence:
            out.append("## Evidence")
            out.extend(f"- {e}" for e in self.evidence)
            out.append("")
        sec("Remediation", self.remediation)
        if self.notes:
            out.append("## Additional Notes")
            out.extend(f"- {n}" for n in self.notes)
            out.append("")
        return "\n".join(out).rstrip() + "\n"


__all__ = ["ReportData"]