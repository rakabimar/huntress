"""PoC documentation pipeline (spec §60).

Turns a validated test into a minimal, reproducible proof-of-concept description
— never a mass-exploitation or persistence tool.  If further validation is
higher risk, instructions are emitted as manual steps instead of being run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..redact import redact_text


@dataclass
class PoC:
    prerequisites: list[str] = field(default_factory=list)
    account_setup: str = ""
    baseline_behavior: str = ""
    controlled_change: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    observed_result: str = ""
    impact_verification: str = ""
    cleanup: str = ""
    manual_only: bool = False

    def render(self) -> str:
        lines = ["## Proof of Concept", ""]
        if self.manual_only:
            lines.append("> Higher-risk validation not auto-run; perform manually.")

        def section(title: str, body: str) -> None:
            lines.append(f"### {title}")
            lines.append(body or "_not provided_")
            lines.append("")

        if self.prerequisites:
            lines.append("### Prerequisites")
            lines.extend(f"- {p}" for p in self.prerequisites)
            lines.append("")
        section("Account setup", self.account_setup)
        section("Baseline behavior", self.baseline_behavior)
        section("Controlled change", self.controlled_change)
        if self.reproduction_steps:
            lines.append("### Steps to Reproduce")
            lines.extend(f"{i}. {s}" for i, s in enumerate(self.reproduction_steps, 1))
            lines.append("")
        section("Observed result", self.observed_result)
        section("Impact verification", self.impact_verification)
        section("Cleanup / reset", self.cleanup or "n/a — no persistent change made")
        return "\n".join(lines).rstrip() + "\n"


@dataclass
class PoCQA:
    passed: bool
    issues: list[str] = field(default_factory=list)


def run_poc_qa(poc: PoC, *, evidence_refs: list[str], finding_status: str) -> PoCQA:
    issues = []
    if finding_status != "validated":
        issues.append("PoC preparation requires a validated finding")
    if not poc.prerequisites:
        issues.append("prerequisites are missing")
    if not poc.account_setup:
        issues.append("account context is missing")
    if not poc.baseline_behavior:
        issues.append("baseline behavior is missing")
    if not poc.controlled_change:
        issues.append("controlled change is missing")
    if not poc.reproduction_steps:
        issues.append("reproduction steps are missing")
    if not poc.observed_result or not poc.impact_verification:
        issues.append("observed result or impact verification is missing")
    if not evidence_refs:
        issues.append("PoC is not evidence-linked")
    rendered = poc.render()
    if redact_text(rendered) != rendered:
        issues.append("PoC may contain a reusable secret")
    destructive = (
        "drop table", "rm -rf", "denial of service", "flood", "mass enumerate",
        "delete account", "destroy",
    )
    if any(term in rendered.lower() for term in destructive):
        issues.append("PoC contains destructive or excessive behavior")
    return PoCQA(passed=not issues, issues=issues)


__all__ = ["PoC", "PoCQA", "run_poc_qa"]
