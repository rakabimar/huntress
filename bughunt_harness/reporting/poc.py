"""PoC documentation pipeline (spec §60).

Turns a validated test into a minimal, reproducible proof-of-concept description
— never a mass-exploitation or persistence tool.  If further validation is
higher risk, instructions are emitted as manual steps instead of being run.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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


__all__ = ["PoC"]