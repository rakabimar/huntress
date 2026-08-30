"""Finding validation contract (spec §41 / §57).

A candidate finding must NOT become ``validated`` until a deterministic gate
passes AND an adversarial reviewer has attempted to disprove it.  This module
implements the deterministic pre-gate; the adversarial reasoning is performed
by the ``finding-validator`` specialist agent, which reads the checklist produced
here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..state.constants import RESULT_SUPPORTS
from ..state.records import EvidenceRecord, FindingRecord, ResearchTestRecord
from ..scope.engine import ScopeEngine

SUPPORTED = "supported"
KILLED = "killed"
INCONCLUSIVE = "inconclusive"

CHECKLIST_QUESTIONS = [
    "Is it reproducible?",
    "What exact asset is affected?",
    "What prerequisite does the attacker need?",
    "What security boundary is crossed?",
    "What attacker-controlled input/action causes it?",
    "What actual security impact was demonstrated?",
    "Could this be intended behavior?",
    "Is it excluded by program policy?",
    "Is the evidence sufficient for a third party to reproduce?",
    "Can the issue be demonstrated with minimal impact?",
]


@dataclass
class ValidationVerdict:
    verdict: str  # supported | killed | inconclusive
    checklist: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == SUPPORTED

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "checklist": self.checklist, "reasons": self.reasons}


def assess_finding(
    finding: FindingRecord,
    *,
    scope_engine: ScopeEngine,
    tests: list[ResearchTestRecord],
    evidence: list[EvidenceRecord],
) -> ValidationVerdict:
    """Deterministic pre-gate for a candidate finding.

    ``scope_engine`` is built from the program's scope; ``tests``/``evidence``
    come from the same program's hunt DB (never another program's).
    """
    reasons: list[str] = []
    checklist: list[dict] = []

    def mark(question: str, answer: str, ok: bool) -> None:
        checklist.append({"question": question, "answer": answer, "satisfied": ok})

    # Isolation invariant: program-wide data is never admissible merely because
    # it exists.  Only explicit finding links can satisfy this gate.
    linked_test_ids = set(finding.test_ids)
    linked_evidence_ids = set(finding.evidence_refs)
    linked_tests = [
        t for t in tests
        if t.id in linked_test_ids and t.hypothesis_id == finding.hypothesis_id
    ]
    linked_evidence = [e for e in evidence if e.public_id in linked_evidence_ids]
    supporting = [
        t for t in linked_tests
        if t.result == RESULT_SUPPORTS
        and bool(set(t.evidence_refs).intersection(linked_evidence_ids))
    ]

    # 1. reproducibility — at least one supporting, executed test with evidence.
    reproducible = bool(supporting and any(t.evidence_refs for t in supporting))
    mark(CHECKLIST_QUESTIONS[0], f"{len(supporting)} supporting test(s)", reproducible)

    # 2. affected asset present.
    mark(CHECKLIST_QUESTIONS[1], finding.affected_target or "_unspecified_", bool(finding.affected_target))

    # 3-5. prerequisite / boundary / attacker input — from impact_summary narrative.
    narrative = finding.impact_summary or ""
    mark(CHECKLIST_QUESTIONS[2], "recorded in impact summary", bool(narrative))
    mark(CHECKLIST_QUESTIONS[3], "recorded in impact summary", bool(narrative))
    mark(CHECKLIST_QUESTIONS[4], "recorded in impact summary", bool(narrative))

    # 6. actual impact demonstrated.
    mark(CHECKLIST_QUESTIONS[5], narrative or "_none_", bool(narrative))

    # 7. intended behavior — requires adversarial judgment, never auto-passed.
    mark(CHECKLIST_QUESTIONS[6], "requires adversarial review", True)

    # 8. program policy / scope.
    in_scope = False
    if finding.affected_target:
        try:
            scope_target = re.sub(
                r"^\s*(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+(?=https?://)",
                "", finding.affected_target, flags=re.IGNORECASE,
            )
            in_scope = scope_engine.check(scope_target).allowed
        except ValueError:
            in_scope = False
    mark(CHECKLIST_QUESTIONS[7], "in scope" if in_scope else "OUT OF SCOPE", in_scope)

    # 9. evidence sufficiency — at least request_response/screenshot-grade evidence.
    rich_evidence = [e for e in linked_evidence if e.kind in ("request_response", "screenshot_reference", "file_reference")]
    sufficient = bool(linked_evidence_ids and rich_evidence)
    mark(CHECKLIST_QUESTIONS[8], f"{len(rich_evidence)} rich evidence record(s)", sufficient)

    # 10. minimal impact — advisory (judgment by validator).
    mark(CHECKLIST_QUESTIONS[9], "requires adversarial review", True)

    # Decision.
    if not in_scope:
        verdict = KILLED
        reasons.append("affected target is out of program scope")
    elif not reproducible:
        verdict = INCONCLUSIVE
        reasons.append("no reproducible supporting test with evidence")
    elif not finding.evidence_refs or not sufficient:
        verdict = INCONCLUSIVE
        reasons.append("evidence insufficient for third-party reproduction")
    elif not narrative:
        verdict = INCONCLUSIVE
        reasons.append("no demonstrated impact recorded")
    else:
        verdict = SUPPORTED
        reasons.append("deterministic gate passed; pending adversarial validation")

    return ValidationVerdict(verdict=verdict, checklist=checklist, reasons=reasons)


def structured_review_checks(
    finding: FindingRecord, *, assessment: ValidationVerdict,
    prerequisite: str, security_boundary: str, attacker_control: str,
) -> dict:
    """Create the required review skeleton for an independent validator.

    The caller still owns adversarial judgment.  This helper prevents missing
    fields but never converts an inconclusive deterministic gate to supported.
    """
    passed = assessment.verdict == SUPPORTED
    return {
        "scope_eligible": {"passed": passed},
        "reproducible": {"passed": passed, "evidence": list(finding.evidence_refs)},
        "prerequisites": {"value": prerequisite},
        "security_boundary": {"value": security_boundary},
        "attacker_control": {"value": attacker_control},
        "demonstrated_impact": {
            "value": finding.impact_summary,
            "evidence": list(finding.evidence_refs),
        },
        "intended_behavior": {"passed": passed},
        "false_positive_analysis": {"passed": passed},
        "evidence_quality": {"passed": passed},
        "minimal_impact": {"passed": passed},
        "program_exclusions": {"passed": passed},
    }


__all__ = [
    "SUPPORTED",
    "KILLED",
    "INCONCLUSIVE",
    "CHECKLIST_QUESTIONS",
    "ValidationVerdict",
    "assess_finding",
    "structured_review_checks",
]
