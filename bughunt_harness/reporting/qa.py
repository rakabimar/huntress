"""Deterministic report QA (plus AI QA in the report-qa specialist).

A report cannot pass QA while evidence is missing, impact is unsupported, or
sensitive values are present.  These checks are deterministic and independent of
any model opinion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..redact import SENSITIVE_HEADERS

# Keywords that indicate a PoC may depend on destructive / disallowed behavior.
_DESTRUCTIVE_HINTS = re.compile(
    r"(?i)\b(rm\s+-rf|drop\s+table|truncate|format\s+disk|dd\s+if=|mass\s+enumerat"
    r"|spam|flood|ddos|denial\s*of\s*service)\b"
)
# Very common secret/PII shapes to catch in report prose.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization|proxy-authorization|cookie|set-cookie):\s*\S"),
    re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),  # JWT
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)api[-_]?key\s*[:=]\s*\S{12,}"),
]


@dataclass
class QAIssue:
    level: str  # fail | warn
    code: str
    message: str


@dataclass
class QAReport:
    issues: list[QAIssue | None]
    passed: bool

    def __post_init__(self):
        self.issues = [i for i in self.issues if i is not None]

    @property
    def failures(self) -> list:
        return [i for i in self.issues if i.level == "fail"]

    @property
    def warnings(self) -> list:
        return [i for i in self.issues if i.level == "warn"]


def run_qa(report: "ReportData", *, finding_status: str | None = None) -> QAReport:
    """Run deterministic QA checks on a rendered report."""
    issues: list[QAIssue | None] = []

    # Evidence must be present.
    if not report.evidence:
        issues.append(QAIssue("fail", "missing_evidence", "no evidence references present"))
    # Reproduction must be complete.
    if not report.steps:
        issues.append(QAIssue("fail", "missing_steps", "no steps-to-reproduce provided"))
    if not report.poc:
        issues.append(QAIssue("fail", "missing_poc", "no proof-of-concept provided"))
    # Impact must be supported, not asserted.
    if not report.impact or report.impact.strip().lower() in ("high", "critical"):
        issues.append(QAIssue("fail", "unsupported_impact", "impact is missing or is an unsupported bare label"))
    if not report.affected_asset:
        issues.append(QAIssue("fail", "missing_asset", "affected asset not specified"))
    if not report.actual_result:
        issues.append(QAIssue("warn", "missing_actual_result", "actual (observed) result not stated"))

    # CVSS consistency.
    if report.severity and not report.cvss_vector:
        issues.append(QAIssue("warn", "severity_without_cvss", "severity claimed without a CVSS vector"))

    # Destructive / disallowed behavior in PoC.
    if _DESTRUCTIVE_HINTS.search(report.poc + " " + " ".join(report.steps)):
        issues.append(QAIssue("fail", "destructive_poc", "PoC references destructive / DoS behavior"))

    # Sensitive values leaking into prose.
    combined = "\n".join([
        report.summary, report.actual_result, report.impact, report.remediation,
        report.poc, " ".join(report.evidence), " ".join(report.notes),
    ])
    for pat in _SECRET_PATTERNS:
        if pat.search(combined):
            issues.append(QAIssue("fail", "secret_in_report", "possible secret/PII detected in report content"))
            break

    # Finding pipeline position: report should only be produced post-validation.
    if finding_status and finding_status in ("candidate", "validation", "rejected", "killed"):
        issues.append(QAIssue("fail", "premature_report", f"report produced from unvalidated finding state ({finding_status})"))

    failures = [i for i in issues if i and i.level == "fail"]
    return QAReport(issues=issues, passed=not failures)


__all__ = ["QAIssue", "QAReport", "run_qa"]