"""Reporting layer: profiles, report builder, QA, PoC pipeline."""

from .profiles import (
    CANONICAL_FIELDS,
    SUPPORTED_PLATFORMS,
    get_profile,
    platform_severity_label,
)
from .report import ReportData
from .qa import QAIssue, QAReport, run_qa
from .poc import PoC

__all__ = [
    "CANONICAL_FIELDS",
    "SUPPORTED_PLATFORMS",
    "get_profile",
    "platform_severity_label",
    "ReportData",
    "QAIssue",
    "QAReport",
    "run_qa",
    "PoC",
]