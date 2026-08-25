"""Platform-specific report profiles (HackerOne / Bugcrowd / YesWeHack /
Intigriti / generic).

Profiles describe *shape* and terminology only — they never auto-submit.  The
final submission adapter requires explicit human approval (spec §63/§64).
"""

from __future__ import annotations

from ..cvss.engine import severity_from_score

CANONICAL_FIELDS = [
    "title",
    "summary",
    "affected_asset",
    "weakness",
    "severity",
    "cvss_vector",
    "prerequisites",
    "steps_to_reproduce",
    "poc",
    "expected_result",
    "actual_result",
    "impact",
    "evidence",
    "remediation",
    "notes",
]

_PROFILES: dict[str, dict] = {
    "hackerone": {
        "display": "HackerOne",
        "expected_fields": [
            "title", "summary", "affected_asset", "weakness", "severity", "cvss_vector",
            "steps_to_reproduce", "impact", "evidence", "remediation",
        ],
        "severity_mechanism": "H1 severity (None/Low/Medium/High/Critical) + CVSS",
        "terminology": ["Report", "Severity", "Weakness (CWE)", "Reproduction Steps"],
        "submission_checklist": [
            "Affected asset is in scope",
            "Reproduction is complete and minimal",
            "Impact is demonstrated, not assumed",
            "No unnecessary PII/secrets included",
            "Severity consistent with evidence and CVSS",
        ],
    },
    "bugcrowd": {
        "display": "Bugcrowd",
        "expected_fields": [
            "title", "summary", "affected_asset", "weakness", "severity", "cvss_vector",
            "steps_to_reproduce", "impact", "evidence", "remediation",
        ],
        "severity_mechanism": "Bugcrowd VRT + CVSS",
        "terminology": ["Submission", "Priority (P1-P5)", "VRT Category", "Steps to Reproduce"],
        "submission_checklist": [
            "VRT category selected appropriately",
            "Reproduction complete",
            "Priority consistent with CVSS/impact",
            "Scope confirmed",
        ],
    },
    "yeswehack": {
        "display": "YesWeHack",
        "expected_fields": [
            "title", "summary", "affected_asset", "weakness", "severity", "impact",
            "steps_to_reproduce", "evidence", "remediation",
        ],
        "severity_mechanism": "CVSS-based",
        "terminology": ["Report", "CVSS", "Steps to Reproduce"],
        "submission_checklist": ["Scope confirmed", "CVSS vector provided", "Reproduction complete"],
    },
    "intigriti": {
        "display": "Intigriti",
        "expected_fields": [
            "title", "summary", "affected_asset", "weakness", "severity", "impact",
            "steps_to_reproduce", "evidence", "remediation",
        ],
        "severity_mechanism": "CVSS-based",
        "terminology": ["Submission", "CVSS", "Steps to Reproduce"],
        "submission_checklist": ["Scope confirmed", "CVSS vector provided", "Impact demonstrated"],
    },
    "generic": {
        "display": "Generic",
        "expected_fields": list(CANONICAL_FIELDS),
        "severity_mechanism": "CVSS v4.0 / v3.1",
        "terminology": ["Findings", "Severity", "PoC", "Steps to Reproduce"],
        "submission_checklist": [
            "Scope confirmed",
            "Reproduction complete",
            "Evidence present",
            "CVSS provided",
            "Impact demonstrated",
        ],
    },
}

# Platform-specific qualitative severity overrides keyed by platform slug.
# A value of None means "fall back to standard CVSS bands".
_PLATFORM_BAND_OVERRIDES: dict[str, dict] = {}

SUPPORTED_PLATFORMS = tuple(_PROFILES)


def get_profile(platform: str | None) -> dict:
    if platform is None:
        return _PROFILES["generic"]
    return _PROFILES.get(platform.lower(), _PROFILES["generic"])


def platform_severity_label(platform: str | None, cvss_score: float) -> str:
    """Map a CVSS score to a platform's qualitative label.

    Program-specific rules always override this generic default.  Most
    platforms reuse the standard four-band scale; overrides can be registered
    in ``_PLATFORM_BAND_OVERRIDES``.
    """
    override = _PLATFORM_BAND_OVERRIDES.get((platform or "generic").lower())
    if override:
        for band, label in override.items():
            lo, hi = band
            if lo <= cvss_score <= hi:
                return label
    return severity_from_score(cvss_score)


__all__ = [
    "CANONICAL_FIELDS",
    "SUPPORTED_PLATFORMS",
    "get_profile",
    "platform_severity_label",
]