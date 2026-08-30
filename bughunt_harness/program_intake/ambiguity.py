"""Deterministic authorization ambiguity detection and concise grouping."""

from __future__ import annotations

from .models import (
    AmbiguitySeverity,
    AutomationClass,
    ProgramAmbiguity,
    ProgramIntakeDraft,
    RuleStatus,
)


def detect_ambiguities(draft: ProgramIntakeDraft) -> list[ProgramAmbiguity]:
    ambiguities: list[ProgramAmbiguity] = []

    def add(field: str, severity: AmbiguitySeverity, category: str, reason: str,
            *, sources: list[str] | None = None, proposed=None, alternatives=None,
            question: str | None = None) -> None:
        ambiguities.append(ProgramAmbiguity(
            id=f"AMB-{len(ambiguities) + 1:03d}", field=field, severity=severity,
            category=category, reason=reason, source_refs=sources or [],
            proposed_interpretation=proposed, alternatives=alternatives or [],
            required_user_input=question,
        ))

    network = [entry for entry in draft.scope_entries if entry.automation_class == AutomationClass.NETWORK_TESTABLE]
    if not network:
        add("scope_entries", AmbiguitySeverity.CRITICAL, "MISSING_NETWORK_SCOPE",
            "No network-testable structured scope was available; automated testing cannot be authorized.",
            question="Provide or confirm an official structured network scope source.")
    unknown = [entry for entry in network if entry.testing_allowed is None]
    if unknown:
        add(
            "scope_entries.testing_allowed", AmbiguitySeverity.CRITICAL,
            "TESTING_AUTHORIZATION_UNKNOWN",
            f"Testing authorization is unknown for {len(unknown)} network asset(s).",
            sources=[entry.source_id for entry in unknown], proposed=False,
            alternatives=[True, False],
            question="Confirm testing authorization from the official program source for the grouped assets.",
        )
    conflicts = [
        entry for entry in network
        if entry.testing_allowed is True and entry.instruction
        and any(term in entry.instruction.lower() for term in ("do not test", "out of scope", "not allowed", "prohibited"))
    ]
    if conflicts:
        add(
            "scope_entries", AmbiguitySeverity.CRITICAL, "STRUCTURED_POLICY_CONFLICT",
            f"{len(conflicts)} structured scope item(s) are submission eligible but their instructions appear restrictive.",
            sources=[entry.source_id for entry in conflicts], proposed=False,
            alternatives=[False, True], question="Review the conflicting official asset instructions.",
        )

    if not draft.capabilities.policy_text:
        add(
            "roe_rules", AmbiguitySeverity.CRITICAL, "POLICY_SOURCE_UNAVAILABLE",
            "The official program policy was not retrieved, so program-specific restrictions may be missing.",
            proposed="block_hunt", question="Configure authorized platform access or supply an official saved policy.",
        )

    automation = next((rule for rule in draft.roe_rules if rule.key == "automated_scanning"), None)
    rate = next((rule for rule in draft.roe_rules if rule.key == "rate_limits"), None)
    if automation and automation.status in {RuleStatus.ALLOWED, RuleStatus.CONDITIONAL} and not rate:
        add(
            "local_safety_defaults", AmbiguitySeverity.WARNING, "NON_NUMERIC_TRAFFIC_LIMIT",
            "Automated tooling is permitted or conditional, but no numeric traffic limit is stated.",
            sources=[automation.provenance.source_id],
            proposed={"max_rps": draft.local_safety_defaults.max_rps,
                      "max_concurrency": draft.local_safety_defaults.max_concurrency,
                      "deep_recon": "ASK"},
            question="Approve or edit the grouped conservative local traffic policy.",
        )

    placeholder_headers = [header for header in draft.required_headers if header.value_status == "NEEDS_USER_VALUE" and not header.value_ref]
    if placeholder_headers:
        add(
            "required_headers", AmbiguitySeverity.CRITICAL, "REQUIRED_HEADER_VALUE_MISSING",
            f"{len(placeholder_headers)} mandatory header value(s) require local user input.",
            sources=[header.provenance.source_id for header in placeholder_headers],
            proposed={header.name: None for header in placeholder_headers},
            question="Provide values or secret references for the grouped required headers.",
        )

    missing_documents = [
        item for item in draft.reward_metadata.get("referenced_policy_documents", [])
        if not item.get("fetched") or not item.get("parsed")
    ]
    if missing_documents:
        add(
            "reward_metadata.referenced_policy_documents",
            AmbiguitySeverity.CRITICAL, "MISSING_REFERENCED_POLICY_DOCUMENT",
            f"{len(missing_documents)} official policy document link(s) were referenced but not captured and parsed.",
            sources=[item["url"] for item in missing_documents], proposed="block_hunt",
            question="Make the referenced official documents available and refresh intake.",
        )

    state = (draft.metadata.submission_state or "").lower()
    if state and state not in {"open", "accepting", "active", "public"}:
        severity = AmbiguitySeverity.CRITICAL if state in {"closed", "paused", "disabled"} else AmbiguitySeverity.WARNING
        add(
            "metadata.submission_state", severity, "PROGRAM_NOT_OPEN",
            f"Official platform submission state is {draft.metadata.submission_state!r}.",
            proposed="block_hunt" if severity == AmbiguitySeverity.CRITICAL else None,
        )

    if draft.metadata.platform == "generic":
        add(
            "sources", AmbiguitySeverity.WARNING, "GENERIC_SOURCE_REVIEW",
            "Generic extraction requires explicit human review of source authority and parsing quality.",
            proposed="review_required",
        )

    for rule in draft.roe_rules:
        if rule.provenance.confidence < 0.8:
            add(
                f"roe_rules.{rule.key}", AmbiguitySeverity.WARNING,
                "LOW_CONFIDENCE_INTERPRETATION",
                f"Rule {rule.key!r} has confidence {rule.provenance.confidence:.2f}.",
                sources=[rule.provenance.source_id], proposed=RuleStatus.UNKNOWN.value,
            )
    return ambiguities


__all__ = ["detect_ambiguities"]
