"""Compact review and provenance views; detailed raw policy stays on disk."""

from __future__ import annotations

from .models import AutomationClass, ProgramIntakeDraft, RuleStatus


def review_summary(draft: ProgramIntakeDraft, import_row: dict, ambiguities: list[dict]) -> dict:
    scope = draft.scope_entries
    return {
        "source": {
            "platform": draft.metadata.platform,
            "import_id": draft.import_id,
            "fetched_at": import_row.get("completed_at"),
            "capabilities": draft.capabilities.model_dump(mode="json"),
        },
        "program": {
            "name": draft.metadata.name,
            "handle": draft.metadata.handle,
            "submission_state": draft.metadata.submission_state,
            "offers_bounties": draft.metadata.offers_bounties,
        },
        "scope": {
            "total": len(scope),
            "submission_eligible": sum(item.submission_eligible is True for item in scope),
            "submission_ineligible": sum(item.submission_eligible is False for item in scope),
            "bounty_eligible": sum(item.bounty_eligible is True for item in scope),
            "network_testable": sum(item.automation_class == AutomationClass.NETWORK_TESTABLE for item in scope),
            "non_network": sum(item.automation_class == AutomationClass.NON_NETWORK_REFERENCE for item in scope),
            "unsupported": sum(item.automation_class == AutomationClass.UNSUPPORTED_AUTOMATED_TARGET for item in scope),
            "exclusions": len(draft.scope_exclusions),
        },
        "roe": {
            "explicit_allow": sum(item.explicit and item.status == RuleStatus.ALLOWED for item in draft.roe_rules),
            "explicit_deny": sum(item.explicit and item.status == RuleStatus.PROHIBITED for item in draft.roe_rules),
            "conditional": sum(item.status == RuleStatus.CONDITIONAL for item in draft.roe_rules),
            "unknown": sum(item.status == RuleStatus.UNKNOWN for item in draft.roe_rules),
        },
        "local_safety_defaults": draft.local_safety_defaults.model_dump(mode="json"),
        "clarifications": [{
            "id": item["public_id"], "severity": item["severity"],
            "category": item["category"], "reason": item["reason"],
            "proposed": item["proposed_value"], "status": item["status"],
        } for item in ambiguities],
        "manual_setup": {
            "account_placeholders": draft.account_requirements.minimum_accounts or 0,
            "required_header_values": [h.name for h in draft.required_headers if h.value_status == "NEEDS_USER_VALUE"],
            "integrations": "inherited from global config unless locally overridden",
        },
        "status": import_row["status"],
        "nothing_is_active": True,
    }


__all__ = ["review_summary"]
