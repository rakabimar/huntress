"""Semantic intake diff: safer changes apply now, expansion waits for approval."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .models import (
    ChangeCategory,
    IntakeChange,
    IntakeDiff,
    ProgramIntakeDraft,
    RuleStatus,
)

_RULE_ORDER = {
    RuleStatus.PROHIBITED: 0,
    RuleStatus.UNKNOWN: 1,
    RuleStatus.CONDITIONAL: 2,
    RuleStatus.ALLOWED: 3,
}


def semantic_diff(old: ProgramIntakeDraft, new: ProgramIntakeDraft) -> IntakeDiff:
    changes: list[IntakeChange] = []
    old_scope = {_scope_key(item): item for item in old.scope_entries}
    new_scope = {_scope_key(item): item for item in new.scope_entries}
    for key in sorted(old_scope.keys() - new_scope.keys()):
        item = old_scope[key]
        if item.testing_allowed is True:
            changes.append(_change("SCOPE_REMOVED", ChangeCategory.RESTRICTIVE,
                                   f"scope.{key}", item.selector or item.asset_identifier, None,
                                   "Previously approved scope was removed.", True))
    for key in sorted(new_scope.keys() - old_scope.keys()):
        item = new_scope[key]
        category = ChangeCategory.PERMISSIVE if item.testing_allowed is True else ChangeCategory.OTHER
        changes.append(_change("SCOPE_ADDED", category, f"scope.{key}", None,
                               item.selector or item.asset_identifier,
                               "A platform scope item was added.", False))
    for key in sorted(old_scope.keys() & new_scope.keys()):
        before, after = old_scope[key], new_scope[key]
        if before.submission_eligible != after.submission_eligible:
            restrictive = before.submission_eligible is True and after.submission_eligible is not True
            changes.append(_change(
                "SUBMISSION_ELIGIBILITY_CHANGED",
                ChangeCategory.RESTRICTIVE if restrictive else ChangeCategory.PERMISSIVE,
                f"scope.{key}.submission_eligible", before.submission_eligible,
                after.submission_eligible, "Submission eligibility changed.", restrictive,
            ))
        if before.bounty_eligible != after.bounty_eligible:
            changes.append(_change(
                "BOUNTY_ELIGIBILITY_CHANGED", ChangeCategory.OTHER,
                f"scope.{key}.bounty_eligible", before.bounty_eligible, after.bounty_eligible,
                "Bounty eligibility changed independently of testing authorization.", False,
            ))
        if before.maximum_severity != after.maximum_severity:
            changes.append(_change("MAX_SEVERITY_CHANGED", ChangeCategory.OTHER,
                                   f"scope.{key}.maximum_severity", before.maximum_severity,
                                   after.maximum_severity, "Maximum severity metadata changed.", False))
        if before.instruction != after.instruction:
            restrictive = bool(after.instruction and any(
                phrase in after.instruction.lower()
                for phrase in ("do not test", "out of scope", "not allowed", "prohibited")
            ))
            changes.append(_change(
                "SCOPE_INSTRUCTION_CHANGED",
                ChangeCategory.RESTRICTIVE if restrictive else ChangeCategory.OTHER,
                f"scope.{key}.instruction", before.instruction, after.instruction,
                "Asset-specific instruction changed.", restrictive,
            ))

    old_exclusions = {(item.category, item.details) for item in old.scope_exclusions}
    new_exclusions = {(item.category, item.details) for item in new.scope_exclusions}
    for value in sorted(new_exclusions - old_exclusions, key=str):
        changes.append(_change("NEW_SCOPE_EXCLUSION", ChangeCategory.RESTRICTIVE,
                               "scope_exclusions", None, value, "A new official exclusion was added.", True))
    for value in sorted(old_exclusions - new_exclusions, key=str):
        changes.append(_change("REMOVED_SCOPE_EXCLUSION", ChangeCategory.PERMISSIVE,
                               "scope_exclusions", value, None, "An official exclusion was removed.", False))

    old_rules = {item.key: item for item in old.roe_rules}
    new_rules = {item.key: item for item in new.roe_rules}
    for key in sorted(old_rules.keys() | new_rules.keys()):
        before = old_rules.get(key)
        after = new_rules.get(key)
        before_status = before.status if before else RuleStatus.UNKNOWN
        after_status = after.status if after else RuleStatus.UNKNOWN
        if before_status != after_status:
            restrictive = _RULE_ORDER[after_status] < _RULE_ORDER[before_status]
            permissive = _RULE_ORDER[after_status] > _RULE_ORDER[before_status]
            changes.append(_change(
                "ROE_MORE_RESTRICTIVE" if restrictive else "ROE_MORE_PERMISSIVE" if permissive else "PROGRAM_POLICY_CHANGED",
                ChangeCategory.RESTRICTIVE if restrictive else ChangeCategory.PERMISSIVE if permissive else ChangeCategory.OTHER,
                f"roe.{key}", before_status.value, after_status.value,
                f"ROE rule {key!r} changed.", restrictive,
            ))
        before_value = before.value if before else None
        after_value = after.value if after else None
        if before_value != after_value and key in {"rate_limits", "concurrency"}:
            old_num = _numeric_value(before_value)
            new_num = _numeric_value(after_value)
            restrictive = old_num is not None and (new_num is None or new_num < old_num)
            category = ChangeCategory.RESTRICTIVE if restrictive else ChangeCategory.PERMISSIVE
            changes.append(_change("RATE_LIMIT_CHANGED", category, f"roe.{key}.value",
                                   before_value, after_value, "Numeric traffic constraint changed.", restrictive))

    old_headers = {(h.name.lower(), h.value_status, h.value, h.value_ref) for h in old.required_headers}
    new_headers = {(h.name.lower(), h.value_status, h.value, h.value_ref) for h in new.required_headers}
    if old_headers != new_headers:
        added_names = {item[0] for item in new_headers} - {item[0] for item in old_headers}
        restrictive = bool(added_names)
        changes.append(_change("REQUIRED_HEADER_CHANGED",
                               ChangeCategory.RESTRICTIVE if restrictive else ChangeCategory.OTHER,
                               "required_headers", sorted(old_headers), sorted(new_headers),
                               "Required request header policy changed.", restrictive))

    old_accounts = old.account_requirements.model_dump(exclude={"provenance"})
    new_accounts = new.account_requirements.model_dump(exclude={"provenance"})
    if old_accounts != new_accounts:
        changes.append(_change("ACCOUNT_RULE_CHANGED", ChangeCategory.OTHER,
                               "account_requirements", old_accounts,
                               new_accounts, "Account requirements changed.", False))
    old_reporting = old.reporting_rules.model_dump(exclude={"provenance"})
    new_reporting = new.reporting_rules.model_dump(exclude={"provenance"})
    if old_reporting != new_reporting:
        changes.append(_change("REPORTING_RULE_CHANGED", ChangeCategory.OTHER,
                               "reporting_rules", old_reporting,
                               new_reporting, "Reporting metadata changed.", False))

    old_policy = next((source.content_hash for source in old.sources if source.source_type.value == "official_policy_text"), None)
    new_policy = next((source.content_hash for source in new.sources if source.source_type.value == "official_policy_text"), None)
    if old_policy != new_policy and not any(change.field.startswith("roe.") for change in changes):
        changes.append(_change("PROGRAM_POLICY_CHANGED", ChangeCategory.OTHER,
                               "policy", old_policy, new_policy,
                               "Official policy source content changed.", False))

    old_state = (old.metadata.submission_state or "unknown").lower()
    new_state = (new.metadata.submission_state or "unknown").lower()
    if old_state != new_state:
        if new_state in {"closed", "paused", "disabled"}:
            category, kind, immediate = ChangeCategory.RESTRICTIVE, "PROGRAM_CLOSED" if new_state == "closed" else "PROGRAM_PAUSED", True
        elif new_state in {"open", "active", "accepting"}:
            category, kind, immediate = ChangeCategory.PERMISSIVE, "PROGRAM_REOPENED", False
        else:
            category, kind, immediate = ChangeCategory.OTHER, "PROGRAM_POLICY_CHANGED", False
        changes.append(_change(kind, category, "metadata.submission_state", old_state,
                               new_state, "Official program submission state changed.", immediate))
    return IntakeDiff(previous_import_id=old.import_id, current_import_id=new.import_id, changes=changes)


def write_protective_overlay(workspace: Path, diff: IntakeDiff, old: ProgramIntakeDraft,
                             new: ProgramIntakeDraft) -> Path | None:
    if not diff.restrictive:
        return None
    old_scope = {_scope_key(item): item for item in old.scope_entries}
    new_scope = {_scope_key(item): item for item in new.scope_entries}
    excluded: list[dict[str, str]] = []
    for key, item in old_scope.items():
        replacement = new_scope.get(key)
        if item.testing_allowed is True and (replacement is None or replacement.testing_allowed is not True):
            if item.selector:
                excluded.append({"kind": item.selector_kind, "selector": item.selector})
    for item in new.scope_entries:
        if item.selector and item.instruction and any(
            phrase in item.instruction.lower() for phrase in ("do not test", "out of scope", "not allowed", "prohibited")
        ):
            excluded.append({"kind": item.selector_kind, "selector": item.selector})
    disabled_rules = [
        change.field.removeprefix("roe.").split(".", 1)[0]
        for change in diff.restrictive if change.change_type == "ROE_MORE_RESTRICTIVE"
    ]
    program_blocked = any(change.change_type in {"PROGRAM_CLOSED", "PROGRAM_PAUSED"} for change in diff.restrictive)
    payload = {
        "import_id": diff.current_import_id,
        "excluded": excluded,
        "disabled_rules": sorted(set(disabled_rules)),
        "program_blocked": program_blocked,
        "changes": [change.model_dump(mode="json") for change in diff.restrictive],
    }
    path = Path(workspace) / "intake" / "protective-overlay.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def load_diff(workspace: Path, import_id: str) -> IntakeDiff | None:
    path = Path(workspace) / "intake" / import_id / "diff.json"
    if not path.is_file():
        return None
    return IntakeDiff.model_validate_json(path.read_text(encoding="utf-8"))


def save_diff(workspace: Path, diff: IntakeDiff) -> Path:
    path = Path(workspace) / "intake" / diff.current_import_id / "diff.json"
    path.write_text(json.dumps(diff.model_dump(mode="json"), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _scope_key(item) -> str:
    return f"{item.asset_type.lower()}:{(item.selector or item.asset_identifier).lower()}"


def _numeric_value(value) -> float | None:
    if isinstance(value, dict):
        for candidate in value.values():
            if isinstance(candidate, (int, float)):
                return float(candidate)
    return None


def _change(kind, category, field, old, new, description, immediate) -> IntakeChange:
    return IntakeChange(change_type=kind, category=category, field=field,
                        old_value=old, new_value=new, description=description,
                        effective_immediately=immediate)


__all__ = ["load_diff", "save_diff", "semantic_diff", "write_protective_overlay"]
