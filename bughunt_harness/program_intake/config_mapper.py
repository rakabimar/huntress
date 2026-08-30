"""Map an intake draft through the existing engagement Pydantic schemas."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from ..engagement.models import (
    AccountModel,
    AccountsModel,
    AutonomyModel,
    Engagement,
    HeaderModel,
    HeadersModel,
    IntegrationsModel,
    Platform,
    ProgramModel,
    ReconModel,
    ReportingModel,
    ROEModel,
    ScopeModel,
    ScopeSet,
)
from .models import AutomationClass, ProgramIntakeDraft, RuleStatus

DRAFT_CONFIG_FILES = (
    "program.yaml", "scope.yaml", "roe.yaml", "headers.yaml", "reporting.yaml",
    "accounts.yaml", "autonomy.yaml", "recon.yaml", "integrations.yaml",
)


def build_engagement(draft: ProgramIntakeDraft) -> Engagement:
    include = ScopeSet()
    exclude = ScopeSet()
    for entry in draft.scope_entries:
        if entry.automation_class != AutomationClass.NETWORK_TESTABLE or not entry.selector:
            continue
        target = include if entry.testing_allowed is True else exclude
        _append_selector(target, entry.selector_kind, entry.selector)
    for item in draft.scope_exclusions:
        if item.selector and item.selector_kind:
            _append_selector(exclude, item.selector_kind, item.selector)

    rules = {rule.key: rule for rule in draft.roe_rules}
    rate = rules.get("rate_limits")
    concurrency = rules.get("concurrency")
    max_rps = _rule_number(rate, "max_rps", draft.local_safety_defaults.max_rps)
    max_concurrency = int(_rule_number(concurrency, "max_concurrency", draft.local_safety_defaults.max_concurrency))
    automation = _enabled(rules.get("automated_scanning"), conditional=True)
    required_names = [header.name for header in draft.required_headers if header.mandatory]
    roe = ROEModel(
        automation_allowed=automation,
        authentication_testing=False,
        authorization_testing=True,
        file_upload=_enabled(rules.get("file_upload")),
        race_conditions=_enabled(rules.get("race_conditions")),
        fuzzing=automation,
        out_of_band_testing=_enabled(rules.get("out_of_band_testing")),
        state_changing_actions=False,
        brute_force=_enabled(rules.get("brute_force")),
        denial_of_service=False,
        destructive_testing=False,
        passive_recon=True,
        historical_url_recon=True,
        active_recon=False,
        crawling=automation,
        bounded_scanning=automation,
        max_rps=max_rps,
        max_concurrency=max_concurrency,
        manual_approval_actions=["active_recon"],
        forbidden_actions=_forbidden_actions(rules),
        required_headers=required_names,
        notes="Generated from approved intake; absent/unknown program rules remain denied.",
    )
    headers = HeadersModel(headers=[
        HeaderModel(
            name=header.name, mandatory=header.mandatory,
            secret=bool(header.value_ref), value=header.value if header.value_status == "FIXED" else None,
            value_ref=header.value_ref, note=header.note,
        ) for header in draft.required_headers
    ])
    account_count = draft.account_requirements.minimum_accounts or 0
    accounts = AccountsModel(accounts=[
        AccountModel(id=f"account_{chr(97 + index)}", role="regular_user", enabled=True,
                     description="Intake-generated placeholder; configure AuthContext secret refs locally.")
        for index in range(min(account_count, 10))
    ])
    platform_value = draft.metadata.platform if draft.metadata.platform in {item.value for item in Platform} else "custom"
    return Engagement(
        program=ProgramModel(
            name=draft.metadata.name, platform=platform_value,
            program_url=draft.metadata.program_url, status="paused",
            notes=f"Platform-managed fields approved through {draft.import_id}.",
        ),
        scope=ScopeModel(include=include, exclude=exclude,
                         notes=f"Generated from {draft.import_id}; submission and bounty eligibility remain in provenance."),
        roe=roe, headers=headers, accounts=accounts,
        reporting=ReportingModel(
            platform=platform_value,
            severity_mechanism=draft.reporting_rules.severity_mechanism,
            required_fields=draft.reporting_rules.required_fields,
            submission_checklist=draft.reporting_rules.special_instructions,
            notes="Excluded categories: " + "; ".join(draft.reporting_rules.excluded_categories),
        ),
        autonomy=AutonomyModel(enabled=False),
        recon=ReconModel(), integrations=IntegrationsModel(),
    )


def write_draft_bundle(workspace: Path, draft: ProgramIntakeDraft) -> tuple[Path, Engagement | None]:
    root = Path(workspace) / "intake" / draft.import_id
    config_dir = root / "draft"
    config_dir.mkdir(parents=True, exist_ok=True)
    normalized = root / "normalized_draft.json"
    normalized.write_text(
        json.dumps(draft.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    provenance = root / "provenance.json"
    provenance.write_text(json.dumps({
        "scope": {entry.source_id: entry.provenance.model_dump(mode="json") for entry in draft.scope_entries},
        "roe": {rule.key: rule.provenance.model_dump(mode="json") for rule in draft.roe_rules},
        "headers": {header.name: header.provenance.model_dump(mode="json") for header in draft.required_headers},
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    try:
        engagement = build_engagement(draft)
    except Exception as exc:
        (root / "draft_validation_error.txt").write_text(
            f"Draft config is conservatively non-promotable: {type(exc).__name__}: {exc}\n",
            encoding="utf-8",
        )
        return root, None
    _write_engagement(config_dir, engagement)
    return root, engagement


def promote_bundle(workspace: Path, draft: ProgramIntakeDraft, *, current: Engagement | None) -> Engagement:
    proposed = build_engagement(draft)
    if current:
        # Local-managed data survives refresh/approval.
        proposed.accounts = current.accounts
        proposed.autonomy = current.autonomy
        proposed.recon = current.recon
        proposed.integrations = current.integrations
        # Preserve locally supplied header values/refs by case-insensitive name.
        local_headers = current.headers.by_name()
        for header in proposed.headers.headers:
            old = local_headers.get(header.name.lower())
            if old and (old.value_ref or old.value):
                header.value_ref = old.value_ref
                header.value = old.value
                header.secret = old.secret
        proposed.program.status = "paused"
    _write_engagement(Path(workspace), proposed)
    return proposed


def config_hashes(engagement: Engagement) -> dict[str, str]:
    def digest(value) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(raw).hexdigest()
    program = engagement.program.model_dump(mode="json")
    program.pop("status", None)  # lifecycle state is local-managed, not platform authorization
    return {
        "program_hash": digest(program),
        "scope_hash": digest(engagement.scope.model_dump(mode="json")),
        "roe_hash": digest(engagement.roe.model_dump(mode="json")),
    }


def bundle_hash(workspace: Path) -> str:
    digest = hashlib.sha256()
    for name in sorted(DRAFT_CONFIG_FILES):
        path = Path(workspace) / name
        if not path.is_file():
            continue
        digest.update(name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _write_engagement(root: Path, engagement: Engagement) -> None:
    root.mkdir(parents=True, exist_ok=True)
    mapping = {
        "program.yaml": engagement.program, "scope.yaml": engagement.scope,
        "roe.yaml": engagement.roe, "headers.yaml": engagement.headers,
        "accounts.yaml": engagement.accounts, "reporting.yaml": engagement.reporting,
        "autonomy.yaml": engagement.autonomy, "recon.yaml": engagement.recon,
        "integrations.yaml": engagement.integrations,
    }
    for name, model in mapping.items():
        (root / name).write_text(
            yaml.safe_dump(model.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )


def _append_selector(target: ScopeSet, kind: str, selector: str) -> None:
    field = {"domain": "domains", "wildcard": "wildcards", "url": "urls",
             "path_url": "path_urls", "ip": "ipv4", "cidr": "cidr"}.get(kind)
    if field and selector not in getattr(target, field):
        getattr(target, field).append(selector)


def _enabled(rule, *, conditional: bool = False) -> bool:
    if not rule:
        return False
    return rule.status == RuleStatus.ALLOWED or (conditional and rule.status == RuleStatus.CONDITIONAL)


def _rule_number(rule, key: str, default: float) -> float:
    if rule and isinstance(rule.value, dict) and isinstance(rule.value.get(key), (int, float)):
        return float(rule.value[key])
    return float(default)


def _forbidden_actions(rules: dict) -> list[str]:
    actions = ["dos", "destructive"]
    mapping = {"brute_force": "brute_force", "race_conditions": "race_test",
               "out_of_band_testing": "oob_test", "file_upload": "upload_test"}
    for key, action in mapping.items():
        rule = rules.get(key)
        if rule and rule.status == RuleStatus.PROHIBITED and action not in actions:
            actions.append(action)
    return actions


__all__ = ["DRAFT_CONFIG_FILES", "build_engagement", "bundle_hash", "config_hashes",
           "promote_bundle", "write_draft_bundle"]
