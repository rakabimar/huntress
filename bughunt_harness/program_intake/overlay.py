"""Apply a refresh protective overlay to effective runtime authorization."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..engagement.models import Engagement

RULE_TO_ROE_FIELD = {
    "automated_scanning": "automation_allowed",
    "denial_of_service": "denial_of_service",
    "destructive_testing": "destructive_testing",
    "brute_force": "brute_force",
    "race_conditions": "race_conditions",
    "file_upload": "file_upload",
    "out_of_band_testing": "out_of_band_testing",
}


def apply_protective_overlay(engagement: Engagement, workspace: Path) -> tuple[Engagement, bool]:
    path = Path(workspace) / "intake" / "protective-overlay.yaml"
    if not path.is_file():
        return engagement, False
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    effective = engagement.model_copy(deep=True)
    for item in data.get("excluded", []):
        field = {"domain": "domains", "wildcard": "wildcards", "url": "urls",
                 "path_url": "path_urls", "ip": "ipv4", "cidr": "cidr"}.get(item.get("kind"))
        selector = item.get("selector")
        if field and selector and selector not in getattr(effective.scope.exclude, field):
            getattr(effective.scope.exclude, field).append(selector)
    for rule in data.get("disabled_rules", []):
        field = RULE_TO_ROE_FIELD.get(rule)
        if field:
            setattr(effective.roe, field, False)
    return effective, bool(data.get("program_blocked"))


__all__ = ["apply_protective_overlay"]
