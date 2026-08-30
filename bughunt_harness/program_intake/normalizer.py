"""Normalize adapter payloads without widening source authorization."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlunparse

from .models import (
    AdapterPayload,
    AutomationClass,
    ProgramIntakeDraft,
    ProgramMetadata,
    Provenance,
    ReportingRules,
    ScopeEntry,
    ScopeExclusion,
    SourceType,
)
from .policy_parser import PARSER_VERSION, parse_policy

NON_NETWORK_TYPES = {
    "android play store", "android", "ios app store", "ios", "mobile_app",
    "source code", "source_code", "downloadable executable", "hardware", "other asset",
}


def _provenance(import_id: str, source_id: str, source_type: SourceType = SourceType.OFFICIAL_STRUCTURED_API) -> Provenance:
    return Provenance(source_type=source_type, source_id=source_id, import_id=import_id, confidence=1.0)


def classify_selector(identifier: str, asset_type: str) -> tuple[str | None, str, AutomationClass]:
    raw = identifier.strip()
    kind = asset_type.strip().lower().replace("-", " ")
    if kind in NON_NETWORK_TYPES or any(token in kind for token in ("mobile", "source code", "hardware", "executable")):
        return None, "reference", AutomationClass.NON_NETWORK_REFERENCE
    if raw.startswith("*.") and "/" not in raw:
        return raw.lower().rstrip("."), "wildcard", AutomationClass.NETWORK_TESTABLE
    try:
        network = ipaddress.ip_network(raw, strict=False)
        if "/" in raw:
            return str(network), "cidr", AutomationClass.NETWORK_TESTABLE
        return str(network.network_address), "ip", AutomationClass.NETWORK_TESTABLE
    except ValueError:
        pass
    if raw.lower().startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.hostname:
            return None, "unsupported", AutomationClass.UNSUPPORTED_AUTOMATED_TARGET
        path = parsed.path or "/"
        selector_kind = "url"
        if path not in ("", "/"):
            selector_kind = "path_url"
            # Existing Scope Engine models prefix semantics. A terminal source
            # glob is translated to the exact equivalent prefix, never to host scope.
            if path.endswith("/*"):
                path = path[:-1]
            elif "*" in path:
                return None, "unsupported", AutomationClass.UNSUPPORTED_AUTOMATED_TARGET
        selector = urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", "", ""))
        return selector, selector_kind, AutomationClass.NETWORK_TESTABLE
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}", raw.rstrip(".")):
        return raw.lower().rstrip("."), "domain", AutomationClass.NETWORK_TESTABLE
    return None, "unsupported", AutomationClass.UNSUPPORTED_AUTOMATED_TARGET


def normalize_payload(
    payload: AdapterPayload, *, import_id: str, adapter_version: str,
    llm_extract: Callable[[str], dict[str, Any]] | None = None,
) -> ProgramIntakeDraft:
    program_data = payload.program.get("data", {})
    attrs = program_data.get("attributes", {})
    program_source = next((s for s in payload.sources if "program" in s.artifact_ref), payload.sources[0] if payload.sources else None)
    source_id = program_source.source_identifier if program_source else f"{payload.platform}:program:{payload.handle}"
    primary_source_type = program_source.source_type if program_source else SourceType.OFFICIAL_STRUCTURED_API
    metadata = ProgramMetadata(
        name=str(attrs.get("name") or payload.handle),
        handle=str(attrs.get("handle") or payload.handle),
        platform=payload.platform,
        platform_program_id=str(program_data.get("id")) if program_data.get("id") is not None else None,
        program_url=payload.program_url,
        public=_public_state(attrs.get("state")),
        submission_state=attrs.get("submission_state"),
        offers_bounties=attrs.get("offers_bounties"),
        currency=attrs.get("currency"),
        platform_state=attrs.get("state"),
        last_platform_update=attrs.get("updated_at"),
        provenance=_provenance(import_id, source_id, primary_source_type),
    )
    structured_source = next((s for s in payload.sources if s.source_type in {
        SourceType.OFFICIAL_STRUCTURED_API, SourceType.OFFICIAL_RESEARCHER_JSON,
        SourceType.OFFICIAL_STRUCTURED_HTML, SourceType.HUMAN_INPUT,
    }), program_source)
    structured_type = structured_source.source_type if structured_source else SourceType.OFFICIAL_STRUCTURED_API
    scopes = [_normalize_scope(item, import_id, structured_type) for item in payload.scopes]
    exclusions = [_normalize_exclusion(item, import_id, structured_type) for item in payload.exclusions]
    policy_source = next((s.source_identifier for s in payload.sources if s.source_type == SourceType.OFFICIAL_POLICY_TEXT), source_id + "#policy")
    roe, headers, accounts = parse_policy(
        payload.policy_text, import_id=import_id, source_id=policy_source,
        llm_extract=llm_extract,
    )
    reporting = ReportingRules(
        platform=payload.platform, program_handle=metadata.handle,
        program_url=payload.program_url,
        excluded_categories=[item.category for item in exclusions if item.category],
        provenance=[_provenance(import_id, source_id, primary_source_type)],
    )
    policy_urls = {
        value.rstrip(".,;") for value in re.findall(
            r"https://[^\s<>()\]]+", payload.policy_text, flags=re.I
        )
    }
    referenced_documents = sorted(
        value for value in policy_urls
        if re.search(r"(?:\.(?:pdf|md|txt|docx?|html?)(?:\?|$)|policy|rules|guidelines?|safe[-_]?harbou?r)", value, re.I)
    )
    fetched_sources = {source.source_identifier: source for source in payload.sources}
    source_proposals = []
    for entry in scopes:
        kind = entry.asset_type.lower().replace("-", " ")
        identifier = entry.asset_identifier.strip()
        if "source" not in kind or not re.match(r"https://(?:www\.)?(?:github\.com|gitlab\.com)/[^/]+/[^/#?]+", identifier, re.I):
            continue
        source_proposals.append({
            "official_url": identifier.rstrip("/"), "requested_ref": "unknown/latest",
            "source_id": entry.source_id, "status": "PROPOSED",
            "registration_requires_human_approval": True, "automatic_clone": False,
        })
    return ProgramIntakeDraft(
        import_id=import_id, adapter_version=adapter_version, parser_version=PARSER_VERSION,
        capabilities=payload.capabilities, metadata=metadata, scope_entries=scopes,
        scope_exclusions=exclusions, roe_rules=roe, reporting_rules=reporting,
        required_headers=headers, account_requirements=accounts,
        reward_metadata={
            "offers_bounties": metadata.offers_bounties, "currency": metadata.currency,
            "referenced_policy_documents": [
                {
                    "url": value.rstrip(".,;"),
                    "fetched": value.rstrip(".,;") in fetched_sources,
                    "parsed": bool(fetched_sources[value.rstrip(".,;")].metadata.get("parsed", True))
                    if value.rstrip(".,;") in fetched_sources else False,
                }
                for value in referenced_documents
            ], "source_repository_proposals": source_proposals,
        },
        sources=payload.sources,
    )


def _normalize_scope(item: dict, import_id: str, source_type: SourceType) -> ScopeEntry:
    attrs = item.get("attributes", item)
    source_id = f"scope:{item.get('id', attrs.get('id', 'unknown'))}"
    identifier = str(attrs.get("asset_identifier") or attrs.get("endpoint") or attrs.get("name") or "").strip()
    asset_type = str(attrs.get("asset_type") or attrs.get("type") or "OTHER")
    selector, selector_kind, automation_class = classify_selector(identifier, asset_type)
    submission = attrs.get("eligible_for_submission")
    testing_allowed = submission if isinstance(submission, bool) else None
    return ScopeEntry(
        source_id=source_id, asset_identifier=identifier, asset_type=asset_type,
        selector=selector, selector_kind=selector_kind, automation_class=automation_class,
        testing_allowed=testing_allowed, submission_eligible=submission,
        bounty_eligible=attrs.get("eligible_for_bounty"),
        maximum_severity=attrs.get("max_severity"), instruction=attrs.get("instruction"),
        created_at=attrs.get("created_at"), updated_at=attrs.get("updated_at"),
        confidentiality_requirement=attrs.get("confidentiality_requirement"),
        integrity_requirement=attrs.get("integrity_requirement"),
        availability_requirement=attrs.get("availability_requirement"),
        reference=attrs.get("reference"), provenance=_provenance(import_id, source_id, source_type),
    )


def _normalize_exclusion(item: dict, import_id: str, source_type: SourceType) -> ScopeExclusion:
    attrs = item.get("attributes", item)
    source_id = f"exclusion:{item.get('id', attrs.get('id', 'unknown'))}"
    return ScopeExclusion(
        source_id=source_id, category=attrs.get("category"), details=attrs.get("details"),
        created_at=attrs.get("created_at"), updated_at=attrs.get("updated_at"),
        provenance=_provenance(import_id, source_id, source_type),
    )


def _public_state(state: object) -> bool | None:
    if state is None:
        return None
    lowered = str(state).lower()
    if "public" in lowered:
        return True
    if "private" in lowered:
        return False
    return None


__all__ = ["classify_selector", "normalize_payload"]
