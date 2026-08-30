"""Platform-neutral intake models.

These models deliberately remain richer than the engagement YAML models.  They
preserve platform semantics, unknowns, and field-level provenance before a
conservative mapper proposes the existing authorization configuration.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class IntakeStatus(str, Enum):
    NEW = "NEW"
    FETCHING = "FETCHING"
    IMPORTED_DRAFT = "IMPORTED_DRAFT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED = "APPROVED"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    FETCH_FAILED = "FETCH_FAILED"
    IMPORT_FAILED = "IMPORT_FAILED"
    STALE = "STALE"
    CHANGE_REVIEW_REQUIRED = "CHANGE_REVIEW_REQUIRED"
    ARCHIVED = "ARCHIVED"


class SourceType(str, Enum):
    OFFICIAL_STRUCTURED_API = "official_structured_api"
    OFFICIAL_RESEARCHER_JSON = "official_researcher_json"
    OFFICIAL_STRUCTURED_HTML = "official_structured_html"
    OFFICIAL_POLICY_TEXT = "official_policy_text"
    LLM_INTERPRETATION = "llm_interpretation"
    HUMAN_INPUT = "human_input"
    HARNESS_DEFAULT = "harness_default"


SOURCE_TRUST = {
    SourceType.OFFICIAL_STRUCTURED_API: 100,
    SourceType.OFFICIAL_RESEARCHER_JSON: 95,
    SourceType.OFFICIAL_STRUCTURED_HTML: 90,
    SourceType.OFFICIAL_POLICY_TEXT: 80,
    SourceType.LLM_INTERPRETATION: 60,
    SourceType.HUMAN_INPUT: 100,
    SourceType.HARNESS_DEFAULT: 100,
}


class RuleStatus(str, Enum):
    ALLOWED = "ALLOWED"
    PROHIBITED = "PROHIBITED"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"


class AutomationClass(str, Enum):
    NETWORK_TESTABLE = "NETWORK_TESTABLE"
    NON_NETWORK_REFERENCE = "NON_NETWORK_REFERENCE"
    UNSUPPORTED_AUTOMATED_TARGET = "UNSUPPORTED_AUTOMATED_TARGET"


class AmbiguitySeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AmbiguityStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED_DEFAULT = "ACCEPTED_DEFAULT"
    IGNORED_NONCRITICAL = "IGNORED_NONCRITICAL"


class PlatformCapabilities(BaseModel):
    program_metadata: bool = False
    structured_scope: bool = False
    scope_exclusions: bool = False
    policy_text: bool = False
    reward_data: bool = False
    reporting_metadata: bool = False
    change_timestamps: bool = False
    public_api: bool = False
    authenticated_api: bool = False
    availability: dict[str, str] = Field(default_factory=dict)


class Provenance(BaseModel):
    source_type: SourceType
    source_id: str
    import_id: str
    confidence: float = 1.0
    source_section: str | None = None
    excerpt_hash: str | None = None

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("confidence must be between 0 and 1")
        return value


class ProgramMetadata(BaseModel):
    name: str
    handle: str
    platform: str
    platform_program_id: str | None = None
    program_url: str | None = None
    public: bool | None = None
    submission_state: str | None = None
    offers_bounties: bool | None = None
    currency: str | None = None
    platform_state: str | None = None
    last_platform_update: str | None = None
    provenance: Provenance


class ScopeEntry(BaseModel):
    source_id: str
    asset_identifier: str
    asset_type: str
    selector: str | None = None
    selector_kind: Literal["domain", "wildcard", "url", "path_url", "ip", "cidr", "reference", "unsupported"]
    automation_class: AutomationClass
    testing_allowed: bool | None = None
    submission_eligible: bool | None = None
    bounty_eligible: bool | None = None
    maximum_severity: str | None = None
    instruction: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    confidentiality_requirement: str | None = None
    integrity_requirement: str | None = None
    availability_requirement: str | None = None
    reference: str | None = None
    provenance: Provenance


class ScopeExclusion(BaseModel):
    source_id: str
    category: str | None = None
    details: str | None = None
    selector: str | None = None
    selector_kind: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    provenance: Provenance


class ROERule(BaseModel):
    key: str
    status: RuleStatus
    explicit: bool = False
    condition: str | None = None
    note: str | None = None
    value: Any = None
    provenance: Provenance


class LocalSafetyDefaults(BaseModel):
    max_rps: float = 2.0
    max_concurrency: int = 2
    deep_recon: Literal["ASK"] = "ASK"
    source: Literal["harness_default"] = "harness_default"


class HeaderRequirement(BaseModel):
    name: str
    mandatory: bool = True
    value_status: Literal["FIXED", "NEEDS_USER_VALUE", "UNKNOWN"] = "UNKNOWN"
    value: str | None = None
    value_ref: str | None = None
    note: str = ""
    provenance: Provenance


class AccountRequirements(BaseModel):
    minimum_accounts: int | None = None
    self_registration: bool | None = None
    provided_credentials: bool | None = None
    testing_other_real_users: RuleStatus = RuleStatus.UNKNOWN
    email_domain: str | None = None
    notes: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)


class ReportingRules(BaseModel):
    platform: str
    program_handle: str
    program_url: str | None = None
    severity_mechanism: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    special_instructions: list[str] = Field(default_factory=list)
    excluded_categories: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)


class ProgramAmbiguity(BaseModel):
    id: str
    field: str
    severity: AmbiguitySeverity
    category: str
    reason: str
    source_refs: list[str] = Field(default_factory=list)
    proposed_interpretation: Any = None
    alternatives: list[Any] = Field(default_factory=list)
    required_user_input: str | None = None
    status: AmbiguityStatus = AmbiguityStatus.OPEN
    resolved_value: Any = None
    resolved_by: str | None = None
    resolved_at: str | None = None


class SourceArtifact(BaseModel):
    source_type: SourceType
    source_identifier: str
    retrieved_at: str
    content_hash: str
    artifact_ref: str
    trust_level: int
    status: int | str
    etag: str | None = None
    last_modified: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProgramIntakeDraft(BaseModel):
    import_id: str
    generated_at: str = Field(default_factory=utcnow)
    adapter_version: str
    parser_version: str
    capabilities: PlatformCapabilities
    metadata: ProgramMetadata
    scope_entries: list[ScopeEntry] = Field(default_factory=list)
    scope_exclusions: list[ScopeExclusion] = Field(default_factory=list)
    roe_rules: list[ROERule] = Field(default_factory=list)
    reporting_rules: ReportingRules
    required_headers: list[HeaderRequirement] = Field(default_factory=list)
    account_requirements: AccountRequirements = Field(default_factory=AccountRequirements)
    reward_metadata: dict[str, Any] = Field(default_factory=dict)
    local_safety_defaults: LocalSafetyDefaults = Field(default_factory=LocalSafetyDefaults)
    ambiguities: list[ProgramAmbiguity] = Field(default_factory=list)
    sources: list[SourceArtifact] = Field(default_factory=list)
    human_overrides: list[dict[str, Any]] = Field(default_factory=list)

    def canonical_bytes(self) -> bytes:
        payload = self.model_dump(mode="json", exclude_none=False)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def draft_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def scope_hash(self) -> str:
        payload = [entry.model_dump(mode="json") for entry in self.scope_entries]
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def roe_hash(self) -> str:
        payload = [rule.model_dump(mode="json") for rule in self.roe_rules]
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def open_critical_ambiguities(self) -> list[ProgramAmbiguity]:
        return [
            item for item in self.ambiguities
            if item.severity == AmbiguitySeverity.CRITICAL and item.status == AmbiguityStatus.OPEN
        ]


class AdapterPayload(BaseModel):
    platform: str
    handle: str
    program_url: str | None = None
    capabilities: PlatformCapabilities
    program: dict[str, Any]
    scopes: list[dict[str, Any]] = Field(default_factory=list)
    exclusions: list[dict[str, Any]] = Field(default_factory=list)
    policy_text: str = ""
    sources: list[SourceArtifact] = Field(default_factory=list)


class ChangeCategory(str, Enum):
    RESTRICTIVE = "RESTRICTIVE"
    PERMISSIVE = "PERMISSIVE"
    OTHER = "OTHER"


class IntakeChange(BaseModel):
    change_type: str
    category: ChangeCategory
    field: str
    old_value: Any = None
    new_value: Any = None
    effective_immediately: bool = False
    description: str


class IntakeDiff(BaseModel):
    previous_import_id: str
    current_import_id: str
    changes: list[IntakeChange] = Field(default_factory=list)

    @property
    def material(self) -> bool:
        return bool(self.changes)

    @property
    def restrictive(self) -> list[IntakeChange]:
        return [c for c in self.changes if c.category == ChangeCategory.RESTRICTIVE]

    @property
    def permissive(self) -> list[IntakeChange]:
        return [c for c in self.changes if c.category == ChangeCategory.PERMISSIVE]


__all__ = [name for name in globals() if not name.startswith("_")]
