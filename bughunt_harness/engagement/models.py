"""Engagement configuration schemas (program.yaml / scope.yaml / roe.yaml /
headers.yaml / accounts.yaml / reporting.yaml).

These are pure-data Pydantic models.  Matching/decision logic lives in the
scope and policy engines; the models only validate *shape* of configuration.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from ..actions import ACTIONS, action_names


class Platform(str, Enum):
    hackerone = "hackerone"
    bugcrowd = "bugcrowd"
    yeswehack = "yeswehack"
    intigriti = "intigriti"
    custom = "custom"


# --------------------------------------------------------------------------- #
# program.yaml
# --------------------------------------------------------------------------- #
class ProgramModel(BaseModel):
    name: str
    platform: Platform = Platform.custom
    program_url: str | None = None
    status: str = "paused"  # active | paused | archived
    notes: str = ""

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: str) -> str:
        if v not in ("active", "paused", "archived"):
            raise ValueError("status must be active|paused|archived")
        return v


# --------------------------------------------------------------------------- #
# scope.yaml
# --------------------------------------------------------------------------- #
class ScopeSet(BaseModel):
    """A grouped set of target selectors.  Every entry is a selector string."""

    domains: list[str] = Field(default_factory=list)  # exact hosts, e.g. example.com
    wildcards: list[str] = Field(default_factory=list)  # *.example.com
    subdomains: list[str] = Field(default_factory=list)  # explicit subhosts (alias of exact)
    urls: list[str] = Field(default_factory=list)  # full URLs
    path_urls: list[str] = Field(default_factory=list)  # URLs with a path prefix
    ipv4: list[str] = Field(default_factory=list)
    cidr: list[str] = Field(default_factory=list)

    @field_validator("wildcards")
    @classmethod
    def _wildcards_must_be_wildcards(cls, v: list[str]) -> list[str]:
        for item in v:
            if not item.startswith("*."):
                raise ValueError(f"wildcard entry {item!r} must start with '*.'")
        return v

    @field_validator("domains", "subdomains")
    @classmethod
    def _no_wildcards_here(cls, v: list[str]) -> list[str]:
        for item in v:
            if item.startswith("*"):
                raise ValueError(f"entry {item!r} must not be a wildcard; put it under wildcards:")
        return v

    @field_validator("urls", "path_urls")
    @classmethod
    def _urls_parse(cls, v: list[str]) -> list[str]:
        for item in v:
            p = urlparse(item)
            if p.scheme not in ("http", "https") or not p.netloc:
                raise ValueError(f"URL {item!r} must be absolute http(s)")
        return v

    def has_entries(self) -> bool:
        """True if any selector list is non-empty (P0.3: not ``bool(self)``)."""
        return any(
            bool(getattr(self, field, ()))
            for field in (
                "domains", "wildcards", "subdomains", "urls", "path_urls", "ipv4", "cidr",
            )
        )

    def included_hosts(self) -> list[str]:
        """Deduplicated, normalized list of hostname selectors usable as a
        runtime egress allowlist (P0.11: Claude sandbox ``allowedDomains``).

        Wildcards pass through unchanged (``*.example.com``); exact domains and
        subdomains are normalized; URL entries contribute their hostname; IPv4
        literals pass through.  CIDR blocks are omitted: they cannot be expressed
        as a domain allowlist and remain enforced by the scope engine alone.
        """
        hosts: list[str] = []
        for item in self.domains + self.subdomains + self.wildcards + self.ipv4:
            h = item.strip().rstrip(".").lower()
            if h:
                hosts.append(h)
        for item in self.urls + self.path_urls:
            h = (urlparse(item).hostname or "").strip().rstrip(".").lower()
            if h:
                hosts.append(h)
        # Preserve first-seen order, drop duplicates.
        seen: set[str] = set()
        out: list[str] = []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out


class ScopeModel(BaseModel):
    include: ScopeSet = Field(default_factory=ScopeSet)
    exclude: ScopeSet = Field(default_factory=ScopeSet)
    notes: str = ""

    @model_validator(mode="after")
    def _must_have_includes(self) -> "ScopeModel":
        if not self.include.has_entries():
            raise ValueError("scope.include must define at least one target")
        return self

    @property
    def has_includes(self) -> bool:
        return self.include.has_entries()


# --------------------------------------------------------------------------- #
# roe.yaml
# --------------------------------------------------------------------------- #
class ROEModel(BaseModel):
    """Rules of Engagement — program-specific activity constraints."""

    automation_allowed: bool = False
    authentication_testing: bool = False
    authorization_testing: bool = True
    file_upload: bool = False
    race_conditions: bool = False
    fuzzing: bool = False
    out_of_band_testing: bool = False
    state_changing_actions: bool = False
    brute_force: bool = False
    denial_of_service: bool = False
    destructive_testing: bool = False
    passive_recon: bool = True
    historical_url_recon: bool = True
    active_recon: bool = False
    crawling: bool = False
    bounded_scanning: bool = False

    max_rps: float = 3.0
    max_concurrency: int = 1

    manual_approval_actions: list[str] = Field(default_factory=list)  # action names
    forbidden_actions: list[str] = Field(default_factory=list)  # action names
    required_headers: list[str] = Field(default_factory=list)  # header names that MUST be sent
    notes: str = ""

    @field_validator("manual_approval_actions", "forbidden_actions")
    @classmethod
    def _known_actions(cls, v: list[str]) -> list[str]:
        unknown = [a for a in v if a not in ACTIONS]
        if unknown:
            raise ValueError(f"unknown action(s) {unknown}; legal: {sorted(ACTIONS)}")
        return v

    @field_validator("max_rps")
    @classmethod
    def _positive_rps(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("max_rps must be > 0")
        return v

    @field_validator("max_concurrency")
    @classmethod
    def _positive_conc(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_concurrency must be >= 1")
        return v

    def approval_required_for(self, action: str) -> bool:
        return action in self.manual_approval_actions

    def forbidden(self, action: str) -> bool:
        return action in self.forbidden_actions


# --------------------------------------------------------------------------- #
# headers.yaml
# --------------------------------------------------------------------------- #
class HeaderModel(BaseModel):
    name: str
    mandatory: bool = False
    secret: bool = False
    value: str | None = None  # non-secret literal required by the official program
    value_ref: str | None = None  # secret reference (env/keyring), never plaintext
    note: str = ""

    @model_validator(mode="after")
    def _one_value_source(self) -> "HeaderModel":
        if self.value is not None and self.value_ref is not None:
            raise ValueError("header may define value or value_ref, not both")
        if self.secret and self.value is not None:
            raise ValueError("secret headers must use value_ref")
        return self


class HeadersModel(BaseModel):
    headers: list[HeaderModel] = Field(default_factory=list)
    secret_patterns: list[str] = Field(default_factory=list)

    def by_name(self) -> dict[str, HeaderModel]:
        return {h.name.lower(): h for h in self.headers}


# --------------------------------------------------------------------------- #
# accounts.yaml
# --------------------------------------------------------------------------- #
def _secret_ref(value: Any) -> str | None:
    """Normalize ergonomic YAML refs (``{env: NAME}``) to ``env:NAME``.

    Only reference metadata is normalized here.  Secret values are resolved
    inside the broker and never enter engagement/model summaries.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and len(value) == 1:
        kind, name = next(iter(value.items()))
        if kind in {"env", "keyring", "file"} and isinstance(name, str) and name.strip():
            return f"{kind}:{name.strip()}"
    raise ValueError("secret reference must use env:/keyring:/file: or {env|keyring|file: name}")


class AuthLoginModel(BaseModel):
    url: str
    method: Literal["POST", "PUT"] = "POST"
    body_type: Literal["json", "form"] = "json"
    username_field: str = "username"
    username_ref: str | dict[str, str]
    password_field: str = "password"
    password_ref: str | dict[str, str]
    success_status: int = 200
    bearer_json_path: str | None = None
    refresh_json_path: str | None = None
    cookie_name: str | None = None
    refresh_url: str | None = None
    refresh_method: Literal["POST", "PUT"] = "POST"
    refresh_token_field: str = "refresh_token"
    refresh_token_ref: str | dict[str, str] | None = None
    max_login_attempts: int = 1

    @model_validator(mode="after")
    def _normalize_login_refs(self) -> "AuthLoginModel":
        self.username_ref = _secret_ref(self.username_ref) or ""
        self.password_ref = _secret_ref(self.password_ref) or ""
        self.refresh_token_ref = _secret_ref(self.refresh_token_ref)
        self.max_login_attempts = max(1, min(int(self.max_login_attempts), 2))
        return self


class AccountAuthModel(BaseModel):
    type: Literal["bearer", "cookie", "header_bundle", "browser_session"] = "header_bundle"
    bearer_ref: str | dict[str, str] | None = None
    cookie_ref: str | dict[str, str] | None = None
    headers: dict[str, str | dict[str, str]] = Field(default_factory=dict)
    browser_profile: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    strategy: Literal["STATIC", "HTTP_LOGIN", "REFRESH_TOKEN", "COOKIE_LOGIN", "BEARER_LOGIN", "MANUAL_BROWSER"] = "STATIC"
    login: AuthLoginModel | None = None

    @model_validator(mode="after")
    def _normalize_refs(self) -> "AccountAuthModel":
        self.bearer_ref = _secret_ref(self.bearer_ref)
        self.cookie_ref = _secret_ref(self.cookie_ref)
        self.headers = {name: _secret_ref(ref) or "" for name, ref in self.headers.items()}
        if self.type == "bearer" and not self.bearer_ref:
            raise ValueError("bearer auth requires bearer_ref")
        if self.type == "cookie" and not self.cookie_ref:
            raise ValueError("cookie auth requires cookie_ref")
        if self.type == "header_bundle" and not self.headers:
            raise ValueError("header_bundle auth requires at least one header reference")
        if self.strategy in {"HTTP_LOGIN", "REFRESH_TOKEN", "COOKIE_LOGIN", "BEARER_LOGIN"} and self.login is None:
            raise ValueError(f"{self.strategy} requires auth.login configuration")
        return self

    def secret_refs(self) -> list[str]:
        refs = [self.bearer_ref, self.cookie_ref, *self.headers.values()]
        return [str(r) for r in refs if r]


class AccountModel(BaseModel):
    id: str  # e.g. account_a, account_b, admin_test
    role: str = ""
    description: str = ""
    secret_ref: str | None = None  # reference to a credential; never plaintext
    auth: AccountAuthModel | None = None
    enabled: bool = True

    @field_validator("secret_ref", mode="before")
    @classmethod
    def _normalize_legacy_secret_ref(cls, value: Any) -> str | None:
        return _secret_ref(value)


class AccountsModel(BaseModel):
    accounts: list[AccountModel] = Field(default_factory=list)

    def by_id(self) -> dict[str, AccountModel]:
        return {a.id: a for a in self.accounts}

    def enabled_ids(self) -> list[str]:
        return [a.id for a in self.accounts if a.enabled]


# --------------------------------------------------------------------------- #
# reporting.yaml
# --------------------------------------------------------------------------- #
class ReportingModel(BaseModel):
    platform: Platform | None = None
    severity_mechanism: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    submission_checklist: list[str] = Field(default_factory=list)
    notes: str = ""


# --------------------------------------------------------------------------- #
# autonomy.yaml
# --------------------------------------------------------------------------- #
class AutonomyModel(BaseModel):
    enabled: bool = False
    goal: Literal[
        "validated_finding", "validated", "poc_ready", "scored", "report_ready",
        "qa_passed", "budget_exhausted",
    ] = "validated_finding"
    stop_on_validated_finding: bool = True
    max_session_minutes: int = 180
    max_total_requests: int = 1000
    max_leads_per_session: int = 20
    max_leads_per_run: int | None = None
    max_hypotheses_per_lead: int = 8
    max_tests_per_hypothesis: int = 30
    max_requests_per_hypothesis: int = 30
    max_inconclusive_tests_per_hypothesis: int = 4
    max_failed_tests_per_hypothesis: int = 5
    max_redirects: int = 5
    # Deprecated compatibility field. Output preparation requires report/PoC
    # judgment and stays model-or-human orchestrated through idempotent tools.
    # It is never interpreted as permission to submit.
    auto_prepare_outputs: bool = False
    max_parallel_specialists: int = 1

    @field_validator(
        "max_session_minutes", "max_total_requests", "max_leads_per_session",
        "max_hypotheses_per_lead", "max_tests_per_hypothesis", "max_requests_per_hypothesis",
        "max_inconclusive_tests_per_hypothesis", "max_failed_tests_per_hypothesis",
        "max_redirects",
        "max_parallel_specialists",
    )
    @classmethod
    def _positive_budget(cls, value: int) -> int:
        if value < 1:
            raise ValueError("autonomy budgets must be >= 1")
        return value

    @field_validator("max_parallel_specialists")
    @classmethod
    def _bounded_specialists(cls, value: int) -> int:
        if not 1 <= value <= 2:
            raise ValueError("max_parallel_specialists must be 1 or 2")
        return value

    @field_validator("max_leads_per_run")
    @classmethod
    def _optional_positive_budget(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("autonomy budgets must be >= 1")
        return value


class ReconModel(BaseModel):
    passive_max_age_hours: int = 24
    light_max_age_hours: int = 12
    standard_max_age_hours: int = 24
    deep_max_age_hours: int = 168
    lead_threshold: int = 40
    interest_weights: dict[str, int] = Field(default_factory=dict)

    @field_validator("passive_max_age_hours", "light_max_age_hours", "standard_max_age_hours", "deep_max_age_hours")
    @classmethod
    def _positive_age(cls, value: int) -> int:
        if value < 1: raise ValueError("recon freshness hours must be >= 1")
        return value

    @field_validator("lead_threshold")
    @classmethod
    def _score_range(cls, value: int) -> int:
        if not 0 <= value <= 100: raise ValueError("recon lead_threshold must be 0..100")
        return value

    @field_validator("interest_weights")
    @classmethod
    def _bounded_weights(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not -100 <= int(weight) <= 100 for weight in value.values()):
            raise ValueError("recon interest weights must be -100..100")
        return value


class BurpIntegrationModel(BaseModel):
    mcp_url: str | None = None
    proxy_url: str | None = None
    ca_bundle: str | None = None
    https_interception: bool = False


class PlaywrightIntegrationModel(BaseModel):
    headed: bool = True


class IntegrationsModel(BaseModel):
    burp: BurpIntegrationModel = Field(default_factory=BurpIntegrationModel)
    playwright: PlaywrightIntegrationModel = Field(default_factory=PlaywrightIntegrationModel)


# --------------------------------------------------------------------------- #
# Engagement bundle
# --------------------------------------------------------------------------- #
class Engagement(BaseModel):
    program: ProgramModel
    scope: ScopeModel
    roe: ROEModel = Field(default_factory=ROEModel)
    headers: HeadersModel = Field(default_factory=HeadersModel)
    accounts: AccountsModel = Field(default_factory=AccountsModel)
    reporting: ReportingModel = Field(default_factory=ReportingModel)
    autonomy: AutonomyModel = Field(default_factory=AutonomyModel)
    recon: ReconModel = Field(default_factory=ReconModel)
    integrations: IntegrationsModel = Field(default_factory=IntegrationsModel)


__all__ = [
    "Platform",
    "ProgramModel",
    "ScopeSet",
    "ScopeModel",
    "ROEModel",
    "HeaderModel",
    "HeadersModel",
    "AccountModel",
    "AccountAuthModel",
    "AccountsModel",
    "ReportingModel",
    "AutonomyModel",
    "ReconModel",
    "BurpIntegrationModel",
    "PlaywrightIntegrationModel",
    "IntegrationsModel",
    "Engagement",
    "action_names",
]
