"""Engagement configuration schemas (program.yaml / scope.yaml / roe.yaml /
headers.yaml / accounts.yaml / reporting.yaml).

These are pure-data Pydantic models.  Matching/decision logic lives in the
scope and policy engines; the models only validate *shape* of configuration.
"""

from __future__ import annotations

from enum import Enum
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
    value_ref: str | None = None  # secret reference (env/keyring), never plaintext
    note: str = ""


class HeadersModel(BaseModel):
    headers: list[HeaderModel] = Field(default_factory=list)

    def by_name(self) -> dict[str, HeaderModel]:
        return {h.name.lower(): h for h in self.headers}


# --------------------------------------------------------------------------- #
# accounts.yaml
# --------------------------------------------------------------------------- #
class AccountModel(BaseModel):
    id: str  # e.g. account_a, account_b, admin_test
    role: str = ""
    description: str = ""
    secret_ref: str | None = None  # reference to a credential; never plaintext
    enabled: bool = True


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
# Engagement bundle
# --------------------------------------------------------------------------- #
class Engagement(BaseModel):
    program: ProgramModel
    scope: ScopeModel
    roe: ROEModel = Field(default_factory=ROEModel)
    headers: HeadersModel = Field(default_factory=HeadersModel)
    accounts: AccountsModel = Field(default_factory=AccountsModel)
    reporting: ReportingModel = Field(default_factory=ReportingModel)


__all__ = [
    "Platform",
    "ProgramModel",
    "ScopeSet",
    "ScopeModel",
    "ROEModel",
    "HeaderModel",
    "HeadersModel",
    "AccountModel",
    "AccountsModel",
    "ReportingModel",
    "Engagement",
    "action_names",
]