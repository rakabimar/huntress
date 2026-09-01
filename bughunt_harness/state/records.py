"""Entity record dataclasses returned by the per-program research state store."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionRecord:
    id: int
    public_id: str
    runtime: str
    agent_role: str
    program_slug: str
    started_at: str
    status: str
    ended_at: str | None = None
    active_lead_id: int | None = None


@dataclass
class LeadRecord:
    id: int
    public_id: str
    title: str
    entity: str
    source: str
    status: str
    priority: str
    rationale: str
    created_at: str
    updated_at: str
    claimed_session: str | None = None


@dataclass
class HypothesisRecord:
    id: int
    public_id: str
    statement: str
    rationale: str
    status: str
    created_at: str
    updated_at: str
    lead_id: int | None = None
    confidence: float | None = None


@dataclass
class ResearchTestRecord:
    id: int
    public_id: str
    hypothesis_id: int
    objective: str
    method: str
    status: str
    created_at: str
    baseline_ref: str = ""
    controlled_change: str = ""
    expected_if_true: str = ""
    expected_if_false: str = ""
    observation: str = ""
    result: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    completed_at: str | None = None


@dataclass
class EvidenceRecord:
    id: int
    public_id: str
    kind: str
    ref: str
    description: str
    preview: str
    created_at: str


@dataclass
class FindingRecord:
    id: int
    public_id: str
    title: str
    affected_target: str
    category: str
    status: str
    impact_summary: str
    created_at: str
    updated_at: str
    validation_state: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    cvss_data: dict | None = None
    report_path: str | None = None
    lead_id: int | None = None
    hypothesis_id: int | None = None
    test_ids: list[int] = field(default_factory=list)
    creator_session_id: int | None = None
    linkage_state: str = "complete"
    poc_path: str | None = None
    dedup_classification: str = ""
    potential_duplicate_of: int | None = None


@dataclass
class CheckpointRecord:
    id: int
    public_id: str
    created_at: str
    active_lead_id: int | None = None
    active_hypotheses: list[int] = field(default_factory=list)
    completed_tests: list[int] = field(default_factory=list)
    pending_tests: list[int] = field(default_factory=list)
    recent_observations: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    next_action: str = ""
    session_id: int | None = None
    autonomy_state: dict = field(default_factory=dict)
    pending_approval_id: int | None = None


@dataclass
class AgentActionRecord:
    id: int
    public_id: str
    agent_role: str
    action: str
    program: str
    target: str
    decision: str
    result_summary: str
    created_at: str
    session_id: int | None = None


@dataclass
class ApprovalRecord:
    id: int
    public_id: str
    action: str
    target: str
    status: str
    requested_by: str
    requested_at: str
    note: str = ""
    decided_at: str | None = None
    program: str = ""
    method: str = ""
    params_hash: str = ""
    expires_at: str | None = None
    used_at: str | None = None
    approved_by: str = ""
    session_id: int | None = None
    auth_context: str = ""
    constraints: dict = field(default_factory=dict)
    usage_count: int = 0
    autonomy_run_id: int | None = None


@dataclass
class ValidationReviewRecord:
    id: int
    public_id: str
    finding_id: int
    verdict: str
    status: str
    created_at: str
    reviewer_type: str = ""
    reviewer_runtime: str = ""
    reviewer_session: str = ""
    requested_by: str = ""
    reasoning_summary: str = ""
    check_results: dict = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    reviewer_role: str = ""
    reviewer_session_id: int | None = None


@dataclass
class AuthContextRecord:
    id: int
    public_id: str
    account_id: str
    type: str
    enabled: bool
    secret_refs: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    created_at: str = ""
    role: str = ""


@dataclass
class RequestRecord:
    id: int
    public_id: str
    program: str
    method: str
    url: str
    created_at: str
    session_id: int | None = None
    auth_context: str = ""
    request_metadata: dict = field(default_factory=dict)
    response_metadata: dict = field(default_factory=dict)
    burp_ref: str = ""
    body_hash: str = ""
    evidence_ref: str = ""
    research_test_id: int | None = None
    hypothesis_id: int | None = None
    controlled_mutation: dict = field(default_factory=dict)
    autonomy_run_id: int | None = None
    parent_request_id: int | None = None
    root_request_id: int | None = None
    replay_depth: int = 0
    mutation_summary: str = ""


@dataclass
class AutonomyRunRecord:
    id: int
    public_id: str
    session_id: int
    goal: str
    status: str
    started_at: str
    budget: dict = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    stop_reason: str = ""
    ended_at: str | None = None
    program: str = ""
    runtime: str = ""
    model_info: dict = field(default_factory=dict)


@dataclass
class AutonomyActivityRecord:
    id: int
    public_id: str
    autonomy_run_id: int
    session_id: int
    activity_type: str
    entity_type: str
    entity_id: int | None
    created_at: str
    metadata: dict = field(default_factory=dict)
