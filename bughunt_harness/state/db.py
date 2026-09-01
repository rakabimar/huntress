"""Per-program research state (SQLite ``state/hunt.db``).

One HuntDB instance is bound to ONE program's workspace.  The database stores a
``meta.program_slug`` row on first open and refuses to open against a different
program — this is a hard per-session isolation invariant (spec §91).

Writes are guarded by a re-entrant lock; the connection is WAL + foreign_keys
enabled, and ``check_same_thread`` is relaxed so the MCP server (async) can use
the same store safely.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import STATE_SCHEMA_VERSION
from ..errors import StateError
from ..timeutil import utcnow
from .constants import (
    APPROVAL_APPROVED,
    APPROVAL_CONSUMED,
    APPROVAL_EXPIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    FINDING_CANDIDATE,
    FINDING_KILLED,
    FINDING_VALIDATED,
    FINDING_VALIDATION,
    HYPO_OPEN,
    LEAD_OPEN,
    SESSION_ENDED,
    SESSION_RUNNING,
    TEST_EXECUTED,
    TEST_PLANNED,
    VREVIEW_OPEN,
    VREVIEW_SUBMITTED,
    VR_INCONCLUSIVE,
    VR_REJECTED,
    VR_SUPPORTED,
    validate_transition,
)
from .records import (
    AgentActionRecord,
    ApprovalRecord,
    AuthContextRecord,
    AutonomyRunRecord,
    AutonomyActivityRecord,
    CheckpointRecord,
    EvidenceRecord,
    FindingRecord,
    HypothesisRecord,
    LeadRecord,
    RequestRecord,
    ResearchTestRecord,
    SessionRecord,
    ValidationReviewRecord,
)

PUBLIC_ID_PREFIX = {
    "session": "SES",
    "lead": "LEAD",
    "hypothesis": "HYP",
    "research_test": "TEST",
    "evidence": "EVD",
    "finding": "FIND",
    "checkpoint": "CKPT",
    "agent_action": "ACT",
    "approval": "APP",
    "validation_review": "VREV",
    "auth_context": "AUTH",
    "request_record": "REQ",
    "autonomy_run": "RUN",
    "autonomy_activity": "AAT",
    "recon_run": "RECON",
    "asset": "ASSET",
    "endpoint": "ENDP",
    "endpoint_parameter": "PARAM",
    "technology_observation": "TECH",
    "recon_change": "CHANGE",
    "source_repository": "SRC",
    "source_observation": "SOBS",
    "source_analysis_run": "SARUN",
    "source_runtime_mapping": "SRMAP",
    "source_symbol": "SSYM",
    "security_invariant": "SINV",
    "root_cause": "ROOT",
    "specialist_task": "TASK",
    "agent_turn": "TURN",
    "tool_call": "TCALL",
    "skill_usage": "SUSE",
}

_BASELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    runtime        TEXT NOT NULL,
    agent_role     TEXT NOT NULL,
    program_slug   TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    ended_at       TEXT,
    status         TEXT NOT NULL,
    active_lead_id INTEGER
);
CREATE TABLE IF NOT EXISTS lead (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    entity          TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'manual',
    status          TEXT NOT NULL DEFAULT 'open',
    priority        TEXT NOT NULL DEFAULT 'medium',
    rationale       TEXT NOT NULL DEFAULT '',
    claimed_session TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypothesis (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id    INTEGER,
    statement  TEXT NOT NULL,
    rationale  TEXT NOT NULL DEFAULT '',
    confidence REAL,
    status     TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS research_test (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id     INTEGER NOT NULL,
    objective         TEXT NOT NULL,
    method            TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'planned',
    baseline_ref      TEXT NOT NULL DEFAULT '',
    controlled_change TEXT NOT NULL DEFAULT '',
    expected_if_true  TEXT NOT NULL DEFAULT '',
    expected_if_false TEXT NOT NULL DEFAULT '',
    observation       TEXT NOT NULL DEFAULT '',
    result            TEXT,
    evidence_refs     TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL,
    completed_at      TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    ref         TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    preview     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT NOT NULL,
    affected_target  TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'candidate',
    validation_state TEXT,
    impact_summary   TEXT NOT NULL DEFAULT '',
    evidence_refs    TEXT NOT NULL DEFAULT '[]',
    cvss_data        TEXT,
    report_path      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoint (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    active_lead_id      INTEGER,
    active_hypotheses   TEXT NOT NULL DEFAULT '[]',
    completed_tests     TEXT NOT NULL DEFAULT '[]',
    pending_tests       TEXT NOT NULL DEFAULT '[]',
    recent_observations TEXT NOT NULL DEFAULT '[]',
    evidence_refs       TEXT NOT NULL DEFAULT '[]',
    next_action         TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_action (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     INTEGER,
    agent_role     TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    program        TEXT NOT NULL,
    target         TEXT NOT NULL DEFAULT '',
    decision       TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approval (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL,
    decided_at   TEXT,
    note         TEXT NOT NULL DEFAULT ''
);
"""


def _jload(raw: str | None, default):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


def _jdump(obj) -> str:
    return json.dumps(obj, default=str)


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


_CREATE_VALIDATION_REVIEW = """
CREATE TABLE IF NOT EXISTS validation_review (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER NOT NULL,
    verdict           TEXT NOT NULL DEFAULT 'inconclusive',
    status            TEXT NOT NULL DEFAULT 'open',
    reviewer_type     TEXT NOT NULL DEFAULT '',
    reviewer_runtime  TEXT NOT NULL DEFAULT '',
    reviewer_session  TEXT NOT NULL DEFAULT '',
    requested_by      TEXT NOT NULL DEFAULT '',
    reasoning_summary TEXT NOT NULL DEFAULT '',
    check_results     TEXT NOT NULL DEFAULT '{}',
    evidence_refs     TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vreview_finding ON validation_review(finding_id);
"""

_CREATE_AUTH_CONTEXT = """
CREATE TABLE IF NOT EXISTS auth_context (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT NOT NULL UNIQUE,
    type         TEXT NOT NULL DEFAULT 'header_bundle',
    enabled      INTEGER NOT NULL DEFAULT 1,
    secret_refs  TEXT NOT NULL DEFAULT '[]',
    metadata     TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);
"""

# Cross-process rate-limiter state (one row per program+host window).
_CREATE_RATE_LIMIT = """
CREATE TABLE IF NOT EXISTS rate_limit (
    program      TEXT NOT NULL,
    host         TEXT NOT NULL,
    bucket_start REAL NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    in_flight    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (program, host)
);
"""

# Structured request records (never raw bodies/secrets).
_CREATE_REQUEST_RECORD = """
CREATE TABLE IF NOT EXISTS request_record (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    program            TEXT NOT NULL,
    session_id         INTEGER,
    auth_context       TEXT NOT NULL DEFAULT '',
    method             TEXT NOT NULL,
    url                TEXT NOT NULL,
    request_metadata   TEXT NOT NULL DEFAULT '{}',
    response_metadata  TEXT NOT NULL DEFAULT '{}',
    burp_ref           TEXT NOT NULL DEFAULT '',
    body_hash          TEXT NOT NULL DEFAULT '',
    evidence_ref       TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_request_program ON request_record(program);
"""

_CREATE_RATE_LIMIT_LEASE = """
CREATE TABLE IF NOT EXISTS rate_limit_lease (
    lease_id    TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    host        TEXT NOT NULL,
    session_id  INTEGER,
    acquired_at REAL NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_lease_host
    ON rate_limit_lease(program, host, expires_at);
"""

_CREATE_AUTONOMY_RUN = """
CREATE TABLE IF NOT EXISTS autonomy_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    budget      TEXT NOT NULL DEFAULT '{}',
    usage       TEXT NOT NULL DEFAULT '{}',
    stop_reason TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_autonomy_session ON autonomy_run(session_id);
"""

_CREATE_AUTONOMY_ACTIVITY = """
CREATE TABLE IF NOT EXISTS autonomy_activity (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    autonomy_run_id INTEGER NOT NULL REFERENCES autonomy_run(id) ON DELETE CASCADE,
    session_id      INTEGER NOT NULL,
    activity_type   TEXT NOT NULL,
    entity_type     TEXT NOT NULL DEFAULT '',
    entity_id       INTEGER,
    created_at      TEXT NOT NULL,
    metadata        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_autonomy_activity_run
    ON autonomy_activity(autonomy_run_id, activity_type, entity_type, entity_id);

CREATE TABLE IF NOT EXISTS lead_recon_change (
    lead_id         INTEGER NOT NULL REFERENCES lead(id) ON DELETE CASCADE,
    recon_change_id INTEGER NOT NULL REFERENCES recon_change(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (lead_id, recon_change_id)
);
"""

_CREATE_RECON_INVENTORY = """
CREATE TABLE IF NOT EXISTS recon_run (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    profile               TEXT NOT NULL DEFAULT '',
    stage                 TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'queued',
    started_at            TEXT NOT NULL,
    completed_at          TEXT,
    tools_requested       TEXT NOT NULL DEFAULT '[]',
    tools_used            TEXT NOT NULL DEFAULT '[]',
    raw_observation_count INTEGER NOT NULL DEFAULT 0,
    new_asset_count       INTEGER NOT NULL DEFAULT 0,
    updated_asset_count   INTEGER NOT NULL DEFAULT 0,
    new_endpoint_count    INTEGER NOT NULL DEFAULT 0,
    lead_count            INTEGER NOT NULL DEFAULT 0,
    error_count           INTEGER NOT NULL DEFAULT 0,
    artifact_refs         TEXT NOT NULL DEFAULT '[]',
    metadata              TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_recon_run_status ON recon_run(status, id);

CREATE TABLE IF NOT EXISTS asset (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    type              TEXT NOT NULL,
    value             TEXT NOT NULL,
    normalized_value  TEXT NOT NULL,
    scope_status      TEXT NOT NULL DEFAULT 'unknown',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    interest_score    INTEGER NOT NULL DEFAULT 0,
    interesting       INTEGER NOT NULL DEFAULT 0,
    confidence        REAL NOT NULL DEFAULT 0.5,
    observation_count INTEGER NOT NULL DEFAULT 0,
    metadata          TEXT NOT NULL DEFAULT '{}',
    UNIQUE(type, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_asset_interest ON asset(interesting, interest_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_last_seen ON asset(last_seen);

CREATE TABLE IF NOT EXISTS asset_observation (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    recon_run_id     INTEGER NOT NULL REFERENCES recon_run(id) ON DELETE CASCADE,
    source_tool      TEXT NOT NULL,
    source_type      TEXT NOT NULL,
    observed_at      TEXT NOT NULL,
    observation_type TEXT NOT NULL,
    raw_value        TEXT NOT NULL DEFAULT '',
    artifact_ref     TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    UNIQUE(asset_id, recon_run_id, source_tool, observation_type, raw_value)
);
CREATE INDEX IF NOT EXISTS idx_asset_observation_asset ON asset_observation(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_observation_run ON asset_observation(recon_run_id);

CREATE TABLE IF NOT EXISTS endpoint (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    scheme           TEXT NOT NULL DEFAULT '',
    method           TEXT NOT NULL DEFAULT 'GET',
    normalized_path  TEXT NOT NULL,
    auth_required    INTEGER,
    auth_observed    INTEGER NOT NULL DEFAULT 0,
    content_type     TEXT NOT NULL DEFAULT '',
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    source_count     INTEGER NOT NULL DEFAULT 0,
    interest_score   INTEGER NOT NULL DEFAULT 0,
    interesting      INTEGER NOT NULL DEFAULT 0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    UNIQUE(host_asset_id, scheme, method, normalized_path)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_interest ON endpoint(interesting, interest_score DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_host ON endpoint(host_asset_id);

CREATE TABLE IF NOT EXISTS endpoint_parameter (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id                 INTEGER NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
    name                        TEXT NOT NULL,
    location                    TEXT NOT NULL,
    observed_types              TEXT NOT NULL DEFAULT '[]',
    user_controlled             INTEGER NOT NULL DEFAULT 0,
    sensitive_name              INTEGER NOT NULL DEFAULT 0,
    object_identifier_candidate INTEGER NOT NULL DEFAULT 0,
    first_seen                  TEXT NOT NULL,
    last_seen                   TEXT NOT NULL,
    metadata                    TEXT NOT NULL DEFAULT '{}',
    UNIQUE(endpoint_id, name, location)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_parameter_endpoint ON endpoint_parameter(endpoint_id);

CREATE TABLE IF NOT EXISTS technology_observation (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    endpoint_id INTEGER REFERENCES endpoint(id) ON DELETE CASCADE,
    technology  TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'other',
    confidence  REAL NOT NULL DEFAULT 0.5,
    source      TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    UNIQUE(asset_id, endpoint_id, technology, source)
);
CREATE INDEX IF NOT EXISTS idx_technology_asset ON technology_observation(asset_id);

CREATE TABLE IF NOT EXISTS recon_change (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recon_run_id   INTEGER NOT NULL REFERENCES recon_run(id) ON DELETE CASCADE,
    change_type    TEXT NOT NULL,
    entity_type    TEXT NOT NULL,
    entity_id      INTEGER NOT NULL,
    old_value      TEXT NOT NULL DEFAULT '',
    new_value      TEXT NOT NULL DEFAULT '',
    interest_score INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    UNIQUE(recon_run_id, change_type, entity_type, entity_id, new_value)
);
CREATE INDEX IF NOT EXISTS idx_recon_change_run ON recon_change(recon_run_id, interest_score DESC);
"""

_CREATE_PROGRAM_INTAKE = """
CREATE TABLE IF NOT EXISTS program_import (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id                TEXT NOT NULL UNIQUE,
    program_slug             TEXT NOT NULL,
    platform                 TEXT NOT NULL,
    platform_program_id      TEXT,
    platform_handle          TEXT NOT NULL DEFAULT '',
    source_locator           TEXT NOT NULL DEFAULT '',
    adapter_version          TEXT NOT NULL DEFAULT '',
    parser_version           TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL,
    started_at               TEXT NOT NULL,
    completed_at             TEXT,
    last_checked_at          TEXT,
    source_hash              TEXT NOT NULL DEFAULT '',
    draft_hash               TEXT NOT NULL DEFAULT '',
    scope_hash               TEXT NOT NULL DEFAULT '',
    roe_hash                 TEXT NOT NULL DEFAULT '',
    structured_source_count  INTEGER NOT NULL DEFAULT 0,
    prose_source_count       INTEGER NOT NULL DEFAULT 0,
    ambiguity_count          INTEGER NOT NULL DEFAULT 0,
    critical_ambiguity_count INTEGER NOT NULL DEFAULT 0,
    approved_at              TEXT,
    approved_by              TEXT,
    supersedes_import_id     TEXT,
    metadata                 TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_program_import_status
    ON program_import(program_slug, status, id DESC);

CREATE TABLE IF NOT EXISTS program_source (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id         TEXT NOT NULL,
    source_type       TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    retrieved_at      TEXT NOT NULL,
    content_hash      TEXT NOT NULL,
    artifact_ref      TEXT NOT NULL,
    trust_level       INTEGER NOT NULL,
    status            TEXT NOT NULL,
    etag              TEXT,
    last_modified     TEXT,
    metadata          TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(import_id) REFERENCES program_import(public_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_program_source_import ON program_source(import_id, id);

CREATE TABLE IF NOT EXISTS program_ambiguity (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id           TEXT NOT NULL,
    import_id           TEXT NOT NULL,
    field_path          TEXT NOT NULL,
    severity            TEXT NOT NULL,
    category            TEXT NOT NULL,
    reason              TEXT NOT NULL,
    source_refs         TEXT NOT NULL DEFAULT '[]',
    proposed_value      TEXT NOT NULL DEFAULT 'null',
    alternatives        TEXT NOT NULL DEFAULT '[]',
    required_user_input TEXT,
    status              TEXT NOT NULL DEFAULT 'OPEN',
    resolution          TEXT NOT NULL DEFAULT 'null',
    resolved_at         TEXT,
    resolved_by         TEXT,
    UNIQUE(import_id, public_id),
    FOREIGN KEY(import_id) REFERENCES program_import(public_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_program_ambiguity_import
    ON program_ambiguity(import_id, status, severity);

CREATE TABLE IF NOT EXISTS program_import_approval (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id    TEXT NOT NULL UNIQUE,
    approved_at  TEXT NOT NULL,
    approved_by  TEXT NOT NULL,
    actor_kind   TEXT NOT NULL DEFAULT 'human',
    draft_hash   TEXT NOT NULL,
    scope_hash   TEXT NOT NULL,
    roe_hash     TEXT NOT NULL,
    program_hash TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(import_id) REFERENCES program_import(public_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS program_intake_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id  TEXT,
    event      TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL,
    metadata   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_program_intake_audit ON program_intake_audit(import_id, id);
"""

_CREATE_SOURCE_INTELLIGENCE = """
CREATE TABLE IF NOT EXISTS source_repository (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id    TEXT NOT NULL UNIQUE,
    official_url     TEXT NOT NULL,
    source_type      TEXT NOT NULL DEFAULT 'git',
    requested_ref    TEXT NOT NULL,
    resolved_commit  TEXT NOT NULL,
    previous_commit  TEXT NOT NULL DEFAULT '',
    branch           TEXT NOT NULL DEFAULT '',
    tag              TEXT NOT NULL DEFAULT '',
    retrieved_at     TEXT NOT NULL,
    program_relation TEXT NOT NULL DEFAULT 'in_scope_source',
    license_info     TEXT NOT NULL DEFAULT '',
    snapshot_path    TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    metadata         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_source_repository_commit
    ON source_repository(repository_id, resolved_commit);

CREATE TABLE IF NOT EXISTS source_analysis_run (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id      INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    analysis_type      TEXT NOT NULL,
    tool               TEXT NOT NULL DEFAULT 'builtin',
    tool_version       TEXT NOT NULL DEFAULT '',
    source_commit      TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'running',
    started_at         TEXT NOT NULL,
    completed_at       TEXT,
    files_read         INTEGER NOT NULL DEFAULT 0,
    searches           INTEGER NOT NULL DEFAULT 0,
    observation_count  INTEGER NOT NULL DEFAULT 0,
    artifact_refs      TEXT NOT NULL DEFAULT '[]',
    metadata           TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_source_analysis_repository
    ON source_analysis_run(repository_id, id DESC);

CREATE TABLE IF NOT EXISTS source_runtime_mapping (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id         INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    source_commit         TEXT NOT NULL,
    source_surface        TEXT NOT NULL DEFAULT '',
    runtime_target        TEXT NOT NULL,
    runtime_version       TEXT NOT NULL DEFAULT '',
    runtime_endpoint_id   INTEGER REFERENCES endpoint(id) ON DELETE SET NULL,
    confidence            REAL NOT NULL DEFAULT 0.0,
    mapping_method        TEXT NOT NULL,
    evidence_refs         TEXT NOT NULL DEFAULT '[]',
    status                TEXT NOT NULL DEFAULT 'candidate',
    created_at            TEXT NOT NULL,
    metadata              TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_source_runtime_repository
    ON source_runtime_mapping(repository_id, confidence DESC, id DESC);

CREATE TABLE IF NOT EXISTS source_observation (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id       INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    analysis_run_id     INTEGER REFERENCES source_analysis_run(id) ON DELETE SET NULL,
    observation_type    TEXT NOT NULL,
    file                TEXT NOT NULL,
    line_start          INTEGER,
    line_end            INTEGER,
    symbol              TEXT NOT NULL DEFAULT '',
    source_commit       TEXT NOT NULL,
    observation         TEXT NOT NULL,
    redacted_excerpt    TEXT NOT NULL DEFAULT '',
    confidence          REAL NOT NULL DEFAULT 0.5,
    source_skill        TEXT NOT NULL,
    runtime_mapping_id  INTEGER REFERENCES source_runtime_mapping(id) ON DELETE SET NULL,
    lead_id             INTEGER REFERENCES lead(id) ON DELETE SET NULL,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    metadata            TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_source_observation_repository
    ON source_observation(repository_id, source_commit, confidence DESC, id DESC);
"""

_CREATE_RESEARCH_INTELLIGENCE_V8 = """
CREATE TABLE IF NOT EXISTS source_security_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    source_commit TEXT NOT NULL,
    architecture_summary TEXT NOT NULL DEFAULT '',
    components TEXT NOT NULL DEFAULT '[]',
    entry_points TEXT NOT NULL DEFAULT '[]',
    trust_boundaries TEXT NOT NULL DEFAULT '[]',
    security_controls TEXT NOT NULL DEFAULT '[]',
    sensitive_assets TEXT NOT NULL DEFAULT '[]',
    external_integrations TEXT NOT NULL DEFAULT '[]',
    data_stores TEXT NOT NULL DEFAULT '[]',
    security_invariants TEXT NOT NULL DEFAULT '[]',
    unresolved_questions TEXT NOT NULL DEFAULT '[]',
    generated_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(repository_id, source_commit)
);
CREATE TABLE IF NOT EXISTS source_symbol (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    source_commit TEXT NOT NULL,
    language TEXT NOT NULL,
    file TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'MEDIUM',
    assumptions TEXT NOT NULL DEFAULT '[]',
    guarantees TEXT NOT NULL DEFAULT '[]',
    controls TEXT NOT NULL DEFAULT '[]',
    inputs TEXT NOT NULL DEFAULT '[]',
    outputs TEXT NOT NULL DEFAULT '[]',
    callers TEXT NOT NULL DEFAULT '[]',
    callees TEXT NOT NULL DEFAULT '[]',
    side_effects TEXT NOT NULL DEFAULT '[]',
    trust_boundary TEXT NOT NULL DEFAULT '',
    unresolved_assumptions TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(repository_id, source_commit, file, line_start, name, kind)
);
CREATE INDEX IF NOT EXISTS idx_source_symbol_lookup
    ON source_symbol(repository_id, source_commit, name, kind);
CREATE TABLE IF NOT EXISTS security_invariant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    source_commit TEXT NOT NULL,
    component TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    source_evidence TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.5,
    supporting_controls TEXT NOT NULL DEFAULT '[]',
    possible_violations TEXT NOT NULL DEFAULT '[]',
    source_skill TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate',
    created_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_security_invariant_repo
    ON security_invariant(repository_id, source_commit, confidence DESC);
CREATE TABLE IF NOT EXISTS root_cause (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES source_repository(id) ON DELETE CASCADE,
    source_commit TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    affected_component TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    violated_invariant TEXT NOT NULL DEFAULT '',
    exact_pattern TEXT NOT NULL DEFAULT '',
    fix_pattern TEXT NOT NULL DEFAULT '',
    preconditions TEXT NOT NULL DEFAULT '[]',
    dangerous_sink TEXT NOT NULL DEFAULT '',
    safe_sibling TEXT NOT NULL DEFAULT '',
    rule_artifacts TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS specialist_task (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autonomy_run_id INTEGER REFERENCES autonomy_run(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES session(id) ON DELETE SET NULL,
    created_by_role TEXT NOT NULL,
    assigned_role TEXT NOT NULL,
    lead_id INTEGER REFERENCES lead(id) ON DELETE SET NULL,
    hypothesis_id INTEGER REFERENCES hypothesis(id) ON DELETE SET NULL,
    goal TEXT NOT NULL,
    input_summary TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'PENDING',
    result_summary TEXT NOT NULL DEFAULT '',
    result_refs TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    tokens INTEGER NOT NULL DEFAULT 0,
    cost REAL NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_specialist_task_run ON specialist_task(autonomy_run_id, status, id);
CREATE TABLE IF NOT EXISTS agent_turn (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autonomy_run_id INTEGER REFERENCES autonomy_run(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES session(id) ON DELETE SET NULL,
    role TEXT NOT NULL,
    specialist_task_id INTEGER REFERENCES specialist_task(id) ON DELETE SET NULL,
    model TEXT NOT NULL DEFAULT '',
    runtime TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    estimated_cost REAL NOT NULL DEFAULT 0,
    skills_loaded TEXT NOT NULL DEFAULT '[]',
    tools_available_count INTEGER NOT NULL DEFAULT 0,
    tool_calls_count INTEGER NOT NULL DEFAULT 0,
    lead_id INTEGER REFERENCES lead(id) ON DELETE SET NULL,
    hypothesis_id INTEGER REFERENCES hypothesis(id) ON DELETE SET NULL,
    test_id INTEGER REFERENCES research_test(id) ON DELETE SET NULL,
    outcome TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_agent_turn_run ON agent_turn(autonomy_run_id, id);
CREATE TABLE IF NOT EXISTS tool_call (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_turn_id INTEGER REFERENCES agent_turn(id) ON DELETE SET NULL,
    autonomy_run_id INTEGER REFERENCES autonomy_run(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES session(id) ON DELETE SET NULL,
    role TEXT NOT NULL,
    tool TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    success INTEGER NOT NULL DEFAULT 0,
    error_class TEXT NOT NULL DEFAULT '',
    request_id INTEGER REFERENCES request_record(id) ON DELETE SET NULL,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_tool_call_run ON tool_call(autonomy_run_id, tool, success);
CREATE TABLE IF NOT EXISTS skill_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autonomy_run_id INTEGER REFERENCES autonomy_run(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES session(id) ON DELETE SET NULL,
    specialist_task_id INTEGER REFERENCES specialist_task(id) ON DELETE SET NULL,
    skill TEXT NOT NULL,
    role TEXT NOT NULL,
    lead_id INTEGER REFERENCES lead(id) ON DELETE SET NULL,
    hypothesis_id INTEGER REFERENCES hypothesis(id) ON DELETE SET NULL,
    candidate_resulted INTEGER NOT NULL DEFAULT 0,
    validator_killed INTEGER NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    cost REAL NOT NULL DEFAULT 0,
    activated_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_skill_usage_run ON skill_usage(autonomy_run_id, skill);
"""

_CREATE_CAPABILITIES_V10 = """
CREATE TABLE IF NOT EXISTS differential_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL DEFAULT '', baseline_request_id INTEGER,
    request_ids TEXT NOT NULL DEFAULT '[]', research_test_id INTEGER,
    hypothesis_id INTEGER, result TEXT NOT NULL DEFAULT '{}',
    artifact_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oast_session (
    id INTEGER PRIMARY KEY AUTOINCREMENT, program TEXT NOT NULL,
    autonomy_run_id INTEGER, research_session_id INTEGER, provider TEXT NOT NULL,
    provider_session_reference TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, status TEXT NOT NULL, third_party_provider INTEGER NOT NULL DEFAULT 1,
    approval_id INTEGER, metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_oast_session_program ON oast_session(program, status);
CREATE TABLE IF NOT EXISTS oast_probe (
    id INTEGER PRIMARY KEY AUTOINCREMENT, oast_session_id INTEGER NOT NULL REFERENCES oast_session(id) ON DELETE CASCADE,
    hypothesis_id INTEGER, research_test_id INTEGER, request_id INTEGER,
    correlation_token TEXT NOT NULL UNIQUE, callback_domain TEXT NOT NULL,
    callback_urls TEXT NOT NULL DEFAULT '{}', expected_protocols TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE INDEX IF NOT EXISTS idx_oast_probe_test ON oast_probe(research_test_id, hypothesis_id);
CREATE TABLE IF NOT EXISTS oast_interaction (
    id INTEGER PRIMARY KEY AUTOINCREMENT, probe_id INTEGER NOT NULL REFERENCES oast_probe(id) ON DELETE CASCADE,
    provider_interaction_id TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL,
    observed_at TEXT NOT NULL, remote_address TEXT NOT NULL DEFAULT '', request_method TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', sanitized_headers TEXT NOT NULL DEFAULT '{}',
    artifact_ref TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL DEFAULT '', dedup_fingerprint TEXT NOT NULL UNIQUE,
    evidence_id INTEGER, metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS auth_session (
    id INTEGER PRIMARY KEY AUTOINCREMENT, auth_context TEXT NOT NULL UNIQUE,
    strategy TEXT NOT NULL DEFAULT 'STATIC', state TEXT NOT NULL DEFAULT 'VALID',
    issued_at TEXT, expires_at TEXT, last_refresh TEXT, credential_ref TEXT NOT NULL DEFAULT '',
    refresh_count INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS auth_session_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, auth_session_id INTEGER NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    event TEXT NOT NULL, request_id INTEGER, created_at TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS coverage_observation (
    id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, endpoint_id INTEGER,
    method TEXT NOT NULL DEFAULT '', parameter TEXT NOT NULL DEFAULT '', auth_context_class TEXT NOT NULL DEFAULT '',
    skill_family TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, research_test_id INTEGER,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(endpoint_id, method, parameter, auth_context_class, skill_family)
);
CREATE TABLE IF NOT EXISTS js_artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
    content_hash TEXT NOT NULL, size INTEGER NOT NULL, source_map_url TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, analysis_version TEXT NOT NULL,
    artifact_ref TEXT NOT NULL DEFAULT '', observations TEXT NOT NULL DEFAULT '{}', metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS finding_fingerprint (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL UNIQUE REFERENCES finding(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL, normalized TEXT NOT NULL DEFAULT '{}', dedup_version TEXT NOT NULL,
    potential_duplicate_of INTEGER, duplicate_score REAL NOT NULL DEFAULT 0,
    duplicate_reason TEXT NOT NULL DEFAULT '', classification TEXT NOT NULL DEFAULT 'DISTINCT', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_fingerprint ON finding_fingerprint(fingerprint);
CREATE TABLE IF NOT EXISTS prior_finding (
    id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL, title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '', normalized_endpoint TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
    submitted_at TEXT, duplicate_status TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(report_id)
);
CREATE TABLE IF NOT EXISTS recon_watch (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
    last_run TEXT, next_run TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', last_result TEXT NOT NULL DEFAULT '{}',
    error_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, UNIQUE(profile)
);
CREATE TABLE IF NOT EXISTS program_learning (
    id INTEGER PRIMARY KEY AUTOINCREMENT, signal TEXT NOT NULL, skill TEXT NOT NULL DEFAULT '',
    specialist TEXT NOT NULL DEFAULT '', surface_type TEXT NOT NULL DEFAULT '', attempted INTEGER NOT NULL DEFAULT 0,
    supported INTEGER NOT NULL DEFAULT 0, candidates INTEGER NOT NULL DEFAULT 0,
    validator_killed INTEGER NOT NULL DEFAULT 0, validated INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL, UNIQUE(signal, skill, specialist, surface_type)
);
CREATE TABLE IF NOT EXISTS knowledge_document (
    id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, source_id TEXT NOT NULL,
    title TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '', content TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
    retrieved_at TEXT NOT NULL, UNIQUE(category, source_id, content_hash)
);
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(title, summary, content, content='knowledge_document', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge_document BEGIN
  INSERT INTO knowledge_fts(rowid,title,summary,content) VALUES(new.id,new.title,new.summary,new.content);
END;
CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge_document BEGIN
  INSERT INTO knowledge_fts(knowledge_fts,rowid,title,summary,content) VALUES('delete',old.id,old.title,old.summary,old.content);
END;
CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge_document BEGIN
  INSERT INTO knowledge_fts(knowledge_fts,rowid,title,summary,content) VALUES('delete',old.id,old.title,old.summary,old.content);
  INSERT INTO knowledge_fts(rowid,title,summary,content) VALUES(new.id,new.title,new.summary,new.content);
END;
CREATE TABLE IF NOT EXISTS specialist_task_lease (
    task_id INTEGER PRIMARY KEY REFERENCES specialist_task(id) ON DELETE CASCADE,
    lease_owner TEXT NOT NULL, acquired_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
"""


def _migration_v3(conn: sqlite3.Connection) -> None:
    """v2 -> v3: autonomous runs and security-principal/linkage integrity."""
    _add_column(conn, "finding", "creator_session_id", "INTEGER")
    _add_column(conn, "finding", "linkage_state", "TEXT NOT NULL DEFAULT 'legacy_incomplete'")
    _add_column(conn, "finding", "poc_path", "TEXT")
    _add_column(conn, "checkpoint", "session_id", "INTEGER")
    _add_column(conn, "checkpoint", "autonomy_state", "TEXT NOT NULL DEFAULT '{}'")
    _add_column(conn, "checkpoint", "pending_approval_id", "INTEGER")
    _add_column(conn, "approval", "auth_context", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "approval", "constraints", "TEXT NOT NULL DEFAULT '{}'")
    _add_column(conn, "approval", "usage_count", "INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "validation_review", "reviewer_role", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "validation_review", "reviewer_session_id", "INTEGER")
    _add_column(conn, "auth_context", "role", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "request_record", "research_test_id", "INTEGER")
    _add_column(conn, "request_record", "hypothesis_id", "INTEGER")
    _add_column(conn, "request_record", "controlled_mutation", "TEXT NOT NULL DEFAULT '{}'")
    conn.executescript(_CREATE_RATE_LIMIT_LEASE)
    conn.executescript(_CREATE_AUTONOMY_RUN)


def _migration_v4(conn: sqlite3.Connection) -> None:
    """v3 -> v4: persistent, normalized recon and attack-surface inventory."""
    conn.executescript(_CREATE_RECON_INVENTORY)


def _migration_v5(conn: sqlite3.Connection) -> None:
    """v4 -> v5: immutable autonomy provenance and recon-change/Lead linkage."""
    _add_column(conn, "autonomy_run", "program", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "autonomy_run", "runtime", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "autonomy_run", "model_info", "TEXT NOT NULL DEFAULT '{}'")
    _add_column(conn, "request_record", "autonomy_run_id", "INTEGER")
    conn.executescript(_CREATE_AUTONOMY_ACTIVITY)


def _migration_v6(conn: sqlite3.Connection) -> None:
    """v5 -> v6: human-gated, provenance-preserving program intake."""
    conn.executescript(_CREATE_PROGRAM_INTAKE)


def _migration_v7(conn: sqlite3.Connection) -> None:
    """v6 -> v7: bounded, program-local whitebox source intelligence."""
    conn.executescript(_CREATE_SOURCE_INTELLIGENCE)


def _migration_v8(conn: sqlite3.Connection) -> None:
    """v7 -> v8: security architecture, handoffs, telemetry, scoped ASK."""
    _add_column(conn, "approval", "autonomy_run_id", "INTEGER")
    conn.executescript(_CREATE_RESEARCH_INTELLIGENCE_V8)


def _migration_v9(conn: sqlite3.Connection) -> None:
    """v8 -> v9: actual specialist execution and invocation correlation."""
    _add_column(conn, "specialist_task", "creator_session_id", "INTEGER")
    _add_column(conn, "specialist_task", "input_context_ref", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "specialist_task", "claimed_session_id", "INTEGER")
    _add_column(conn, "specialist_task", "timeout_seconds", "INTEGER NOT NULL DEFAULT 600")
    _add_column(conn, "specialist_task", "error", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "specialist_task", "model", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "specialist_task", "runtime", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "tool_call", "invocation_id", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "tool_call", "lead_id", "INTEGER")
    _add_column(conn, "tool_call", "hypothesis_id", "INTEGER")
    _add_column(conn, "tool_call", "test_id", "INTEGER")
    _add_column(conn, "tool_call", "source_analysis_run_id", "INTEGER")
    _add_column(conn, "tool_call", "specialist_task_id", "INTEGER")
    _add_column(conn, "tool_call", "result_summary", "TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "UPDATE specialist_task SET creator_session_id=session_id "
        "WHERE creator_session_id IS NULL AND session_id IS NOT NULL"
    )


def _migration_v10(conn: sqlite3.Connection) -> None:
    """v9 -> v10: replay, differential, OAST, lifecycle, coverage and learning."""
    _add_column(conn, "request_record", "parent_request_id", "INTEGER")
    _add_column(conn, "request_record", "root_request_id", "INTEGER")
    _add_column(conn, "request_record", "replay_depth", "INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "request_record", "mutation_summary", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "finding", "dedup_classification", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "finding", "potential_duplicate_of", "INTEGER")
    conn.executescript(_CREATE_CAPABILITIES_V10)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_call_invocation "
        "ON tool_call(invocation_id) WHERE invocation_id<>''"
    )


def _migration_v2(conn: sqlite3.Connection) -> None:
    """v1 -> v2: approval audit fields, finding linkage, and new entity tables."""
    # approval audit columns (program/method/params/expiry/consumption/approver).
    _add_column(conn, "approval", "program", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "approval", "method", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "approval", "params_hash", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "approval", "expires_at", "TEXT")
    _add_column(conn, "approval", "used_at", "TEXT")
    _add_column(conn, "approval", "approved_by", "TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "approval", "session_id", "INTEGER")
    # finding linkage.
    _add_column(conn, "finding", "lead_id", "INTEGER")
    _add_column(conn, "finding", "hypothesis_id", "INTEGER")
    _add_column(conn, "finding", "test_ids", "TEXT NOT NULL DEFAULT '[]'")
    # new entity tables.
    conn.executescript(_CREATE_VALIDATION_REVIEW)
    conn.executescript(_CREATE_AUTH_CONTEXT)
    conn.executescript(_CREATE_RATE_LIMIT)
    conn.executescript(_CREATE_REQUEST_RECORD)


# Version -> migration function.  v1 is the idempotent baseline schema above.
_MIGRATIONS: dict[int, object] = {
    2: _migration_v2,
    3: _migration_v3,
    4: _migration_v4,
    5: _migration_v5,
    6: _migration_v6,
    7: _migration_v7,
    8: _migration_v8,
    9: _migration_v9,
    10: _migration_v10,
}


class HuntDB:
    def __init__(self, db_path: Path | str, program_slug: str | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.program_slug = program_slug
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ #
    # schema / program binding
    # ------------------------------------------------------------------ #
    def _migrate(self) -> None:
        with self._lock:
            # v1 baseline is always applied idempotently (CREATE IF NOT EXISTS).
            self._conn.executescript(_BASELINE_SCHEMA)
            # Program binding invariant.
            if self.program_slug:
                row = self._conn.execute("SELECT value FROM meta WHERE key='program_slug'").fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO meta(key,value) VALUES('program_slug',?)", (self.program_slug,)
                    )
                elif row["value"] != self.program_slug:
                    raise StateError(
                        f"state DB {self.db_path} is bound to program {row['value']!r}, "
                        f"not {self.program_slug!r}"
                    )
            # Versioned migrations (from current user_version up to latest).
            cur = self._conn.execute("PRAGMA user_version").fetchone()
            current = int(cur[0]) if cur else 0
            current = max(current, 1)  # baseline is v1
            for version in range(current + 1, STATE_SCHEMA_VERSION + 1):
                fn = _MIGRATIONS.get(version)
                if fn is None:
                    raise StateError(f"no migration registered for schema v{version}")
                fn(self._conn)
                # PRAGMA does not accept bound parameters; integer is a safe literal.
                self._conn.execute(f"PRAGMA user_version = {int(version)}")
            self._conn.execute(f"PRAGMA user_version = {int(STATE_SCHEMA_VERSION)}")
            self._conn.commit()

    @staticmethod
    def public_id(entity: str, rowid: int) -> str:
        return f"{PUBLIC_ID_PREFIX[entity]}-{rowid:03d}"

    # ------------------------------------------------------------------ #
    # sessions (immutable program binding)
    # ------------------------------------------------------------------ #
    def start_session(
        self, runtime: str, agent_role: str, program_slug: str, active_lead_id: int | None = None
    ) -> SessionRecord:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO session(runtime,agent_role,program_slug,started_at,status,active_lead_id) "
                "VALUES(?,?,?,?,?,?)",
                (runtime, agent_role, program_slug, utcnow(), SESSION_RUNNING, active_lead_id),
            )
            self._conn.commit()
            return self.get_session(cur.lastrowid)

    def end_session(self, session_id: int) -> SessionRecord:
        self._transition("session", session_id, SESSION_ENDED)
        with self._lock:
            self._conn.execute(
                "UPDATE session SET status=?, ended_at=? WHERE id=?",
                (SESSION_ENDED, utcnow(), session_id),
            )
            self._conn.commit()
        return self.get_session(session_id)

    def get_session(self, session_id: int) -> SessionRecord:
        row = self._fetch("session", session_id)
        return SessionRecord(
            id=row["id"], public_id=self.public_id("session", row["id"]),
            runtime=row["runtime"], agent_role=row["agent_role"],
            program_slug=row["program_slug"], started_at=row["started_at"],
            ended_at=row["ended_at"], status=row["status"], active_lead_id=row["active_lead_id"],
        )

    def latest_session(self) -> SessionRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM session ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return self.get_session(row["id"]) if row else None

    def require_session(
        self, session_id: int, *, program_slug: str | None = None,
        role: str | None = None, running: bool = False,
    ) -> SessionRecord:
        session = self.get_session(session_id)
        expected_program = program_slug or self.program_slug
        if expected_program and session.program_slug != expected_program:
            raise StateError(
                f"session {session.public_id} belongs to {session.program_slug!r}, not {expected_program!r}"
            )
        if role and session.agent_role != role:
            raise StateError(
                f"session {session.public_id} role {session.agent_role!r} cannot act as {role!r}"
            )
        if running and session.status != SESSION_RUNNING:
            raise StateError(f"session {session.public_id} is not running")
        return session

    def set_active_lead(self, session_id: int, lead_id: int | None) -> None:
        with self._lock:
            self._conn.execute("UPDATE session SET active_lead_id=? WHERE id=?", (lead_id, session_id))
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # leads
    # ------------------------------------------------------------------ #
    def add_lead(
        self, title: str, entity: str = "", source: str = "manual",
        priority: str = "medium", rationale: str = "",
    ) -> LeadRecord:
        now = utcnow()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO lead(title,entity,source,status,priority,rationale,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (title, entity, source, LEAD_OPEN, priority, rationale, now, now),
            )
            self._conn.commit()
            return self.get_lead(cur.lastrowid)

    def get_lead(self, lead_id: int) -> LeadRecord:
        row = self._fetch("lead", lead_id)
        return LeadRecord(
            id=row["id"], public_id=self.public_id("lead", row["id"]),
            title=row["title"], entity=row["entity"], source=row["source"],
            status=row["status"], priority=row["priority"], rationale=row["rationale"],
            claimed_session=row["claimed_session"], created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_leads(self, status: str | None = None) -> list[LeadRecord]:
        q = "SELECT id FROM lead"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self.get_lead(r["id"]) for r in rows]

    def claim_lead(self, lead_id: int, session_id: int) -> LeadRecord:
        self._transition("lead", lead_id, "claimed")
        with self._lock:
            self._conn.execute(
                "UPDATE lead SET status='claimed', claimed_session=?, updated_at=? WHERE id=?",
                (str(session_id), utcnow(), lead_id),
            )
            self._conn.commit()
        run = self.active_autonomy_run(session_id)
        if run is not None:
            self.record_autonomy_activity(
                run.id, session_id, "LEAD_VISITED", "lead", lead_id,
            )
        return self.get_lead(lead_id)

    def release_lead(self, lead_id: int) -> LeadRecord:
        claimed = self.get_lead(lead_id).claimed_session
        self._transition("lead", lead_id, "open")
        with self._lock:
            self._conn.execute(
                "UPDATE lead SET status='open', claimed_session=NULL, updated_at=? WHERE id=?",
                (utcnow(), lead_id),
            )
            self._conn.commit()
        if claimed and claimed.isdigit():
            run = self.active_autonomy_run(int(claimed))
            if run is not None:
                self.record_autonomy_activity(
                    run.id, int(claimed), "LEAD_RELEASED", "lead", lead_id,
                )
        return self.get_lead(lead_id)

    def close_lead(self, lead_id: int) -> LeadRecord:
        self._transition("lead", lead_id, "closed")
        with self._lock:
            self._conn.execute(
                "UPDATE lead SET status='closed', updated_at=? WHERE id=?", (utcnow(), lead_id)
            )
            self._conn.commit()
        return self.get_lead(lead_id)

    def reopen_lead_for_recon_change(self, lead_id: int, recon_change_id: int) -> LeadRecord:
        """Requeue a closed Lead only with durable ReconChange provenance."""
        self._fetch("recon_change", recon_change_id)
        lead = self.get_lead(lead_id)
        if lead.status == "closed":
            self._transition("lead", lead_id, "open")
            with self._lock:
                self._conn.execute(
                    "UPDATE lead SET status='open',claimed_session=NULL,updated_at=? WHERE id=?",
                    (utcnow(), lead_id),
                )
                self._conn.commit()
        self.link_lead_recon_change(lead_id, recon_change_id)
        return self.get_lead(lead_id)

    def update_lead(self, lead_id: int, **fields) -> LeadRecord:
        self._update_fields("lead", lead_id, fields)
        return self.get_lead(lead_id)

    # ------------------------------------------------------------------ #
    # hypotheses
    # ------------------------------------------------------------------ #
    def create_hypothesis(
        self, statement: str, rationale: str = "", lead_id: int | None = None,
        confidence: float | None = None, autonomy_run_id: int | None = None,
    ) -> HypothesisRecord:
        if lead_id is not None:
            self.get_lead(lead_id)
        now = utcnow()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO hypothesis(lead_id,statement,rationale,confidence,status,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (lead_id, statement, rationale, confidence, HYPO_OPEN, now, now),
            )
            self._conn.commit()
            hypothesis = self.get_hypothesis(cur.lastrowid)
        if autonomy_run_id is not None:
            run = self.get_autonomy_run(autonomy_run_id)
            self.record_autonomy_activity(
                run.id, run.session_id, "HYPOTHESIS_CREATED", "hypothesis",
                hypothesis.id, {"lead_id": lead_id},
            )
        return hypothesis

    def get_hypothesis(self, hypothesis_id: int) -> HypothesisRecord:
        row = self._fetch("hypothesis", hypothesis_id)
        return HypothesisRecord(
            id=row["id"], public_id=self.public_id("hypothesis", row["id"]),
            statement=row["statement"], rationale=row["rationale"],
            status=row["status"], created_at=row["created_at"], updated_at=row["updated_at"],
            lead_id=row["lead_id"], confidence=row["confidence"],
        )

    def list_hypotheses(self, lead_id: int | None = None, status: str | None = None) -> list[HypothesisRecord]:
        q = "SELECT id FROM hypothesis"
        conds, args = [], []
        if lead_id is not None:
            conds.append("lead_id=?")
            args.append(lead_id)
        if status:
            conds.append("status=?")
            args.append(status)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, tuple(args)).fetchall()
        return [self.get_hypothesis(r["id"]) for r in rows]

    def set_hypothesis_status(self, hypothesis_id: int, status: str) -> HypothesisRecord:
        self._transition("hypothesis", hypothesis_id, status)
        with self._lock:
            self._conn.execute(
                "UPDATE hypothesis SET status=?, updated_at=? WHERE id=?", (status, utcnow(), hypothesis_id)
            )
            self._conn.commit()
        return self.get_hypothesis(hypothesis_id)

    def update_hypothesis(self, hypothesis_id: int, **fields) -> HypothesisRecord:
        self._update_fields("hypothesis", hypothesis_id, fields)
        return self.get_hypothesis(hypothesis_id)

    # ------------------------------------------------------------------ #
    # research tests
    # ------------------------------------------------------------------ #
    def add_test(
        self, hypothesis_id: int, objective: str, method: str = "",
        baseline_ref: str = "", controlled_change: str = "",
        expected_if_true: str = "", expected_if_false: str = "",
        autonomy_run_id: int | None = None,
    ) -> ResearchTestRecord:
        self.get_hypothesis(hypothesis_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO research_test(hypothesis_id,objective,method,status,baseline_ref,"
                "controlled_change,expected_if_true,expected_if_false,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (hypothesis_id, objective, method, TEST_PLANNED, baseline_ref,
                 controlled_change, expected_if_true, expected_if_false, utcnow()),
            )
            self._conn.commit()
            test = self.get_test(cur.lastrowid)
        if autonomy_run_id is not None:
            run = self.get_autonomy_run(autonomy_run_id)
            self.record_autonomy_activity(
                run.id, run.session_id, "TEST_CREATED", "research_test",
                test.id, {"hypothesis_id": hypothesis_id},
            )
        return test

    def get_test(self, test_id: int) -> ResearchTestRecord:
        row = self._fetch("research_test", test_id)
        return ResearchTestRecord(
            id=row["id"], public_id=self.public_id("research_test", row["id"]),
            hypothesis_id=row["hypothesis_id"], objective=row["objective"],
            method=row["method"], status=row["status"], created_at=row["created_at"],
            baseline_ref=row["baseline_ref"], controlled_change=row["controlled_change"],
            expected_if_true=row["expected_if_true"], expected_if_false=row["expected_if_false"],
            observation=row["observation"], result=row["result"],
            evidence_refs=_jload(row["evidence_refs"], []), completed_at=row["completed_at"],
        )

    def list_tests(self, hypothesis_id: int | None = None) -> list[ResearchTestRecord]:
        q = "SELECT id FROM research_test WHERE status='executed' OR 1=1"
        args: tuple = ()
        if hypothesis_id is not None:
            q = "SELECT id FROM research_test WHERE hypothesis_id=?"
            args = (hypothesis_id,)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self.get_test(r["id"]) for r in rows]

    def complete_test(
        self, test_id: int, observation: str, result: str,
        evidence_refs: list[str] | None = None, autonomy_run_id: int | None = None,
    ) -> ResearchTestRecord:
        self._transition("research_test", test_id, TEST_EXECUTED)
        refs = evidence_refs or []
        self._require_evidence_refs(refs)
        with self._lock:
            self._conn.execute(
                "UPDATE research_test SET status=?, observation=?, result=?, evidence_refs=?, completed_at=? "
                "WHERE id=?",
                (TEST_EXECUTED, observation, result, _jdump(refs), utcnow(), test_id),
            )
            self._conn.commit()
        test = self.get_test(test_id)
        if autonomy_run_id is not None:
            run = self.get_autonomy_run(autonomy_run_id)
            self.record_autonomy_activity(
                run.id, run.session_id, "TEST_EXECUTED", "research_test", test.id,
                {"hypothesis_id": test.hypothesis_id, "result": result},
            )
        return test

    # ------------------------------------------------------------------ #
    # evidence
    # ------------------------------------------------------------------ #
    def add_evidence(self, kind: str, ref: str, description: str = "", preview: str = "") -> EvidenceRecord:
        from ..redact import redact_text
        from .constants import EVIDENCE_KINDS

        if kind not in EVIDENCE_KINDS:
            raise StateError(f"invalid evidence kind: {kind!r}")
        description = redact_text(description)
        preview = redact_text(preview)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO evidence(kind,ref,description,preview,created_at) VALUES(?,?,?,?,?)",
                (kind, ref, description, preview, utcnow()),
            )
            self._conn.commit()
            return self.get_evidence(cur.lastrowid)

    def get_evidence(self, evidence_id: int) -> EvidenceRecord:
        row = self._fetch("evidence", evidence_id)
        return EvidenceRecord(
            id=row["id"], public_id=self.public_id("evidence", row["id"]),
            kind=row["kind"], ref=row["ref"], description=row["description"],
            preview=row["preview"], created_at=row["created_at"],
        )

    def list_evidence(self) -> list[EvidenceRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM evidence ORDER BY id DESC").fetchall()
        return [self.get_evidence(r["id"]) for r in rows]

    def set_evidence_ref(self, evidence_id: int, ref: str) -> EvidenceRecord:
        with self._lock:
            self._conn.execute("UPDATE evidence SET ref=? WHERE id=?", (ref, evidence_id))
            self._conn.commit()
        return self.get_evidence(evidence_id)

    # ------------------------------------------------------------------ #
    # findings
    # ------------------------------------------------------------------ #
    def create_finding(
        self, title: str, affected_target: str = "", category: str = "",
        impact_summary: str = "", evidence_refs: list[str] | None = None,
        lead_id: int | None = None, hypothesis_id: int | None = None,
        test_ids: list[int] | None = None, creator_session_id: int | None = None,
    ) -> FindingRecord:
        now = utcnow()
        refs = evidence_refs or []
        tests = test_ids or []
        linkage_state = self._validate_finding_links(
            lead_id=lead_id, hypothesis_id=hypothesis_id, test_ids=tests,
            evidence_refs=refs, require_complete=False,
        )
        if creator_session_id is not None:
            self.require_session(creator_session_id, running=False)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO finding(title,affected_target,category,status,impact_summary,"
                "evidence_refs,lead_id,hypothesis_id,test_ids,creator_session_id,linkage_state,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (title, affected_target, category, FINDING_CANDIDATE, impact_summary,
                 _jdump(refs), lead_id, hypothesis_id, _jdump(tests), creator_session_id,
                 linkage_state, now, now),
            )
            self._conn.commit()
            finding = self.get_finding(cur.lastrowid)
        if creator_session_id is not None:
            run = self.active_autonomy_run(creator_session_id)
            if run is not None:
                self.record_autonomy_activity(
                    run.id, creator_session_id, "FINDING_CREATED", "finding", finding.id,
                    {"hypothesis_id": hypothesis_id, "lead_id": lead_id},
                )
        from ..dedup import FindingDeduplicator
        FindingDeduplicator(self).register(
            finding.id, category=category, target=affected_target,
            impact=impact_summary,
        )
        finding = self.get_finding(finding.id)
        return finding

    def get_finding(self, finding_id: int) -> FindingRecord:
        row = self._fetch("finding", finding_id)
        return FindingRecord(
            id=row["id"], public_id=self.public_id("finding", row["id"]),
            title=row["title"], affected_target=row["affected_target"],
            category=row["category"], status=row["status"],
            impact_summary=row["impact_summary"], created_at=row["created_at"],
            updated_at=row["updated_at"], validation_state=row["validation_state"],
            evidence_refs=_jload(row["evidence_refs"], []),
            cvss_data=_jload(row["cvss_data"], None),
            report_path=row["report_path"],
            lead_id=row["lead_id"], hypothesis_id=row["hypothesis_id"],
            test_ids=_jload(row["test_ids"], []),
            creator_session_id=row["creator_session_id"], linkage_state=row["linkage_state"],
            poc_path=row["poc_path"],
            dedup_classification=row["dedup_classification"],
            potential_duplicate_of=row["potential_duplicate_of"],
        )

    def list_findings(self, status: str | None = None) -> list[FindingRecord]:
        q = "SELECT id FROM finding"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self.get_finding(r["id"]) for r in rows]

    def transition_finding(self, finding_id: int, new_status: str, validation_state: str | None = None) -> FindingRecord:
        if new_status == FINDING_VALIDATED:
            raise StateError("validated is reachable only through finalize_validation()")
        self._transition("finding", finding_id, new_status)
        with self._lock:
            if validation_state is not None:
                self._conn.execute(
                    "UPDATE finding SET status=?, validation_state=?, updated_at=? WHERE id=?",
                    (new_status, validation_state, utcnow(), finding_id),
                )
            else:
                self._conn.execute(
                    "UPDATE finding SET status=?, updated_at=? WHERE id=?", (new_status, utcnow(), finding_id)
                )
            self._conn.commit()
        return self.get_finding(finding_id)

    def set_finding_cvss(self, finding_id: int, cvss_data: dict) -> FindingRecord:
        with self._lock:
            self._conn.execute(
                "UPDATE finding SET cvss_data=?, updated_at=? WHERE id=?",
                (_jdump(cvss_data), utcnow(), finding_id),
            )
            self._conn.commit()
        return self.get_finding(finding_id)

    def set_finding_report_path(self, finding_id: int, report_path: str) -> FindingRecord:
        with self._lock:
            self._conn.execute(
                "UPDATE finding SET report_path=?, updated_at=? WHERE id=?", (report_path, utcnow(), finding_id)
            )
            self._conn.commit()
        return self.get_finding(finding_id)

    def set_finding_poc_path(self, finding_id: int, poc_path: str) -> FindingRecord:
        with self._lock:
            self._conn.execute(
                "UPDATE finding SET poc_path=?, updated_at=? WHERE id=?", (poc_path, utcnow(), finding_id)
            )
            self._conn.commit()
        return self.get_finding(finding_id)

    def update_finding(self, finding_id: int, **fields) -> FindingRecord:
        allowed = {
            "title", "affected_target", "category", "impact_summary", "evidence_refs",
            "report_path", "lead_id", "hypothesis_id", "test_ids",
        }
        clean = {k: v for k, v in fields.items() if k in allowed}
        current = self.get_finding(finding_id)
        candidate = {
            "lead_id": fields.get("lead_id", current.lead_id),
            "hypothesis_id": fields.get("hypothesis_id", current.hypothesis_id),
            "test_ids": fields.get("test_ids", current.test_ids),
            "evidence_refs": fields.get("evidence_refs", current.evidence_refs),
        }
        clean["linkage_state"] = self._validate_finding_links(**candidate, require_complete=False)
        for list_col in ("evidence_refs", "test_ids"):
            if list_col in clean:
                clean[list_col] = _jdump(clean[list_col])
        self._update_fields("finding", finding_id, clean)
        return self.get_finding(finding_id)

    # ------------------------------------------------------------------ #
    # checkpoints
    # ------------------------------------------------------------------ #
    def save_checkpoint(
        self, active_lead_id: int | None = None, active_hypotheses: list[int] | None = None,
        completed_tests: list[int] | None = None, pending_tests: list[int] | None = None,
        recent_observations: list[str] | None = None, evidence_refs: list[str] | None = None,
        next_action: str = "", session_id: int | None = None,
        autonomy_state: dict | None = None, pending_approval_id: int | None = None,
    ) -> CheckpointRecord:
        if session_id is not None:
            self.require_session(session_id)
        if active_lead_id is not None:
            self.get_lead(active_lead_id)
        for hid in active_hypotheses or []:
            self.get_hypothesis(hid)
        for tid in (completed_tests or []) + (pending_tests or []):
            self.get_test(tid)
        self._require_evidence_refs(evidence_refs or [])
        if pending_approval_id is not None:
            self.get_approval(pending_approval_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO checkpoint(active_lead_id,active_hypotheses,completed_tests,pending_tests,"
                "recent_observations,evidence_refs,next_action,session_id,autonomy_state,"
                "pending_approval_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    active_lead_id,
                    _jdump(active_hypotheses or []),
                    _jdump(completed_tests or []),
                    _jdump(pending_tests or []),
                    _jdump(recent_observations or []),
                    _jdump(evidence_refs or []),
                    next_action,
                    session_id,
                    _jdump(autonomy_state or {}),
                    pending_approval_id,
                    utcnow(),
                ),
            )
            self._conn.commit()
            return self.get_checkpoint(cur.lastrowid)

    def get_checkpoint(self, checkpoint_id: int) -> CheckpointRecord:
        row = self._fetch("checkpoint", checkpoint_id)
        return CheckpointRecord(
            id=row["id"], public_id=self.public_id("checkpoint", row["id"]),
            created_at=row["created_at"], active_lead_id=row["active_lead_id"],
            active_hypotheses=_jload(row["active_hypotheses"], []),
            completed_tests=_jload(row["completed_tests"], []),
            pending_tests=_jload(row["pending_tests"], []),
            recent_observations=_jload(row["recent_observations"], []),
            evidence_refs=_jload(row["evidence_refs"], []),
            next_action=row["next_action"],
            session_id=row["session_id"], autonomy_state=_jload(row["autonomy_state"], {}),
            pending_approval_id=row["pending_approval_id"],
        )

    def latest_checkpoint(self) -> CheckpointRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT id FROM checkpoint ORDER BY id DESC LIMIT 1").fetchone()
        return self.get_checkpoint(row["id"]) if row else None

    # ------------------------------------------------------------------ #
    # agent actions (no secrets)
    # ------------------------------------------------------------------ #
    def record_action(
        self, agent_role: str, action: str, program: str, target: str = "",
        decision: str = "", result_summary: str = "", session_id: int | None = None,
    ) -> AgentActionRecord:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO agent_action(session_id,agent_role,action,program,target,decision,result_summary,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (session_id, agent_role, action, program, target, decision, result_summary, utcnow()),
            )
            self._conn.commit()
            row = self._fetch("agent_action", cur.lastrowid)
        return AgentActionRecord(
            id=row["id"], public_id=self.public_id("agent_action", row["id"]),
            session_id=row["session_id"], agent_role=row["agent_role"], action=row["action"],
            program=row["program"], target=row["target"], decision=row["decision"],
            result_summary=row["result_summary"], created_at=row["created_at"],
        )

    def list_actions(self, limit: int = 50) -> list[AgentActionRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM agent_action ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            row = self._fetch("agent_action", r["id"])
            out.append(AgentActionRecord(
                id=row["id"], public_id=self.public_id("agent_action", row["id"]),
                session_id=row["session_id"], agent_role=row["agent_role"], action=row["action"],
                program=row["program"], target=row["target"], decision=row["decision"],
                result_summary=row["result_summary"], created_at=row["created_at"],
            ))
        return out

    # ------------------------------------------------------------------ #
    # approvals
    # ------------------------------------------------------------------ #
    def request_approval(
        self, action: str, target: str = "", requested_by: str = "", note: str = "",
        program: str = "", method: str = "", params_hash: str = "",
        expires_at: str | None = None, session_id: int | None = None,
        auth_context: str = "", constraints: dict | None = None,
        autonomy_run_id: int | None = None,
    ) -> ApprovalRecord:
        if session_id is not None:
            session = self.require_session(session_id)
            if session.agent_role in {"human", "approval-authority"}:
                raise StateError("approval requester cannot be its own approval authority")
        constraints = constraints or {"max_requests": 1}
        max_requests = constraints.get("max_requests", 1)
        if not isinstance(max_requests, int) or max_requests < 1:
            raise StateError("approval constraints.max_requests must be a positive integer")
        for name in ("max_concurrency", "duration_seconds"):
            if name in constraints and (
                not isinstance(constraints[name], int) or constraints[name] < 1
            ):
                raise StateError(f"approval constraints.{name} must be a positive integer")
        if autonomy_run_id is None and session_id is not None:
            active = self.active_autonomy_run(session_id)
            autonomy_run_id = active.id if active is not None else None
        if autonomy_run_id is not None:
            bound = self.get_autonomy_run(autonomy_run_id)
            if session_id is None or bound.session_id != session_id:
                raise StateError("approval autonomy run must belong to the requesting session")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO approval(action,target,status,requested_by,requested_at,note,"
                "program,method,params_hash,expires_at,session_id,auth_context,constraints,autonomy_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (action, target, APPROVAL_PENDING, requested_by, utcnow(), note,
                 program, method, params_hash, expires_at, session_id, auth_context,
                 _jdump(constraints), autonomy_run_id),
            )
            self._conn.commit()
            approval = self.get_approval(cur.lastrowid)
        if session_id is not None:
            run = self.active_autonomy_run(session_id)
            if run is not None:
                self.record_autonomy_activity(
                    run.id, session_id, "APPROVAL_REQUESTED", "approval", approval.id,
                    {"action": action},
                )
        return approval

    def get_approval(self, approval_id: int) -> ApprovalRecord:
        row = self._fetch("approval", approval_id)
        return ApprovalRecord(
            id=row["id"], public_id=self.public_id("approval", row["id"]),
            action=row["action"], target=row["target"], status=row["status"],
            requested_by=row["requested_by"], requested_at=row["requested_at"],
            note=row["note"], decided_at=row["decided_at"],
            program=row["program"], method=row["method"], params_hash=row["params_hash"],
            expires_at=row["expires_at"], used_at=row["used_at"],
            approved_by=row["approved_by"], session_id=row["session_id"],
            auth_context=row["auth_context"], constraints=_jload(row["constraints"], {}),
            usage_count=row["usage_count"],
            autonomy_run_id=row["autonomy_run_id"],
        )

    def list_approvals(
        self, status: str | None = None, *, session_id: int | None = None,
        autonomy_run_id: int | None = None, include_legacy_unscoped: bool = True,
    ) -> list[ApprovalRecord]:
        q = "SELECT id FROM approval"
        where: list[str] = []
        args: list[object] = []
        if status:
            where.append("status=?"); args.append(status)
        if autonomy_run_id is not None:
            where.append("autonomy_run_id=?"); args.append(autonomy_run_id)
        elif session_id is not None:
            where.append("session_id=?"); args.append(session_id)
        if not include_legacy_unscoped and (session_id is not None or autonomy_run_id is not None):
            where.append("session_id IS NOT NULL")
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, tuple(args)).fetchall()
        return [self.get_approval(r["id"]) for r in rows]

    def list_pending_approvals(
        self, *, session_id: int | None = None, autonomy_run_id: int | None = None,
        include_legacy_unscoped: bool = True,
    ) -> list[ApprovalRecord]:
        return self.list_approvals(
            status=APPROVAL_PENDING, session_id=session_id,
            autonomy_run_id=autonomy_run_id,
            include_legacy_unscoped=include_legacy_unscoped,
        )

    def decide_approval(self, approval_id: int, status: str, decided_by: str = "") -> ApprovalRecord:
        if not decided_by or decided_by in {"agent", "mcp", "orchestrator", "researcher"}:
            raise StateError("ASK actions may be approved/rejected only by an explicit human authority")
        self._transition("approval", approval_id, status)
        with self._lock:
            self._conn.execute(
                "UPDATE approval SET status=?, decided_at=?, approved_by=? WHERE id=?",
                (status, utcnow(), decided_by, approval_id),
            )
            self._conn.commit()
        return self.get_approval(approval_id)

    def approve_approval(self, approval_id: int, approved_by: str = "") -> ApprovalRecord:
        return self.decide_approval(approval_id, APPROVAL_APPROVED, decided_by=approved_by or "human")

    def reject_approval(self, approval_id: int, decided_by: str = "") -> ApprovalRecord:
        return self.decide_approval(approval_id, APPROVAL_REJECTED, decided_by=decided_by or "human")

    def expire_approval(self, approval_id: int) -> ApprovalRecord:
        return self.decide_approval(approval_id, APPROVAL_EXPIRED, decided_by="system")

    def consume_approval(self, approval_id: int) -> ApprovalRecord:
        """Mark an approved approval as used exactly once (approved -> consumed)."""
        self._transition("approval", approval_id, APPROVAL_CONSUMED)
        with self._lock:
            self._conn.execute(
                "UPDATE approval SET status=?, used_at=? WHERE id=?",
                (APPROVAL_CONSUMED, utcnow(), approval_id),
            )
            self._conn.commit()
        return self.get_approval(approval_id)

    def record_approval_use(self, approval_id: int) -> ApprovalRecord:
        """Atomically reserve one unit from a bounded approved action plan."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT * FROM approval WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                self._conn.rollback()
                raise StateError(f"approval id={approval_id} not found")
            if row["status"] != APPROVAL_APPROVED:
                self._conn.rollback()
                raise StateError(f"approval {self.public_id('approval', approval_id)} is not approved")
            constraints = _jload(row["constraints"], {})
            now_dt = datetime.now(timezone.utc)
            if row["expires_at"]:
                expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now_dt >= expires:
                    self._conn.rollback()
                    raise StateError("bounded approval is expired")
            start_value = constraints.get("start_at")
            if start_value:
                starts = datetime.fromisoformat(str(start_value).replace("Z", "+00:00"))
                if starts.tzinfo is None:
                    starts = starts.replace(tzinfo=timezone.utc)
                if now_dt < starts:
                    self._conn.rollback()
                    raise StateError("bounded approval has not started")
            duration = int(constraints.get("duration_seconds", 0) or 0)
            if duration:
                anchor_value = row["decided_at"] or row["requested_at"]
                anchor = datetime.fromisoformat(anchor_value.replace("Z", "+00:00"))
                if anchor.tzinfo is None:
                    anchor = anchor.replace(tzinfo=timezone.utc)
                if now_dt >= anchor + timedelta(seconds=duration):
                    self._conn.rollback()
                    raise StateError("bounded approval duration is exhausted")
            max_requests = int(constraints.get("max_requests", 1))
            used = int(row["usage_count"]) + 1
            if used > max_requests:
                self._conn.rollback()
                raise StateError("bounded approval request budget is exhausted")
            if used >= max_requests:
                self._conn.execute(
                    "UPDATE approval SET usage_count=?, status=?, used_at=? WHERE id=?",
                    (used, APPROVAL_CONSUMED, utcnow(), approval_id),
                )
            else:
                self._conn.execute("UPDATE approval SET usage_count=? WHERE id=?", (used, approval_id))
            self._conn.commit()
        return self.get_approval(approval_id)

    def find_valid_approval(
        self, action: str, target: str = "", program: str = "",
        method: str = "", params_hash: str = "", auth_context: str = "",
    ) -> ApprovalRecord | None:
        """Return the newest unexpired, unconsumed *approved* approval matching
        the request, or None if no usable approval exists."""
        conds = ["status=?", "action=?"]
        args: list = [APPROVAL_APPROVED, action]
        if program:
            conds.append("program=?")
            args.append(program)
        if method:
            conds.append("method=?")
            args.append(method)
        if params_hash:
            conds.append("params_hash=?")
            args.append(params_hash)
        if target:
            conds.append("target=?")
            args.append(target)
        # The security principal is always part of approval identity, including
        # the explicit unauthenticated principal represented by an empty string.
        conds.append("auth_context=?")
        args.append(auth_context)
        q = f"SELECT id FROM approval WHERE {' AND '.join(conds)} ORDER BY id DESC"
        now = utcnow()
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        for r in rows:
            rec = self.get_approval(r["id"])
            if rec.expires_at and rec.expires_at <= now:
                continue  # lapsed
            duration = int(rec.constraints.get("duration_seconds", 0) or 0)
            if duration:
                start_at = rec.decided_at or rec.requested_at
                started = datetime.fromisoformat(start_at.replace("Z", "+00:00"))
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > started + timedelta(seconds=duration):
                    continue
            if rec.usage_count >= int(rec.constraints.get("max_requests", 1)):
                continue
            return rec
        return None

    # ------------------------------------------------------------------ #
    # validation reviews (finding validation provenance)
    # ------------------------------------------------------------------ #
    def begin_validation(
        self, finding_id: int, requested_by: str = "", reviewer_type: str = "finding-validator",
    ) -> ValidationReviewRecord:
        finding = self.get_finding(finding_id)
        self._validate_finding_links(
            lead_id=finding.lead_id, hypothesis_id=finding.hypothesis_id,
            test_ids=finding.test_ids, evidence_refs=finding.evidence_refs,
            require_complete=True,
        )
        if reviewer_type != "finding-validator":
            raise StateError("validation reviews must be assigned to role 'finding-validator'")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO validation_review(finding_id,verdict,status,requested_by,reviewer_type,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (finding_id, VR_INCONCLUSIVE, VREVIEW_OPEN, requested_by, reviewer_type, utcnow()),
            )
            self._conn.commit()
            return self.get_validation_review(cur.lastrowid)

    def get_validation_review(self, review_id: int) -> ValidationReviewRecord:
        row = self._fetch("validation_review", review_id)
        return self._vreview_from_row(row)

    def list_validation_reviews(self, finding_id: int | None = None) -> list[ValidationReviewRecord]:
        q = "SELECT id FROM validation_review"
        args: tuple = ()
        if finding_id is not None:
            q += " WHERE finding_id=?"
            args = (finding_id,)
        q += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self.get_validation_review(r["id"]) for r in rows]

    def latest_validation_review(self, finding_id: int) -> ValidationReviewRecord | None:
        revs = self.list_validation_reviews(finding_id=finding_id)
        return revs[0] if revs else None

    def submit_validation_review(
        self, review_id: int, verdict: str, reasoning_summary: str = "",
        reviewer_runtime: str = "", reviewer_session: str = "",
        check_results: dict | None = None, evidence_refs: list[str] | None = None,
        reviewer_role: str = "", reviewer_session_id: int | None = None,
    ) -> ValidationReviewRecord:
        if verdict not in (VR_SUPPORTED, VR_REJECTED, VR_INCONCLUSIVE):
            raise StateError(f"invalid validation verdict: {verdict!r}")
        # validation_review statuses are enforced locally (open -> submitted).
        current = self._current_status("validation_review", review_id)
        if current != VREVIEW_OPEN:
            raise StateError(f"validation review {review_id} is already {current!r}")
        review = self.get_validation_review(review_id)
        finding = self.get_finding(review.finding_id)
        if reviewer_role != "finding-validator" or reviewer_session_id is None:
            raise StateError("a finding-validator session is required to submit a validation review")
        session = self.require_session(reviewer_session_id, role="finding-validator")
        if finding.creator_session_id is None:
            raise StateError("legacy finding lacks creator-session provenance and cannot be validated")
        if session.id == finding.creator_session_id:
            raise StateError("finding creator session cannot validate its own finding")
        self._validate_review_payload(
            verdict=verdict, checks=check_results or {}, evidence_refs=evidence_refs or [],
            finding=finding,
        )
        with self._lock:
            self._conn.execute(
                "UPDATE validation_review SET verdict=?, status=?, reasoning_summary=?, "
                "reviewer_runtime=?, reviewer_session=?, check_results=?, evidence_refs=?,"
                "reviewer_role=?, reviewer_session_id=? WHERE id=?",
                (verdict, VREVIEW_SUBMITTED, reasoning_summary, reviewer_runtime, reviewer_session,
                 _jdump(check_results or {}), _jdump(evidence_refs or []), reviewer_role,
                 reviewer_session_id, review_id),
            )
            self._conn.commit()
        return self.get_validation_review(review_id)

    def finalize_validation(self, finding_id: int, *, scope_engine, program_active: bool) -> FindingRecord:
        """Apply the finding's submitted review verdict to its pipeline status.

        Only the finding's *own* submitted reviews are consulted (P0.8 linkage).
        ``supported`` -> validation -> validated; ``rejected`` -> validation -> killed;
        ``inconclusive`` leaves the finding in ``validation``.
        """
        finding = self.get_finding(finding_id)
        if finding.status != FINDING_VALIDATION:
            raise StateError(
                f"finding {finding_id} must be in 'validation' to finalize (is {finding.status!r})"
            )
        revs = [
            r for r in self.list_validation_reviews(finding_id=finding_id)
            if r.status == VREVIEW_SUBMITTED
        ]
        if not revs:
            raise StateError(f"finding {finding_id} has no submitted validation review")
        review = revs[0]
        verdict = review.verdict
        if verdict == VR_SUPPORTED:
            if not program_active:
                raise StateError("program is not active at validation finalization")
            scope_target = re.sub(
                r"^\s*(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+(?=https?://)",
                "", finding.affected_target, flags=re.IGNORECASE,
            )
            if not scope_target or not scope_engine.check(scope_target).allowed:
                raise StateError("finding asset is no longer in scope")
            self._validate_finding_links(
                lead_id=finding.lead_id, hypothesis_id=finding.hypothesis_id,
                test_ids=finding.test_ids, evidence_refs=finding.evidence_refs,
                require_complete=True,
            )
            self._validate_review_payload(
                verdict=review.verdict, checks=review.check_results,
                evidence_refs=review.evidence_refs, finding=finding,
            )
            # This is the sole internal path to validation.
            self._transition("finding", finding_id, FINDING_VALIDATED)
            with self._lock:
                self._conn.execute(
                    "UPDATE finding SET status=?, validation_state=?, updated_at=? WHERE id=?",
                    (FINDING_VALIDATED, "independently_supported", utcnow(), finding_id),
                )
                self._conn.commit()
            return self.get_finding(finding_id)
        if verdict == VR_REJECTED:
            return self.transition_finding(finding_id, FINDING_KILLED)
        return finding  # inconclusive: remain in validation

    def _vreview_from_row(self, row: sqlite3.Row) -> ValidationReviewRecord:
        return ValidationReviewRecord(
            id=row["id"], public_id=self.public_id("validation_review", row["id"]),
            finding_id=row["finding_id"], verdict=row["verdict"], status=row["status"],
            created_at=row["created_at"], reviewer_type=row["reviewer_type"],
            reviewer_runtime=row["reviewer_runtime"], reviewer_session=row["reviewer_session"],
            requested_by=row["requested_by"], reasoning_summary=row["reasoning_summary"],
            check_results=_jload(row["check_results"], {}),
            evidence_refs=_jload(row["evidence_refs"], []),
            reviewer_role=row["reviewer_role"], reviewer_session_id=row["reviewer_session_id"],
        )

    # ------------------------------------------------------------------ #
    # auth contexts (no secret values — refs only)
    # ------------------------------------------------------------------ #
    def create_auth_context(
        self, account_id: str, type: str = "header_bundle",
        secret_refs: list[str] | None = None, metadata: dict | None = None,
        enabled: bool = True, role: str = "",
    ) -> AuthContextRecord:
        if type not in {"bearer", "cookie", "header_bundle", "browser_session"}:
            raise StateError(f"unsupported auth context type: {type!r}")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO auth_context(account_id,type,enabled,secret_refs,metadata,role,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (account_id, type, int(enabled), _jdump(secret_refs or []),
                 _jdump(metadata or {}), role, utcnow()),
            )
            self._conn.commit()
            return self.get_auth_context(cur.lastrowid)

    def get_auth_context(self, auth_context_id: int) -> AuthContextRecord:
        row = self._fetch("auth_context", auth_context_id)
        return self._auth_from_row(row)

    def get_auth_context_by_account(self, account_id: str) -> AuthContextRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM auth_context WHERE account_id=?", (account_id,)
            ).fetchone()
        return self.get_auth_context(row["id"]) if row else None

    def list_auth_contexts(self, enabled: bool | None = None) -> list[AuthContextRecord]:
        q = "SELECT id FROM auth_context"
        args: tuple = ()
        if enabled is not None:
            q += " WHERE enabled=?"
            args = (int(enabled),)
        q += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self.get_auth_context(r["id"]) for r in rows]

    def update_auth_context(self, auth_context_id: int, **fields) -> AuthContextRecord:
        allowed = {"account_id", "type", "enabled", "secret_refs", "metadata", "role"}
        clean = {k: v for k, v in fields.items() if k in allowed}
        for list_col in ("secret_refs",):
            if list_col in clean:
                clean[list_col] = _jdump(clean[list_col])
        for dict_col in ("metadata",):
            if dict_col in clean:
                clean[dict_col] = _jdump(clean[dict_col])
        if "enabled" in clean:
            clean["enabled"] = int(clean["enabled"])
        if clean:
            cols = ", ".join(f"{k}=?" for k in clean)
            with self._lock:
                self._conn.execute(
                    f"UPDATE auth_context SET {cols} WHERE id=?",
                    (*clean.values(), auth_context_id),
                )
                self._conn.commit()
        return self.get_auth_context(auth_context_id)

    def _auth_from_row(self, row: sqlite3.Row) -> AuthContextRecord:
        return AuthContextRecord(
            id=row["id"], public_id=self.public_id("auth_context", row["id"]),
            account_id=row["account_id"], type=row["type"],
            enabled=bool(row["enabled"]), secret_refs=_jload(row["secret_refs"], []),
            metadata=_jload(row["metadata"], {}), created_at=row["created_at"],
            role=row["role"],
        )

    # ------------------------------------------------------------------ #
    # request records (structured metadata, not raw bodies)
    # ------------------------------------------------------------------ #
    def record_request(
        self, program: str, method: str, url: str, session_id: int | None = None,
        auth_context: str = "", request_metadata: dict | None = None,
        response_metadata: dict | None = None, burp_ref: str = "",
        body_hash: str = "", evidence_ref: str = "", research_test_id: int | None = None,
        hypothesis_id: int | None = None, controlled_mutation: dict | None = None,
        parent_request_id: int | None = None, root_request_id: int | None = None,
        replay_depth: int = 0, mutation_summary: str = "",
    ) -> RequestRecord:
        run = self.active_autonomy_run(session_id) if session_id is not None else None
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO request_record(program,session_id,auth_context,method,url,"
                "request_metadata,response_metadata,burp_ref,body_hash,evidence_ref,research_test_id,"
                "hypothesis_id,controlled_mutation,autonomy_run_id,parent_request_id,root_request_id,"
                "replay_depth,mutation_summary,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (program, session_id, auth_context, method, url,
                 _jdump(request_metadata or {}), _jdump(response_metadata or {}),
                 burp_ref, body_hash, evidence_ref, research_test_id, hypothesis_id,
                 _jdump(controlled_mutation or {}), run.id if run else None,
                 parent_request_id, root_request_id, replay_depth, mutation_summary, utcnow()),
            )
            self._conn.commit()
            row = self._fetch("request_record", cur.lastrowid)
        record = RequestRecord(
            id=row["id"], public_id=self.public_id("request_record", row["id"]),
            program=row["program"], method=row["method"], url=row["url"],
            created_at=row["created_at"], session_id=row["session_id"],
            auth_context=row["auth_context"], request_metadata=_jload(row["request_metadata"], {}),
            response_metadata=_jload(row["response_metadata"], {}), burp_ref=row["burp_ref"],
            body_hash=row["body_hash"], evidence_ref=row["evidence_ref"],
            research_test_id=row["research_test_id"], hypothesis_id=row["hypothesis_id"],
            controlled_mutation=_jload(row["controlled_mutation"], {}),
            autonomy_run_id=row["autonomy_run_id"],
            parent_request_id=row["parent_request_id"], root_request_id=row["root_request_id"],
            replay_depth=row["replay_depth"], mutation_summary=row["mutation_summary"],
        )
        if run is not None:
            self.record_autonomy_activity(
                run.id, run.session_id, "REQUEST_SENT", "request_record", record.id,
                {"hypothesis_id": hypothesis_id, "research_test_id": research_test_id},
            )
        if research_test_id is not None:
            self._record_request_coverage(record)
        return record

    def _record_request_coverage(self, record: RequestRecord) -> None:
        """Best-effort automatic observed coverage for executed research traffic."""
        from urllib.parse import urlsplit
        from ..recon import normalize_endpoint_path
        parsed = urlsplit(record.url); host = (parsed.hostname or "").lower()
        normalized_path, _ = normalize_endpoint_path(parsed.path or "/")
        with self._lock:
            endpoint = self._conn.execute(
                "SELECT e.id FROM endpoint e JOIN asset a ON a.id=e.host_asset_id "
                "WHERE a.normalized_value=? AND e.method=? AND e.normalized_path=? LIMIT 1",
                (host, record.method.upper(), normalized_path),
            ).fetchone()
            if endpoint is None:
                return
            mutation = record.controlled_mutation or {}
            items = mutation.get("mutations", []) if isinstance(mutation, dict) else []
            first = items[0] if items else mutation
            parameter = str(first.get("field", "")) if isinstance(first, dict) else ""
            skill = str(first.get("source_skill", "")) if isinstance(first, dict) else ""
            now = utcnow()
            self._conn.execute(
                "INSERT INTO coverage_observation(endpoint_id,method,parameter,auth_context_class,skill_family,state,"
                "research_test_id,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,'TESTED',?,?,?,?) "
                "ON CONFLICT(endpoint_id,method,parameter,auth_context_class,skill_family) DO UPDATE SET "
                "state='TESTED',research_test_id=excluded.research_test_id,last_seen=excluded.last_seen",
                (endpoint["id"], record.method.upper(), parameter, record.auth_context, skill,
                 record.research_test_id, now, now, _jdump({"request_id": record.id})),
            )
            self._conn.commit()

    def list_request_records(self, session_id: int | None = None) -> list[RequestRecord]:
        q = "SELECT id FROM request_record"
        args: tuple = ()
        if session_id is not None:
            q += " WHERE session_id=?"
            args = (session_id,)
        q += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [self._request_from_row(self._fetch("request_record", r["id"])) for r in rows]

    def get_request_record(self, request_id: int) -> RequestRecord:
        return self._request_from_row(self._fetch("request_record", request_id))

    def save_differential_result(
        self, *, mode: str, baseline_request_id: int | None, request_ids: list[int],
        result: dict, research_test_id: int | None = None, hypothesis_id: int | None = None,
        artifact_ref: str = "",
    ) -> int:
        if baseline_request_id is not None:
            self.get_request_record(baseline_request_id)
        for request_id in request_ids:
            self.get_request_record(request_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO differential_result(mode,baseline_request_id,request_ids,research_test_id,"
                "hypothesis_id,result,artifact_ref,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (mode, baseline_request_id, _jdump(request_ids), research_test_id,
                 hypothesis_id, _jdump(result), artifact_ref, utcnow()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def _request_from_row(self, row: sqlite3.Row) -> RequestRecord:
        return RequestRecord(
            id=row["id"], public_id=self.public_id("request_record", row["id"]),
            program=row["program"], method=row["method"], url=row["url"],
            created_at=row["created_at"], session_id=row["session_id"],
            auth_context=row["auth_context"], request_metadata=_jload(row["request_metadata"], {}),
            response_metadata=_jload(row["response_metadata"], {}), burp_ref=row["burp_ref"],
            body_hash=row["body_hash"], evidence_ref=row["evidence_ref"],
            research_test_id=row["research_test_id"], hypothesis_id=row["hypothesis_id"],
            controlled_mutation=_jload(row["controlled_mutation"], {}),
            autonomy_run_id=row["autonomy_run_id"],
            parent_request_id=row["parent_request_id"], root_request_id=row["root_request_id"],
            replay_depth=row["replay_depth"], mutation_summary=row["mutation_summary"],
        )

    # ------------------------------------------------------------------ #
    # autonomy runs / hard budget accounting
    # ------------------------------------------------------------------ #
    def start_autonomy_run(self, session_id: int, goal: str, budget: dict) -> AutonomyRunRecord:
        session = self.require_session(session_id, running=True)
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM autonomy_run WHERE session_id=? AND status='running' ORDER BY id DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            if existing:
                return self.get_autonomy_run(existing["id"])
            cur = self._conn.execute(
                "INSERT INTO autonomy_run(session_id,goal,status,budget,usage,started_at,program,runtime,model_info) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (session_id, goal, "running", _jdump(budget), _jdump({}), utcnow(),
                 session.program_slug, session.runtime, _jdump({"runtime": session.runtime})),
            )
            self._conn.commit()
        return self.get_autonomy_run(cur.lastrowid)

    def get_autonomy_run(self, run_id: int) -> AutonomyRunRecord:
        row = self._fetch("autonomy_run", run_id)
        return AutonomyRunRecord(
            id=row["id"], public_id=self.public_id("autonomy_run", row["id"]),
            session_id=row["session_id"], goal=row["goal"], status=row["status"],
            budget=_jload(row["budget"], {}), usage=_jload(row["usage"], {}),
            stop_reason=row["stop_reason"], started_at=row["started_at"], ended_at=row["ended_at"],
            program=row["program"], runtime=row["runtime"],
            model_info=_jload(row["model_info"], {}),
        )

    def list_autonomy_runs(self, session_id: int | None = None) -> list[AutonomyRunRecord]:
        query = "SELECT id FROM autonomy_run"
        args: tuple = ()
        if session_id is not None:
            query += " WHERE session_id=?"
            args = (session_id,)
        query += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(query, args).fetchall()
        return [self.get_autonomy_run(row["id"]) for row in rows]

    def record_autonomy_activity(
        self, autonomy_run_id: int, session_id: int, activity_type: str,
        entity_type: str = "", entity_id: int | None = None,
        metadata: dict | None = None,
    ) -> AutonomyActivityRecord:
        run = self.get_autonomy_run(autonomy_run_id)
        if run.session_id != session_id:
            raise StateError("autonomy activity session does not match its run")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO autonomy_activity(autonomy_run_id,session_id,activity_type,"
                "entity_type,entity_id,created_at,metadata) VALUES(?,?,?,?,?,?,?)",
                (autonomy_run_id, session_id, activity_type, entity_type, entity_id,
                 utcnow(), _jdump(metadata or {})),
            )
            self._conn.commit()
            row = self._fetch("autonomy_activity", cur.lastrowid)
        return self._autonomy_activity_from_row(row)

    def list_autonomy_activities(
        self, autonomy_run_id: int, *, activity_type: str | None = None,
    ) -> list[AutonomyActivityRecord]:
        query = "SELECT * FROM autonomy_activity WHERE autonomy_run_id=?"
        args: list = [autonomy_run_id]
        if activity_type:
            query += " AND activity_type=?"; args.append(activity_type)
        query += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._autonomy_activity_from_row(row) for row in rows]

    def _autonomy_activity_from_row(self, row: sqlite3.Row) -> AutonomyActivityRecord:
        return AutonomyActivityRecord(
            id=row["id"], public_id=self.public_id("autonomy_activity", row["id"]),
            autonomy_run_id=row["autonomy_run_id"], session_id=row["session_id"],
            activity_type=row["activity_type"], entity_type=row["entity_type"],
            entity_id=row["entity_id"], created_at=row["created_at"],
            metadata=_jload(row["metadata"], {}),
        )

    def active_autonomy_run(self, session_id: int | None = None) -> AutonomyRunRecord | None:
        q = "SELECT id FROM autonomy_run WHERE status='running'"
        args: tuple = ()
        if session_id is not None:
            q += " AND session_id=?"
            args = (session_id,)
        q += " ORDER BY id DESC LIMIT 1"
        with self._lock:
            row = self._conn.execute(q, args).fetchone()
        return self.get_autonomy_run(row["id"]) if row else None

    def update_autonomy_usage(self, run_id: int, usage: dict) -> AutonomyRunRecord:
        with self._lock:
            self._conn.execute("UPDATE autonomy_run SET usage=? WHERE id=?", (_jdump(usage), run_id))
            self._conn.commit()
        return self.get_autonomy_run(run_id)

    def stop_autonomy_run(self, run_id: int, reason: str, status: str = "stopped") -> AutonomyRunRecord:
        if status not in {"stopped", "goal_reached", "paused", "budget_exhausted", "failed"}:
            raise StateError(f"invalid autonomy stop status: {status!r}")
        run = self.get_autonomy_run(run_id)
        with self._lock:
            self._conn.execute(
                "UPDATE autonomy_run SET status=?, stop_reason=?, ended_at=? WHERE id=?",
                (status, reason, utcnow(), run_id),
            )
            self._conn.commit()
        stopped = self.get_autonomy_run(run_id)
        self.record_autonomy_activity(
            run_id, run.session_id, "STOP_CONDITION", "autonomy_run", run_id,
            {"status": status, "reason": reason},
        )
        return stopped

    # ------------------------------------------------------------------ #
    # recon inventory (structured dicts; large raw output stays in files)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _recon_row(table: str, row: sqlite3.Row) -> dict:
        data = dict(row)
        for key in ("tools_requested", "tools_used", "artifact_refs", "metadata", "observed_types"):
            if key in data:
                data[key] = _jload(data[key], [] if key != "metadata" else {})
        for key in ("active", "interesting", "auth_required", "auth_observed", "user_controlled", "sensitive_name", "object_identifier_candidate"):
            if key in data and data[key] is not None:
                data[key] = bool(data[key])
        prefix = PUBLIC_ID_PREFIX.get(table)
        if prefix:
            data["public_id"] = f"{prefix}-{int(data['id']):03d}"
        return data

    def start_recon_run(self, profile: str = "", stage: str = "", tools_requested: list[str] | None = None, metadata: dict | None = None) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO recon_run(profile,stage,status,started_at,tools_requested,metadata) VALUES(?,?,?,?,?,?)",
                (profile, stage, "running", utcnow(), _jdump(tools_requested or []), _jdump(metadata or {})),
            )
            self._conn.commit()
        return self.get_recon_run(cur.lastrowid)

    def finish_recon_run(self, run_id: int, *, status: str = "completed", **counts) -> dict:
        if status not in {"completed", "partial", "failed", "cancelled"}:
            raise StateError(f"invalid recon run status: {status!r}")
        allowed = {
            "tools_used", "raw_observation_count", "new_asset_count", "updated_asset_count",
            "new_endpoint_count", "lead_count", "error_count", "artifact_refs", "metadata",
        }
        clean = {key: value for key, value in counts.items() if key in allowed}
        for key in ("tools_used", "artifact_refs", "metadata"):
            if key in clean:
                clean[key] = _jdump(clean[key])
        clean.update({"status": status, "completed_at": utcnow()})
        self._update_fields("recon_run", run_id, clean)
        return self.get_recon_run(run_id)

    def get_recon_run(self, run_id: int) -> dict:
        return self._recon_row("recon_run", self._fetch("recon_run", run_id))

    def list_recon_runs(self, *, status: str | None = None, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        query, args = "SELECT * FROM recon_run", []
        if status:
            query += " WHERE status=?"
            args.append(status)
        query += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._recon_row("recon_run", row) for row in rows]

    def upsert_asset(self, *, type: str, value: str, normalized_value: str, scope_status: str, confidence: float = 0.5, metadata: dict | None = None) -> tuple[dict, bool]:
        now = utcnow()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM asset WHERE type=? AND normalized_value=?", (type, normalized_value),
            ).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO asset(type,value,normalized_value,scope_status,first_seen,last_seen,confidence,metadata) VALUES(?,?,?,?,?,?,?,?)",
                    (type, value, normalized_value, scope_status, now, now, max(0.0, min(float(confidence), 1.0)), _jdump(metadata or {})),
                )
                asset_id, created = cur.lastrowid, True
            else:
                merged = _jload(row["metadata"], {})
                merged.update(metadata or {})
                self._conn.execute(
                    "UPDATE asset SET value=?,scope_status=?,last_seen=?,active=1,confidence=MAX(confidence,?),metadata=? WHERE id=?",
                    (value, scope_status, now, max(0.0, min(float(confidence), 1.0)), _jdump(merged), row["id"]),
                )
                asset_id, created = row["id"], False
            self._conn.commit()
        return self.get_asset(asset_id), created

    def get_asset(self, asset_id: int) -> dict:
        return self._recon_row("asset", self._fetch("asset", asset_id))

    def set_asset_active(self, asset_id: int, active: bool) -> dict:
        with self._lock:
            self._conn.execute("UPDATE asset SET active=? WHERE id=?", (int(active), asset_id))
            self._conn.commit()
        return self.get_asset(asset_id)

    def list_assets(self, *, type: str | None = None, interesting: bool | None = None, min_score: int = 0, host: str = "", source: str = "", since: str = "", limit: int = 200, offset: int = 0) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        where, args = ["a.interest_score>=?"], [int(min_score)]
        if type:
            where.append("a.type=?"); args.append(type)
        if interesting is not None:
            where.append("a.interesting=?"); args.append(int(interesting))
        if host:
            where.append("a.normalized_value LIKE ?"); args.append(f"%{host.lower()}%")
        if since:
            where.append("a.last_seen>=?"); args.append(since)
        if source:
            where.append("EXISTS(SELECT 1 FROM asset_observation o WHERE o.asset_id=a.id AND (o.source_tool=? OR o.source_type=?))")
            args.extend([source, source])
        args.extend([limit, max(0, int(offset))])
        with self._lock:
            rows = self._conn.execute(
                f"SELECT a.* FROM asset a WHERE {' AND '.join(where)} ORDER BY a.interest_score DESC,a.id LIMIT ? OFFSET ?",
                tuple(args),
            ).fetchall()
        return [self._recon_row("asset", row) for row in rows]

    def add_asset_observation(self, *, asset_id: int, recon_run_id: int, source_tool: str, source_type: str, observation_type: str, raw_value: str = "", artifact_ref: str = "", metadata: dict | None = None) -> tuple[dict, bool]:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO asset_observation(asset_id,recon_run_id,source_tool,source_type,observed_at,observation_type,raw_value,artifact_ref,metadata) VALUES(?,?,?,?,?,?,?,?,?)",
                (asset_id, recon_run_id, source_tool, source_type, utcnow(), observation_type, raw_value[:2048], artifact_ref, _jdump(metadata or {})),
            )
            created = bool(cur.rowcount)
            row = self._conn.execute(
                "SELECT * FROM asset_observation WHERE asset_id=? AND recon_run_id=? AND source_tool=? AND observation_type=? AND raw_value=?",
                (asset_id, recon_run_id, source_tool, observation_type, raw_value[:2048]),
            ).fetchone()
            if created:
                sources = self._conn.execute("SELECT COUNT(DISTINCT source_tool) n FROM asset_observation WHERE asset_id=?", (asset_id,)).fetchone()["n"]
                self._conn.execute("UPDATE asset SET observation_count=observation_count+1,confidence=MAX(confidence,?) WHERE id=?", (min(0.95, 0.5 + 0.1 * int(sources)), asset_id))
            self._conn.commit()
        return dict(row), created

    def list_asset_observations(self, asset_id: int | None = None, recon_run_id: int | None = None, limit: int = 500) -> list[dict]:
        where, args = [], []
        if asset_id is not None: where.append("asset_id=?"); args.append(asset_id)
        if recon_run_id is not None: where.append("recon_run_id=?"); args.append(recon_run_id)
        query = "SELECT * FROM asset_observation"
        if where: query += " WHERE " + " AND ".join(where)
        query += " ORDER BY id DESC LIMIT ?"; args.append(max(1, min(int(limit), 2000)))
        with self._lock: rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._recon_row("asset_observation", row) for row in rows]

    def upsert_endpoint(self, *, host_asset_id: int, scheme: str, method: str, normalized_path: str, auth_required: bool | None = None, auth_observed: bool = False, content_type: str = "", metadata: dict | None = None) -> tuple[dict, bool]:
        now, method = utcnow(), method.upper()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM endpoint WHERE host_asset_id=? AND scheme=? AND method=? AND normalized_path=?",
                (host_asset_id, scheme, method, normalized_path),
            ).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO endpoint(host_asset_id,scheme,method,normalized_path,auth_required,auth_observed,content_type,first_seen,last_seen,source_count,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (host_asset_id, scheme, method, normalized_path, None if auth_required is None else int(auth_required), int(auth_observed), content_type, now, now, 1, _jdump(metadata or {})),
                )
                endpoint_id, created = cur.lastrowid, True
            else:
                merged = _jload(row["metadata"], {})
                observed_sources = set(merged.get("sources", []))
                merged.update(metadata or {})
                observed_sources.update((metadata or {}).get("sources", []))
                if observed_sources: merged["sources"] = sorted(observed_sources)
                self._conn.execute(
                    "UPDATE endpoint SET last_seen=?,auth_required=COALESCE(?,auth_required),auth_observed=MAX(auth_observed,?),content_type=CASE WHEN ?!='' THEN ? ELSE content_type END,source_count=?,metadata=? WHERE id=?",
                    (now, None if auth_required is None else int(auth_required), int(auth_observed), content_type, content_type, max(1, len(observed_sources)), _jdump(merged), row["id"]),
                )
                endpoint_id, created = row["id"], False
            self._conn.commit()
        return self.get_endpoint(endpoint_id), created

    def get_endpoint(self, endpoint_id: int) -> dict:
        row = self._fetch("endpoint", endpoint_id)
        result = self._recon_row("endpoint", row)
        result["host"] = self.get_asset(row["host_asset_id"])["normalized_value"]
        return result

    def list_endpoints(self, *, interesting: bool | None = None, min_score: int = 0, host: str = "", source: str = "", since: str = "", limit: int = 200, offset: int = 0) -> list[dict]:
        where, args = ["e.interest_score>=?"], [int(min_score)]
        if interesting is not None: where.append("e.interesting=?"); args.append(int(interesting))
        if host: where.append("a.normalized_value LIKE ?"); args.append(f"%{host.lower()}%")
        if source: where.append("e.metadata LIKE ?"); args.append(f'%"{source}"%')
        if since: where.append("e.last_seen>=?"); args.append(since)
        args.extend([max(1, min(int(limit), 1000)), max(0, int(offset))])
        with self._lock:
            rows = self._conn.execute(
                f"SELECT e.*,a.normalized_value host FROM endpoint e JOIN asset a ON a.id=e.host_asset_id WHERE {' AND '.join(where)} ORDER BY e.interest_score DESC,e.id LIMIT ? OFFSET ?", tuple(args),
            ).fetchall()
        result = []
        for row in rows:
            item = self._recon_row("endpoint", row); item["host"] = row["host"]; result.append(item)
        return result

    def upsert_endpoint_parameter(self, *, endpoint_id: int, name: str, location: str, observed_types: list[str] | None = None, user_controlled: bool = False, sensitive_name: bool = False, object_identifier_candidate: bool = False, metadata: dict | None = None) -> tuple[dict, bool]:
        now = utcnow()
        with self._lock:
            row = self._conn.execute("SELECT * FROM endpoint_parameter WHERE endpoint_id=? AND name=? AND location=?", (endpoint_id, name, location)).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO endpoint_parameter(endpoint_id,name,location,observed_types,user_controlled,sensitive_name,object_identifier_candidate,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (endpoint_id, name, location, _jdump(sorted(set(observed_types or []))), int(user_controlled), int(sensitive_name), int(object_identifier_candidate), now, now, _jdump(metadata or {})),
                ); parameter_id, created = cur.lastrowid, True
            else:
                types = sorted(set(_jload(row["observed_types"], [])) | set(observed_types or []))
                merged = _jload(row["metadata"], {}); merged.update(metadata or {})
                self._conn.execute(
                    "UPDATE endpoint_parameter SET observed_types=?,user_controlled=MAX(user_controlled,?),sensitive_name=MAX(sensitive_name,?),object_identifier_candidate=MAX(object_identifier_candidate,?),last_seen=?,metadata=? WHERE id=?",
                    (_jdump(types), int(user_controlled), int(sensitive_name), int(object_identifier_candidate), now, _jdump(merged), row["id"]),
                ); parameter_id, created = row["id"], False
            self._conn.commit()
        return self._recon_row("endpoint_parameter", self._fetch("endpoint_parameter", parameter_id)), created

    def list_endpoint_parameters(self, endpoint_id: int | None = None, *, host: str = "", since: str = "", limit: int = 500, offset: int = 0) -> list[dict]:
        where, args = [], []
        if endpoint_id is not None: where.append("p.endpoint_id=?"); args.append(endpoint_id)
        if host: where.append("a.normalized_value LIKE ?"); args.append(f"%{host.lower()}%")
        if since: where.append("p.last_seen>=?"); args.append(since)
        query = "SELECT p.*,a.normalized_value host,e.method,e.normalized_path FROM endpoint_parameter p JOIN endpoint e ON e.id=p.endpoint_id JOIN asset a ON a.id=e.host_asset_id"
        if where: query += " WHERE " + " AND ".join(where)
        query += " ORDER BY p.id LIMIT ? OFFSET ?"; args.extend([max(1, min(int(limit), 2000)), max(0, int(offset))])
        with self._lock: rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._recon_row("endpoint_parameter", row) for row in rows]

    def add_technology_observation(self, *, asset_id: int, technology: str, category: str, confidence: float, source: str, endpoint_id: int | None = None, metadata: dict | None = None) -> tuple[dict, bool]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM technology_observation WHERE asset_id=? AND endpoint_id IS ? AND technology=? AND source=?", (asset_id, endpoint_id, technology, source)).fetchone()
            created = row is None
            if created:
                self._conn.execute(
                    "INSERT INTO technology_observation(asset_id,endpoint_id,technology,category,confidence,source,observed_at,metadata) VALUES(?,?,?,?,?,?,?,?)",
                    (asset_id, endpoint_id, technology, category, max(0.0, min(float(confidence), 1.0)), source, utcnow(), _jdump(metadata or {})),
                )
                row = self._conn.execute("SELECT * FROM technology_observation WHERE asset_id=? AND endpoint_id IS ? AND technology=? AND source=?", (asset_id, endpoint_id, technology, source)).fetchone()
            self._conn.commit()
        return self._recon_row("technology_observation", row), created

    def list_technology_observations(self, *, asset_id: int | None = None, since: str = "", limit: int = 500) -> list[dict]:
        where, args = [], []
        if asset_id is not None: where.append("t.asset_id=?"); args.append(asset_id)
        if since: where.append("t.observed_at>=?"); args.append(since)
        query = "SELECT t.*,a.normalized_value asset FROM technology_observation t JOIN asset a ON a.id=t.asset_id"
        if where: query += " WHERE " + " AND ".join(where)
        query += " ORDER BY t.id DESC LIMIT ?"; args.append(max(1, min(int(limit), 2000)))
        with self._lock: rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._recon_row("technology_observation", row) for row in rows]

    def add_recon_change(self, *, recon_run_id: int, change_type: str, entity_type: str, entity_id: int, old_value: str = "", new_value: str = "", interest_score: int = 0) -> dict:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO recon_change(recon_run_id,change_type,entity_type,entity_id,old_value,new_value,interest_score,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (recon_run_id, change_type, entity_type, entity_id, old_value, new_value, int(interest_score), utcnow()),
            )
            row = self._conn.execute("SELECT * FROM recon_change WHERE recon_run_id=? AND change_type=? AND entity_type=? AND entity_id=? AND new_value=?", (recon_run_id, change_type, entity_type, entity_id, new_value)).fetchone()
            if entity_type == "endpoint" and change_type not in {"ENDPOINT_DISCOVERED", "NEW_ENDPOINT"}:
                self._conn.execute(
                    "UPDATE coverage_observation SET state='STALE_AFTER_CHANGE',last_seen=? "
                    "WHERE endpoint_id=? AND state IN ('BASELINED','TESTED','EXHAUSTED_FOR_HYPOTHESIS')",
                    (utcnow(), entity_id),
                )
            self._conn.commit()
        return self._recon_row("recon_change", row)

    def list_recon_changes(self, *, recon_run_id: int | None = None, change_type: str = "", since: str = "", limit: int = 500, offset: int = 0) -> list[dict]:
        where, args = [], []
        if recon_run_id is not None: where.append("recon_run_id=?"); args.append(recon_run_id)
        if change_type: where.append("change_type=?"); args.append(change_type)
        if since: where.append("created_at>=?"); args.append(since)
        query = "SELECT * FROM recon_change"
        if where: query += " WHERE " + " AND ".join(where)
        query += " ORDER BY interest_score DESC,id DESC LIMIT ? OFFSET ?"; args.extend([max(1, min(int(limit), 2000)), max(0, int(offset))])
        with self._lock: rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._recon_row("recon_change", row) for row in rows]

    def recon_counts(self, *, recon_run_id: int | None = None) -> dict:
        """SQL-native inventory totals, independent of list pagination caps."""
        with self._lock:
            scalar = lambda sql, args=(): int(self._conn.execute(sql, args).fetchone()[0])
            counts = {
                "assets": scalar("SELECT COUNT(*) FROM asset"),
                "hosts": scalar("SELECT COUNT(*) FROM asset WHERE type='host'"),
                "interesting_hosts": scalar("SELECT COUNT(*) FROM asset WHERE type='host' AND interesting=1"),
                "endpoints": scalar("SELECT COUNT(*) FROM endpoint"),
                "interesting_endpoints": scalar("SELECT COUNT(*) FROM endpoint WHERE interesting=1"),
                "authenticated_endpoints": scalar("SELECT COUNT(*) FROM endpoint WHERE auth_observed=1"),
                "state_changing_endpoints": scalar("SELECT COUNT(*) FROM endpoint WHERE method NOT IN ('GET','HEAD','OPTIONS')"),
                "parameters": scalar("SELECT COUNT(*) FROM endpoint_parameter"),
                "object_id_surfaces": scalar("SELECT COUNT(DISTINCT endpoint_id) FROM endpoint_parameter WHERE object_identifier_candidate=1"),
            }
            if recon_run_id is not None:
                rows = self._conn.execute(
                    "SELECT change_type,COUNT(*) n FROM recon_change WHERE recon_run_id=? GROUP BY change_type",
                    (recon_run_id,),
                ).fetchall()
                counts["changes"] = {row["change_type"]: int(row["n"]) for row in rows}
        return counts

    def recon_changes_for_endpoint(self, recon_run_id: int, endpoint_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT c.* FROM recon_change c LEFT JOIN endpoint_parameter p "
                "ON c.entity_type='endpoint_parameter' AND p.id=c.entity_id "
                "WHERE c.recon_run_id=? AND ((c.entity_type='endpoint' AND c.entity_id=?) "
                "OR p.endpoint_id=?) ORDER BY c.interest_score DESC,c.id",
                (recon_run_id, endpoint_id, endpoint_id),
            ).fetchall()
        return [self._recon_row("recon_change", row) for row in rows]

    def link_lead_recon_change(self, lead_id: int, recon_change_id: int) -> None:
        self.get_lead(lead_id); self._fetch("recon_change", recon_change_id)
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO lead_recon_change(lead_id,recon_change_id,created_at) VALUES(?,?,?)",
                (lead_id, recon_change_id, utcnow()),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # source intelligence (program-bound by this HuntDB instance)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _source_row(entity: str, row: sqlite3.Row) -> dict:
        item = dict(row)
        item["public_id"] = HuntDB.public_id(entity, int(row["id"]))
        for field, default in (
            ("metadata", {}), ("artifact_refs", []), ("evidence_refs", []),
        ):
            if field in item:
                item[field] = _jload(item[field], default)
        return item

    def register_source_repository(
        self, *, repository_id: str, official_url: str, requested_ref: str,
        resolved_commit: str, snapshot_path: str, source_type: str = "git",
        branch: str = "", tag: str = "", program_relation: str = "in_scope_source",
        license_info: str = "", metadata: dict | None = None,
    ) -> dict:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", repository_id):
            raise StateError("invalid source repository_id")
        if not re.fullmatch(r"[0-9a-f]{40,64}", resolved_commit.lower()):
            raise StateError("source repository must be pinned to a full commit SHA")
        now = utcnow()
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM source_repository WHERE repository_id=?", (repository_id,),
            ).fetchone()
            if existing is None:
                cur = self._conn.execute(
                    "INSERT INTO source_repository(repository_id,official_url,source_type,requested_ref,resolved_commit,branch,tag,retrieved_at,program_relation,license_info,snapshot_path,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (repository_id, official_url, source_type, requested_ref,
                     resolved_commit.lower(), branch, tag, now, program_relation,
                     license_info, snapshot_path, _jdump(metadata or {})),
                )
                row_id = int(cur.lastrowid)
            else:
                merged = _jload(existing["metadata"], {}); merged.update(metadata or {})
                self._conn.execute(
                    "UPDATE source_repository SET official_url=?,source_type=?,requested_ref=?,previous_commit=resolved_commit,resolved_commit=?,branch=?,tag=?,retrieved_at=?,program_relation=?,license_info=?,snapshot_path=?,status='active',metadata=? WHERE id=?",
                    (official_url, source_type, requested_ref, resolved_commit.lower(),
                     branch, tag, now, program_relation, license_info, snapshot_path,
                     _jdump(merged), existing["id"]),
                )
                row_id = int(existing["id"])
            self._conn.commit()
        return self.get_source_repository(row_id)

    def get_source_repository(self, repository: int | str) -> dict:
        with self._lock:
            if isinstance(repository, int) or str(repository).isdigit():
                row = self._conn.execute(
                    "SELECT * FROM source_repository WHERE id=?", (int(repository),),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM source_repository WHERE repository_id=?", (str(repository),),
                ).fetchone()
        if row is None:
            raise StateError(f"source repository {repository!r} not found")
        return self._source_row("source_repository", row)

    def list_source_repositories(self, *, status: str | None = None) -> list[dict]:
        query, args = "SELECT * FROM source_repository", []
        if status:
            query += " WHERE status=?"; args.append(status)
        query += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._source_row("source_repository", row) for row in rows]

    def update_source_repository_metadata(self, repository: int | str, metadata: dict) -> dict:
        row = self.get_source_repository(repository)
        merged = dict(row.get("metadata", {})); merged.update(metadata)
        with self._lock:
            self._conn.execute(
                "UPDATE source_repository SET metadata=? WHERE id=?",
                (_jdump(merged), row["id"]),
            )
            self._conn.commit()
        return self.get_source_repository(row["id"])

    def start_source_analysis_run(
        self, repository_id: int, analysis_type: str, *, tool: str = "builtin",
        tool_version: str = "", metadata: dict | None = None,
    ) -> dict:
        repo = self.get_source_repository(repository_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO source_analysis_run(repository_id,analysis_type,tool,tool_version,source_commit,started_at,metadata) VALUES(?,?,?,?,?,?,?)",
                (repo["id"], analysis_type, tool, tool_version,
                 repo["resolved_commit"], utcnow(), _jdump(metadata or {})),
            )
            self._conn.commit()
            row = self._fetch("source_analysis_run", int(cur.lastrowid))
        return self._source_row("source_analysis_run", row)

    def finish_source_analysis_run(
        self, run_id: int, *, status: str = "completed", files_read: int = 0,
        searches: int = 0, observation_count: int = 0,
        artifact_refs: list[str] | None = None, metadata: dict | None = None,
    ) -> dict:
        row = self._fetch("source_analysis_run", run_id)
        merged = _jload(row["metadata"], {}); merged.update(metadata or {})
        with self._lock:
            self._conn.execute(
                "UPDATE source_analysis_run SET status=?,completed_at=?,files_read=?,searches=?,observation_count=?,artifact_refs=?,metadata=? WHERE id=?",
                (status, utcnow(), max(0, int(files_read)), max(0, int(searches)),
                 max(0, int(observation_count)), _jdump(artifact_refs or []),
                 _jdump(merged), run_id),
            )
            self._conn.commit()
            updated = self._fetch("source_analysis_run", run_id)
        return self._source_row("source_analysis_run", updated)

    def list_source_analysis_runs(self, repository_id: int | None = None) -> list[dict]:
        query, args = "SELECT * FROM source_analysis_run", []
        if repository_id is not None:
            self.get_source_repository(repository_id)
            query += " WHERE repository_id=?"; args.append(repository_id)
        query += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._source_row("source_analysis_run", row) for row in rows]

    def create_source_runtime_mapping(
        self, *, repository_id: int, source_surface: str, runtime_target: str,
        mapping_method: str, confidence: float, runtime_version: str = "",
        runtime_endpoint_id: int | None = None, evidence_refs: list[str] | None = None,
        status: str = "candidate", metadata: dict | None = None,
    ) -> dict:
        repo = self.get_source_repository(repository_id)
        if runtime_endpoint_id is not None:
            self.get_endpoint(runtime_endpoint_id)
        self._require_evidence_refs(evidence_refs or [])
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO source_runtime_mapping(repository_id,source_commit,source_surface,runtime_target,runtime_version,runtime_endpoint_id,confidence,mapping_method,evidence_refs,status,created_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo["id"], repo["resolved_commit"], source_surface, runtime_target,
                 runtime_version, runtime_endpoint_id, max(0.0, min(float(confidence), 1.0)),
                 mapping_method, _jdump(evidence_refs or []), status, utcnow(),
                 _jdump(metadata or {})),
            )
            self._conn.commit()
            row = self._fetch("source_runtime_mapping", int(cur.lastrowid))
        return self._source_row("source_runtime_mapping", row)

    def list_source_runtime_mappings(self, repository_id: int | None = None) -> list[dict]:
        query, args = "SELECT * FROM source_runtime_mapping", []
        if repository_id is not None:
            query += " WHERE repository_id=?"; args.append(repository_id)
        query += " ORDER BY confidence DESC,id DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._source_row("source_runtime_mapping", row) for row in rows]

    def create_source_observation(
        self, *, repository_id: int, observation_type: str, file: str,
        observation: str, source_skill: str, confidence: float = 0.5,
        line_start: int | None = None, line_end: int | None = None,
        symbol: str = "", redacted_excerpt: str = "", analysis_run_id: int | None = None,
        runtime_mapping_id: int | None = None, metadata: dict | None = None,
    ) -> dict:
        repo = self.get_source_repository(repository_id)
        now = utcnow()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO source_observation(repository_id,analysis_run_id,observation_type,file,line_start,line_end,symbol,source_commit,observation,redacted_excerpt,confidence,source_skill,runtime_mapping_id,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo["id"], analysis_run_id, observation_type, file, line_start,
                 line_end, symbol, repo["resolved_commit"], observation,
                 redacted_excerpt, max(0.0, min(float(confidence), 1.0)), source_skill,
                 runtime_mapping_id, now, now, _jdump(metadata or {})),
            )
            self._conn.commit()
            row = self._fetch("source_observation", int(cur.lastrowid))
        return self._source_row("source_observation", row)

    def list_source_observations(
        self, repository_id: int | None = None, *, status: str | None = None,
        min_confidence: float = 0.0, limit: int = 200,
    ) -> list[dict]:
        where, args = ["confidence>=?"], [max(0.0, min(float(min_confidence), 1.0))]
        if repository_id is not None:
            where.append("repository_id=?"); args.append(repository_id)
        if status:
            where.append("status=?"); args.append(status)
        args.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM source_observation WHERE {' AND '.join(where)} ORDER BY confidence DESC,id DESC LIMIT ?",
                tuple(args),
            ).fetchall()
        return [self._source_row("source_observation", row) for row in rows]

    def promote_source_observation_to_lead(
        self, observation_id: int, *, title: str, priority: str = "medium",
        rationale: str = "",
    ) -> LeadRecord:
        row = self._fetch("source_observation", observation_id)
        if row["lead_id"] is not None:
            return self.get_lead(int(row["lead_id"]))
        repo = self.get_source_repository(int(row["repository_id"]))
        location = f"{repo['repository_id']}@{row['source_commit'][:12]}:{row['file']}"
        lead = self.add_lead(
            title, entity=location, source=f"source:{repo['repository_id']}",
            priority=priority,
            rationale=rationale or str(row["observation"]),
        )
        with self._lock:
            self._conn.execute(
                "UPDATE source_observation SET lead_id=?,last_seen=? WHERE id=?",
                (lead.id, utcnow(), observation_id),
            )
            self._conn.commit()
        return lead

    def save_source_security_context(self, repository_id: int, context: dict) -> dict:
        repo = self.get_source_repository(repository_id)
        json_fields = (
            "components", "entry_points", "trust_boundaries", "security_controls",
            "sensitive_assets", "external_integrations", "data_stores",
            "security_invariants", "unresolved_questions",
        )
        values = [
            repo["id"], repo["resolved_commit"],
            str(context.get("architecture_summary", "")),
            *[_jdump(context.get(field, [])) for field in json_fields],
            utcnow(), _jdump(context.get("metadata", {})),
        ]
        with self._lock:
            self._conn.execute(
                "INSERT INTO source_security_context(repository_id,source_commit,architecture_summary,components,entry_points,trust_boundaries,security_controls,sensitive_assets,external_integrations,data_stores,security_invariants,unresolved_questions,generated_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(repository_id,source_commit) DO UPDATE SET architecture_summary=excluded.architecture_summary,components=excluded.components,entry_points=excluded.entry_points,trust_boundaries=excluded.trust_boundaries,security_controls=excluded.security_controls,sensitive_assets=excluded.sensitive_assets,external_integrations=excluded.external_integrations,data_stores=excluded.data_stores,security_invariants=excluded.security_invariants,unresolved_questions=excluded.unresolved_questions,generated_at=excluded.generated_at,metadata=excluded.metadata",
                tuple(values),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM source_security_context WHERE repository_id=? AND source_commit=?",
                (repo["id"], repo["resolved_commit"]),
            ).fetchone()
        item = dict(row)
        for field in (*json_fields, "metadata"):
            item[field] = _jload(item[field], {} if field == "metadata" else [])
        return item

    def get_source_security_context(self, repository_id: int, commit: str = "") -> dict | None:
        repo = self.get_source_repository(repository_id)
        wanted = commit or repo["resolved_commit"]
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM source_security_context WHERE repository_id=? AND source_commit=?",
                (repo["id"], wanted),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        for field in (
            "components", "entry_points", "trust_boundaries", "security_controls",
            "sensitive_assets", "external_integrations", "data_stores",
            "security_invariants", "unresolved_questions", "metadata",
        ):
            item[field] = _jload(item[field], {} if field == "metadata" else [])
        return item

    def replace_source_symbols(self, repository_id: int, symbols: list[dict]) -> int:
        repo = self.get_source_repository(repository_id)
        commit = repo["resolved_commit"]
        with self._lock:
            self._conn.execute(
                "DELETE FROM source_symbol WHERE repository_id=? AND source_commit=?",
                (repo["id"], commit),
            )
            for symbol in symbols:
                self._conn.execute(
                    "INSERT INTO source_symbol(repository_id,source_commit,language,file,line_start,line_end,name,qualified_name,kind,confidence,assumptions,guarantees,controls,inputs,outputs,callers,callees,side_effects,trust_boundary,unresolved_assumptions,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (repo["id"], commit, symbol.get("language", "Unknown"), symbol["file"],
                     int(symbol.get("line_start", 1)), symbol.get("line_end"), symbol["name"],
                     symbol.get("qualified_name", ""), symbol.get("kind", "function"),
                     symbol.get("confidence", "MEDIUM"), _jdump(symbol.get("assumptions", [])),
                     _jdump(symbol.get("guarantees", [])), _jdump(symbol.get("controls", [])),
                     _jdump(symbol.get("inputs", [])), _jdump(symbol.get("outputs", [])),
                     _jdump(symbol.get("callers", [])), _jdump(symbol.get("callees", [])),
                     _jdump(symbol.get("side_effects", [])), symbol.get("trust_boundary", ""),
                     _jdump(symbol.get("unresolved_assumptions", [])),
                     _jdump(symbol.get("metadata", {}))),
                )
            self._conn.commit()
        return len(symbols)

    def list_source_symbols(
        self, repository_id: int, *, name: str = "", kind: str = "", limit: int = 500,
    ) -> list[dict]:
        repo = self.get_source_repository(repository_id)
        where, args = ["repository_id=?", "source_commit=?"], [repo["id"], repo["resolved_commit"]]
        if name:
            where.append("(name=? OR qualified_name=?)"); args.extend([name, name])
        if kind:
            where.append("kind=?"); args.append(kind)
        args.append(max(1, min(int(limit), 5000)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM source_symbol WHERE {' AND '.join(where)} ORDER BY file,line_start LIMIT ?",
                tuple(args),
            ).fetchall()
        result = []
        for row in rows:
            item = self._source_row("source_symbol", row)
            for field in ("assumptions", "guarantees", "controls", "inputs", "outputs", "callers", "callees", "side_effects", "unresolved_assumptions"):
                item[field] = _jload(row[field], [])
            result.append(item)
        return result

    def create_security_invariant(
        self, repository_id: int, *, description: str, source_skill: str,
        component: str = "", source_evidence: list | None = None,
        confidence: float = 0.5, supporting_controls: list | None = None,
        possible_violations: list | None = None, metadata: dict | None = None,
    ) -> dict:
        repo = self.get_source_repository(repository_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO security_invariant(repository_id,source_commit,component,description,source_evidence,confidence,supporting_controls,possible_violations,source_skill,created_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (repo["id"], repo["resolved_commit"], component, description,
                 _jdump(source_evidence or []), max(0.0, min(float(confidence), 1.0)),
                 _jdump(supporting_controls or []), _jdump(possible_violations or []),
                 source_skill, utcnow(), _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("security_invariant", int(cur.lastrowid))
        return self._source_row("security_invariant", row)

    def list_security_invariants(self, repository_id: int, *, limit: int = 200) -> list[dict]:
        repo = self.get_source_repository(repository_id)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM security_invariant WHERE repository_id=? AND source_commit=? ORDER BY confidence DESC,id DESC LIMIT ?",
                (repo["id"], repo["resolved_commit"], max(1, min(limit, 1000))),
            ).fetchall()
        return [self._source_row("security_invariant", row) for row in rows]

    def create_root_cause(self, repository_id: int, **fields) -> dict:
        repo = self.get_source_repository(repository_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO root_cause(repository_id,source_commit,source,affected_component,description,violated_invariant,exact_pattern,fix_pattern,preconditions,dangerous_sink,safe_sibling,rule_artifacts,created_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo["id"], repo["resolved_commit"], fields.get("source", ""),
                 fields.get("affected_component", ""), fields["description"],
                 fields.get("violated_invariant", ""), fields.get("exact_pattern", ""),
                 fields.get("fix_pattern", ""), _jdump(fields.get("preconditions", [])),
                 fields.get("dangerous_sink", ""), fields.get("safe_sibling", ""),
                 _jdump(fields.get("rule_artifacts", [])), utcnow(),
                 _jdump(fields.get("metadata", {}))),
            )
            self._conn.commit(); row = self._fetch("root_cause", int(cur.lastrowid))
        return self._source_row("root_cause", row)

    def get_root_cause(self, root_cause_id: int) -> dict:
        return self._source_row("root_cause", self._fetch("root_cause", root_cause_id))

    def create_specialist_task(
        self, *, created_by_role: str, assigned_role: str, goal: str,
        session_id: int | None = None, autonomy_run_id: int | None = None,
        lead_id: int | None = None, hypothesis_id: int | None = None,
        input_summary: str = "", input_context_ref: str = "",
        timeout_seconds: int = 600, metadata: dict | None = None,
    ) -> dict:
        if assigned_role in {"human", "approval-authority"}:
            raise StateError("specialist tasks cannot delegate approval authority")
        if not goal.strip():
            raise StateError("specialist task goal is required")
        if session_id is not None:
            creator = self.require_session(session_id, running=True)
            if creator.agent_role != created_by_role:
                raise StateError("specialist creator role does not match creator session")
        if autonomy_run_id is not None:
            run = self.get_autonomy_run(autonomy_run_id)
            if session_id is None or run.session_id != session_id:
                raise StateError("specialist task autonomy run is not bound to creator session")
        if lead_id is not None:
            self.get_lead(lead_id)
        if hypothesis_id is not None:
            hypothesis = self.get_hypothesis(hypothesis_id)
            if lead_id is not None and hypothesis.lead_id != lead_id:
                raise StateError("specialist hypothesis is not bound to the supplied lead")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO specialist_task(autonomy_run_id,session_id,creator_session_id,created_by_role,assigned_role,lead_id,hypothesis_id,goal,input_summary,input_context_ref,timeout_seconds,created_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (autonomy_run_id, session_id, session_id, created_by_role, assigned_role,
                 lead_id, hypothesis_id, goal.strip(), input_summary, input_context_ref,
                 max(1, min(int(timeout_seconds), 3600)), utcnow(), _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("specialist_task", int(cur.lastrowid))
        return self._telemetry_row("specialist_task", row)

    def get_specialist_task(self, task_id: int) -> dict:
        return self._telemetry_row("specialist_task", self._fetch("specialist_task", task_id))

    def claim_specialist_task(
        self, task_id: int, *, lease_owner: str, claimed_session_id: int,
        lease_seconds: int = 120, max_parallel: int = 1,
    ) -> dict:
        """Atomically lease one independent pending Lead task."""
        session = self.require_session(claimed_session_id, running=True)
        now = datetime.now(timezone.utc); expires = now + timedelta(seconds=max(15, min(lease_seconds, 600)))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                stale = [item["task_id"] for item in self._conn.execute(
                    "SELECT task_id FROM specialist_task_lease WHERE expires_at<=?", (now.isoformat(),)
                ).fetchall()]
                for stale_id in stale:
                    self._conn.execute(
                        "UPDATE specialist_task SET status='PENDING',claimed_session_id=NULL,error='stale lease recovered' "
                        "WHERE id=? AND status='RUNNING'", (stale_id,),
                    )
                self._conn.execute("DELETE FROM specialist_task_lease WHERE expires_at<=?", (now.isoformat(),))
                row = self._conn.execute("SELECT * FROM specialist_task WHERE id=?", (task_id,)).fetchone()
                if row is None or row["status"] != "PENDING":
                    raise StateError("specialist task is not pending")
                if session.agent_role != row["assigned_role"]:
                    raise StateError("claimed session role does not match specialist task")
                running = self._conn.execute(
                    "SELECT COUNT(*) FROM specialist_task_lease l JOIN specialist_task t ON t.id=l.task_id "
                    "WHERE t.autonomy_run_id IS ?", (row["autonomy_run_id"],),
                ).fetchone()[0]
                if running >= max(1, min(int(max_parallel), 2)):
                    raise StateError("bounded specialist parallelism limit reached")
                if row["lead_id"] is not None:
                    conflict = self._conn.execute(
                        "SELECT 1 FROM specialist_task_lease l JOIN specialist_task t ON t.id=l.task_id "
                        "WHERE t.lead_id=? LIMIT 1", (row["lead_id"],),
                    ).fetchone()
                    if conflict:
                        raise StateError("another specialist already holds this Lead")
                self._conn.execute(
                    "INSERT INTO specialist_task_lease(task_id,lease_owner,acquired_at,heartbeat_at,expires_at) VALUES(?,?,?,?,?)",
                    (task_id, lease_owner, now.isoformat(), now.isoformat(), expires.isoformat()),
                )
                self._conn.execute(
                    "UPDATE specialist_task SET status='RUNNING',started_at=?,claimed_session_id=? WHERE id=? AND status='PENDING'",
                    (utcnow(), claimed_session_id, task_id),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback(); raise
        return self.get_specialist_task(task_id)

    def heartbeat_specialist_task(self, task_id: int, *, lease_owner: str, lease_seconds: int = 120) -> dict:
        now = datetime.now(timezone.utc); expires = now + timedelta(seconds=max(15, min(lease_seconds, 600)))
        with self._lock:
            cur = self._conn.execute(
                "UPDATE specialist_task_lease SET heartbeat_at=?,expires_at=? WHERE task_id=? AND lease_owner=?",
                (now.isoformat(), expires.isoformat(), task_id, lease_owner),
            )
            if cur.rowcount != 1:
                raise StateError("specialist task lease is missing or owned by another worker")
            self._conn.commit()
        return self.get_specialist_task(task_id)

    def update_specialist_task(
        self, task_id: int, *, status: str, result_summary: str = "",
        result_refs: list[str] | None = None, tokens: int = 0, cost: float = 0,
        duration_ms: int = 0, claimed_session_id: int | None = None,
        error: str = "", model: str = "", runtime: str = "",
        metadata: dict | None = None,
    ) -> dict:
        allowed = {"PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}
        if status not in allowed:
            raise StateError(f"invalid specialist task status: {status}")
        row = self._fetch("specialist_task", task_id)
        transitions = {
            "PENDING": {"RUNNING", "CANCELLED"},
            "RUNNING": {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"},
            "COMPLETED": set(), "FAILED": set(), "CANCELLED": set(), "TIMED_OUT": set(),
        }
        if status != row["status"] and status not in transitions.get(row["status"], set()):
            raise StateError(f"invalid specialist task transition: {row['status']} -> {status}")
        if claimed_session_id is not None:
            claimed = self.require_session(claimed_session_id, running=status == "RUNNING")
            if claimed.agent_role != row["assigned_role"]:
                raise StateError("claimed specialist session role does not match assigned role")
        merged = _jload(row["metadata"], {}); merged.update(metadata or {})
        started = row["started_at"] or (utcnow() if status == "RUNNING" else None)
        completed = utcnow() if status in {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"} else None
        with self._lock:
            self._conn.execute(
                "UPDATE specialist_task SET status=?,result_summary=?,result_refs=?,started_at=?,completed_at=?,tokens=?,cost=?,duration_ms=?,claimed_session_id=COALESCE(?,claimed_session_id),error=?,model=?,runtime=?,metadata=? WHERE id=?",
                (status, result_summary, _jdump(result_refs or []), started, completed,
                 max(0, tokens), max(0.0, cost), max(0, duration_ms), claimed_session_id,
                error[:2000], model[:200], runtime[:100], _jdump(merged), task_id),
            )
            if status in {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}:
                self._conn.execute("DELETE FROM specialist_task_lease WHERE task_id=?", (task_id,))
            self._conn.commit(); updated = self._fetch("specialist_task", task_id)
        return self._telemetry_row("specialist_task", updated)

    @staticmethod
    def _telemetry_row(entity: str, row: sqlite3.Row) -> dict:
        item = dict(row); item["public_id"] = HuntDB.public_id(entity, int(row["id"]))
        for field in ("metadata", "result_refs", "skills_loaded"):
            if field in item:
                item[field] = _jload(item[field], {} if field == "metadata" else [])
        return item

    def list_specialist_tasks(self, autonomy_run_id: int | None = None) -> list[dict]:
        query, args = "SELECT * FROM specialist_task", []
        if autonomy_run_id is not None:
            query += " WHERE autonomy_run_id=?"; args.append(autonomy_run_id)
        query += " ORDER BY id DESC"
        with self._lock:
            rows = self._conn.execute(query, tuple(args)).fetchall()
        return [self._telemetry_row("specialist_task", row) for row in rows]

    def hunt_metrics(self, autonomy_run_id: int) -> dict:
        run = self.get_autonomy_run(autonomy_run_id)
        activities = self.list_autonomy_activities(run.id)
        activity_counts: dict[str, int] = {}
        for item in activities:
            activity_counts[item.activity_type] = activity_counts.get(item.activity_type, 0) + 1
        with self._lock:
            turns = self._conn.execute(
                "SELECT COUNT(*) n,COALESCE(SUM(input_tokens+output_tokens),0) tokens,"
                "COALESCE(SUM(cached_tokens),0) cached_tokens,COALESCE(SUM(estimated_cost),0) cost "
                "FROM agent_turn WHERE autonomy_run_id=?", (run.id,),
            ).fetchone()
            tools = self._conn.execute(
                "SELECT COUNT(*) n,COALESCE(SUM(CASE WHEN success=0 THEN 1 ELSE 0 END),0) errors FROM tool_call WHERE autonomy_run_id=?", (run.id,),
            ).fetchone()
            specialists = self._conn.execute(
                "SELECT COUNT(*) n FROM specialist_task WHERE autonomy_run_id=?", (run.id,),
            ).fetchone()
            skill_rows = self._conn.execute(
                "SELECT skill,COUNT(*) n FROM skill_usage WHERE autonomy_run_id=? GROUP BY skill ORDER BY n DESC,skill",
                (run.id,),
            ).fetchall()
            approvals = self._conn.execute(
                "SELECT COUNT(*) n FROM approval WHERE autonomy_run_id=?", (run.id,),
            ).fetchone()
            hypotheses = self._conn.execute(
                "SELECT status,COUNT(*) n FROM hypothesis GROUP BY status",
            ).fetchall()
            source_runs = self._conn.execute(
                "SELECT COUNT(*) n FROM source_analysis_run",
            ).fetchone()
        findings = self.list_findings()
        requests = activity_counts.get("REQUEST_SENT", 0)
        candidates = sum(f.status not in {"killed", "rejected"} for f in findings)
        validated = sum(f.status in {"validated", "poc_ready", "scored", "report_ready", "qa_passed"} for f in findings)
        return {
            "run": run.public_id, "status": run.status, "duration_minutes": run.usage.get("elapsed_minutes", 0),
            "requests": requests, "leads_considered": activity_counts.get("LEAD_VISITED", 0),
            "hypotheses": activity_counts.get("HYPOTHESIS_CREATED", 0),
            "tests": activity_counts.get("TEST_EXECUTED", 0),
            "rejected_hypotheses": sum(row["n"] for row in hypotheses if row["status"] == "rejected"),
            "inconclusive_hypotheses": sum(row["n"] for row in hypotheses if row["status"] == "inconclusive"),
            "source_analyses": source_runs["n"],
            "candidates": candidates, "validator_kills": sum(f.status == "killed" for f in findings),
            "validated_findings": validated,
            "request_per_candidate": round(requests / candidates, 2) if candidates else None,
            "request_per_validated": round(requests / validated, 2) if validated else None,
            "agent_turns": turns["n"], "tokens": turns["tokens"],
            "cached_tokens": turns["cached_tokens"], "cost": turns["cost"],
            "specialist_tasks": specialists["n"], "tool_calls": tools["n"], "tool_errors": tools["errors"],
            "ask_pauses": approvals["n"], "stop_reason": run.stop_reason,
            "usage_availability": "AVAILABLE" if turns["n"] and turns["tokens"] else (
                "PARTIAL" if turns["n"] else "UNAVAILABLE"
            ),
            "skill_usage_events": sum(row["n"] for row in skill_rows),
            "skills_used": [row["skill"] for row in skill_rows],
        }

    def start_agent_turn(
        self, *, session_id: int, role: str, runtime: str = "", model: str = "",
        autonomy_run_id: int | None = None, specialist_task_id: int | None = None,
        skills_loaded: list[str] | None = None, tools_available_count: int = 0,
        metadata: dict | None = None,
    ) -> dict:
        self.require_session(session_id)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO agent_turn(autonomy_run_id,session_id,role,specialist_task_id,model,runtime,started_at,skills_loaded,tools_available_count,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (autonomy_run_id, session_id, role, specialist_task_id, model, runtime,
                 utcnow(), _jdump(skills_loaded or []), max(0, tools_available_count),
                 _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("agent_turn", int(cur.lastrowid))
        return self._telemetry_row("agent_turn", row)

    def active_agent_turn(self, session_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agent_turn WHERE session_id=? AND completed_at IS NULL ORDER BY id DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        return self._telemetry_row("agent_turn", row) if row is not None else None

    def latest_agent_turn(self, session_id: int) -> dict | None:
        """Return the latest turn even after a runtime hook completed it.

        Wrappers that receive provider usage only when the model process exits
        use this to reconcile authoritative token/cost totals without storing
        the model transcript.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agent_turn WHERE session_id=? ORDER BY id DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        return self._telemetry_row("agent_turn", row) if row is not None else None

    def complete_agent_turn(
        self, turn_id: int, *, latency_ms: int = 0, input_tokens: int = 0,
        output_tokens: int = 0, cached_tokens: int = 0, estimated_cost: float = 0,
        outcome: str = "", error: str = "", metadata: dict | None = None,
    ) -> dict:
        row = self._fetch("agent_turn", turn_id)
        merged = _jload(row["metadata"], {}); merged.update(metadata or {})
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) n FROM tool_call WHERE agent_turn_id=?", (turn_id,)).fetchone()["n"]
            self._conn.execute(
                "UPDATE agent_turn SET completed_at=?,latency_ms=?,input_tokens=?,output_tokens=?,cached_tokens=?,estimated_cost=?,tool_calls_count=?,outcome=?,error=?,metadata=? WHERE id=?",
                (utcnow(), max(0, latency_ms), max(0, input_tokens), max(0, output_tokens),
                 max(0, cached_tokens), max(0.0, estimated_cost), count, outcome,
                 error[:1000], _jdump(merged), turn_id),
            )
            self._conn.commit(); updated = self._fetch("agent_turn", turn_id)
        return self._telemetry_row("agent_turn", updated)

    def record_tool_call(
        self, *, session_id: int, role: str, tool: str, success: bool,
        agent_turn_id: int | None = None, autonomy_run_id: int | None = None,
        latency_ms: int = 0, error_class: str = "", metadata: dict | None = None,
    ) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO tool_call(agent_turn_id,autonomy_run_id,session_id,role,tool,started_at,completed_at,latency_ms,success,error_class,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (agent_turn_id, autonomy_run_id, session_id, role, tool, utcnow(), utcnow(),
                 max(0, latency_ms), int(success), error_class[:200], _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("tool_call", int(cur.lastrowid))
        return self._telemetry_row("tool_call", row)

    def start_tool_call(
        self, *, invocation_id: str, session_id: int, role: str, tool: str,
        agent_turn_id: int | None = None, autonomy_run_id: int | None = None,
        lead_id: int | None = None, hypothesis_id: int | None = None,
        test_id: int | None = None, source_analysis_run_id: int | None = None,
        specialist_task_id: int | None = None, metadata: dict | None = None,
    ) -> dict:
        if not invocation_id.strip():
            raise StateError("tool invocation_id is required")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO tool_call(agent_turn_id,autonomy_run_id,session_id,role,tool,started_at,success,invocation_id,lead_id,hypothesis_id,test_id,source_analysis_run_id,specialist_task_id,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (agent_turn_id, autonomy_run_id, session_id, role, tool, utcnow(), 0,
                 invocation_id[:200], lead_id, hypothesis_id, test_id,
                 source_analysis_run_id, specialist_task_id, _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("tool_call", int(cur.lastrowid))
        return self._telemetry_row("tool_call", row)

    def complete_tool_call(
        self, invocation_id: str, *, success: bool, latency_ms: int,
        error_class: str = "", result_summary: str = "", metadata: dict | None = None,
    ) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tool_call WHERE invocation_id=?", (invocation_id,),
            ).fetchone()
            if row is None:
                raise StateError(f"tool invocation {invocation_id!r} not found")
            merged = _jload(row["metadata"], {}); merged.update(metadata or {})
            self._conn.execute(
                "UPDATE tool_call SET completed_at=?,latency_ms=?,success=?,error_class=?,result_summary=?,metadata=? WHERE id=?",
                (utcnow(), max(0, latency_ms), int(success), error_class[:200],
                 result_summary[:1000], _jdump(merged), row["id"]),
            )
            self._conn.commit(); updated = self._fetch("tool_call", int(row["id"]))
        return self._telemetry_row("tool_call", updated)

    def record_skill_usage(
        self, *, session_id: int, role: str, skill: str,
        autonomy_run_id: int | None = None, specialist_task_id: int | None = None,
        lead_id: int | None = None, hypothesis_id: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO skill_usage(autonomy_run_id,session_id,specialist_task_id,skill,role,lead_id,hypothesis_id,activated_at,metadata) VALUES(?,?,?,?,?,?,?,?,?)",
                (autonomy_run_id, session_id, specialist_task_id, skill, role, lead_id,
                 hypothesis_id, utcnow(), _jdump(metadata or {})),
            )
            self._conn.commit(); row = self._fetch("skill_usage", int(cur.lastrowid))
        return self._telemetry_row("skill_usage", row)

    def update_surface_score(self, entity_type: str, entity_id: int, score: int, reasons: list[str], metadata_updates: dict | None = None) -> None:
        table = {"asset": "asset", "endpoint": "endpoint"}.get(entity_type)
        if table is None: raise StateError(f"unsupported scored entity: {entity_type}")
        row = self._fetch(table, entity_id); metadata = _jload(row["metadata"], {})
        metadata["interest_reasons"] = list(reasons)
        metadata.update(metadata_updates or {})
        with self._lock:
            self._conn.execute(f"UPDATE {table} SET interest_score=?,interesting=?,metadata=? WHERE id=?", (max(0, min(int(score), 100)), int(score >= 40), _jdump(metadata), entity_id))
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #
    def _fetch(self, table: str, rowid: int) -> sqlite3.Row:
        with self._lock:
            row = self._conn.execute(f"SELECT * FROM {table} WHERE id=?", (rowid,)).fetchone()
        if row is None:
            raise StateError(f"{table} id={rowid} not found")
        return row

    @staticmethod
    def _ref_id(ref: str, prefix: str) -> int:
        raw = str(ref).strip()
        if raw.upper().startswith(prefix + "-"):
            raw = raw.split("-", 1)[1]
        if not raw.isdigit():
            raise StateError(f"invalid {prefix} reference: {ref!r}")
        return int(raw)

    def _require_evidence_refs(self, refs: list[str]) -> None:
        for ref in refs:
            self.get_evidence(self._ref_id(ref, "EVD"))

    def _validate_finding_links(
        self, *, lead_id: int | None, hypothesis_id: int | None,
        test_ids: list[int], evidence_refs: list[str], require_complete: bool,
    ) -> str:
        complete = all((lead_id is not None, hypothesis_id is not None, bool(test_ids), bool(evidence_refs)))
        if require_complete and not complete:
            raise StateError("finding linkage is incomplete (lead, hypothesis, tests, and evidence are required)")
        if lead_id is not None:
            self.get_lead(lead_id)
        if hypothesis_id is not None:
            hyp = self.get_hypothesis(hypothesis_id)
            if lead_id is None or hyp.lead_id != lead_id:
                raise StateError("finding hypothesis does not belong to finding lead")
        linked_tests: list[ResearchTestRecord] = []
        for test_id in test_ids:
            test = self.get_test(test_id)
            if hypothesis_id is None or test.hypothesis_id != hypothesis_id:
                raise StateError("finding test does not belong to finding hypothesis")
            linked_tests.append(test)
        self._require_evidence_refs(evidence_refs)
        if complete:
            linked_evidence = set(evidence_refs)
            supported = [t for t in linked_tests if t.result == "supports"]
            if require_complete and not supported:
                raise StateError("finding has no linked supporting test")
            if require_complete and not any(linked_evidence.intersection(t.evidence_refs) for t in supported):
                raise StateError("finding evidence is not linked to a supporting finding test")
            return "complete"
        return "legacy_incomplete"

    def _validate_review_payload(
        self, *, verdict: str, checks: dict, evidence_refs: list[str], finding: FindingRecord,
    ) -> None:
        required_boolean = {
            "scope_eligible", "reproducible", "intended_behavior",
            "false_positive_analysis", "evidence_quality", "minimal_impact",
            "program_exclusions",
        }
        required_value = {
            "prerequisites", "security_boundary", "attacker_control", "demonstrated_impact",
        }
        missing = (required_boolean | required_value) - set(checks)
        if missing:
            raise StateError(f"validation review missing required checks: {sorted(missing)}")
        if verdict == VR_SUPPORTED:
            for name in required_boolean:
                item = checks.get(name)
                if not isinstance(item, dict) or item.get("passed") is not True:
                    raise StateError(f"supported review requires {name}.passed=true")
            for name in required_value:
                item = checks.get(name)
                if not isinstance(item, dict) or not str(item.get("value", "")).strip():
                    raise StateError(f"supported review requires a non-empty {name}.value")
            if not str(checks["demonstrated_impact"].get("value", "")).strip():
                raise StateError("supported review requires demonstrated impact")
        if not set(evidence_refs).issubset(set(finding.evidence_refs)):
            raise StateError("validation review may reference only evidence linked to this finding")
        if verdict == VR_SUPPORTED and not evidence_refs:
            raise StateError("supported validation review requires finding-linked evidence")

    def _current_status(self, table: str, rowid: int) -> str:
        with self._lock:
            row = self._conn.execute(f"SELECT status FROM {table} WHERE id=?", (rowid,)).fetchone()
        if row is None:
            raise StateError(f"{table} id={rowid} not found")
        return row["status"]

    def _transition(self, entity: str, rowid: int, new_status: str) -> None:
        current = self._current_status(entity, rowid)
        validate_transition(entity, current, new_status)

    def _update_fields(self, table: str, rowid: int, fields: dict) -> None:
        # find the status/timestamp columns to avoid clobbering transitions
        allowed = {
            "lead": {"title", "entity", "source", "priority", "rationale"},
            "hypothesis": {"statement", "rationale", "confidence", "lead_id"},
            "finding": {"title", "affected_target", "category", "impact_summary", "evidence_refs", "report_path", "poc_path", "lead_id", "hypothesis_id", "test_ids", "linkage_state"},
            "recon_run": {
                "status", "completed_at", "tools_used", "raw_observation_count",
                "new_asset_count", "updated_asset_count", "new_endpoint_count",
                "lead_count", "error_count", "artifact_refs", "metadata",
            },
        }.get(table, set())
        clean = {k: v for k, v in fields.items() if k in allowed}
        if table in ("lead", "hypothesis", "finding"):
            clean["updated_at"] = utcnow()
        if clean:
            cols = ", ".join(f"{k}=?" for k in clean)
            with self._lock:
                self._conn.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*clean.values(), rowid))
                self._conn.commit()


def open_hunt_db(workspace: Path, program_slug: str) -> HuntDB:
    return HuntDB(workspace / "state" / "hunt.db", program_slug=program_slug)
