"""Entity status/result constants and the research state machine.

The state machine enforces the canonical research loop (spec §14).  Agents are
not permitted to jump straight from observation to a validated finding: each
transition must be explicitly recorded and validated here.
"""

from __future__ import annotations

from ..errors import InvalidTransitionError

# --- lead ----------------------------------------------------------------
LEAD_OPEN = "open"
LEAD_CLAIMED = "claimed"
LEAD_CLOSED = "closed"
LEAD_STATUSES = frozenset({LEAD_OPEN, LEAD_CLAIMED, LEAD_CLOSED})

# --- hypothesis ----------------------------------------------------------
HYPO_OPEN = "open"
HYPO_TESTING = "testing"
HYPO_SUPPORTED = "supported"
HYPO_REJECTED = "rejected"
HYPO_INCONCLUSIVE = "inconclusive"
HYPO_CANDIDATE = "candidate"
HYPOTHESIS_STATUSES = frozenset(
    {HYPO_OPEN, HYPO_TESTING, HYPO_SUPPORTED, HYPO_REJECTED, HYPO_INCONCLUSIVE, HYPO_CANDIDATE}
)

# --- research_test -------------------------------------------------------
TEST_PLANNED = "planned"
TEST_EXECUTED = "executed"
TEST_STATUSES = frozenset({TEST_PLANNED, TEST_EXECUTED})

RESULT_SUPPORTS = "supports"
RESULT_REJECTS = "rejects"
RESULT_INCONCLUSIVE = "inconclusive"
TEST_RESULTS = frozenset({RESULT_SUPPORTS, RESULT_REJECTS, RESULT_INCONCLUSIVE})

# --- evidence kinds ------------------------------------------------------
EVIDENCE_TEXT = "text"
EVIDENCE_REQUEST_RESPONSE = "request_response"
EVIDENCE_COMMAND_OUTPUT = "command_output"
EVIDENCE_SCREENSHOT = "screenshot_reference"
EVIDENCE_FILE = "file_reference"
EVIDENCE_OBSERVATION = "observation"
EVIDENCE_KINDS = frozenset(
    {
        EVIDENCE_TEXT,
        EVIDENCE_REQUEST_RESPONSE,
        EVIDENCE_COMMAND_OUTPUT,
        EVIDENCE_SCREENSHOT,
        EVIDENCE_FILE,
        EVIDENCE_OBSERVATION,
    }
)

# --- finding pipeline (spec §14) ----------------------------------------
FINDING_CANDIDATE = "candidate"
FINDING_VALIDATION = "validation"
FINDING_KILLED = "killed"
FINDING_VALIDATED = "validated"
FINDING_POC_READY = "poc_ready"
FINDING_SCORED = "scored"
FINDING_REPORT_READY = "report_ready"
FINDING_QA_PASSED = "qa_passed"
FINDING_HUMAN_APPROVED = "human_approved"
FINDING_REJECTED = "rejected"
FINDING_STATUSES = frozenset(
    {
        FINDING_CANDIDATE,
        FINDING_VALIDATION,
        FINDING_KILLED,
        FINDING_VALIDATED,
        FINDING_POC_READY,
        FINDING_SCORED,
        FINDING_REPORT_READY,
        FINDING_QA_PASSED,
        FINDING_HUMAN_APPROVED,
        FINDING_REJECTED,
    }
)

# --- session / approval --------------------------------------------------
SESSION_RUNNING = "running"
SESSION_ENDED = "ended"
SESSION_STATUSES = frozenset({SESSION_RUNNING, SESSION_ENDED})

APPROVAL_PENDING = "pending"
APPROVAL_APPROVED = "approved"
APPROVAL_REJECTED = "rejected"
APPROVAL_EXPIRED = "expired"
APPROVAL_CONSUMED = "consumed"
APPROVAL_STATUSES = frozenset(
    {APPROVAL_PENDING, APPROVAL_APPROVED, APPROVAL_REJECTED, APPROVAL_EXPIRED, APPROVAL_CONSUMED}
)

# --- validation review (finding validation provenance) --------------------
VREVIEW_OPEN = "open"
VREVIEW_SUBMITTED = "submitted"
VREVIEW_STATUSES = frozenset({VREVIEW_OPEN, VREVIEW_SUBMITTED})

VR_SUPPORTED = "supported"
VR_REJECTED = "rejected"
VR_INCONCLUSIVE = "inconclusive"
VR_VERDICTS = frozenset({VR_SUPPORTED, VR_REJECTED, VR_INCONCLUSIVE})

# --- transition maps (directed) -----------------------------------------
TRANSITIONS: dict[str, dict[str, frozenset[str]]] = {
    "lead": {
        LEAD_OPEN: frozenset({LEAD_CLAIMED}),
        LEAD_CLAIMED: frozenset({LEAD_OPEN, LEAD_CLOSED}),
        # A durable, meaningful ReconChange may explicitly requeue an exhausted
        # Lead; ordinary callers still cannot mutate status through update.
        LEAD_CLOSED: frozenset({LEAD_OPEN}),
    },
    "hypothesis": {
        HYPO_OPEN: frozenset({HYPO_TESTING, HYPO_REJECTED, HYPO_INCONCLUSIVE}),
        HYPO_TESTING: frozenset({HYPO_SUPPORTED, HYPO_REJECTED, HYPO_INCONCLUSIVE, HYPO_CANDIDATE}),
        HYPO_SUPPORTED: frozenset({HYPO_CANDIDATE, HYPO_REJECTED}),
        HYPO_INCONCLUSIVE: frozenset({HYPO_OPEN, HYPO_TESTING, HYPO_REJECTED}),
        HYPO_CANDIDATE: frozenset({HYPO_SUPPORTED, HYPO_REJECTED}),
        HYPO_REJECTED: frozenset(),
    },
    "research_test": {
        TEST_PLANNED: frozenset({TEST_EXECUTED}),
        TEST_EXECUTED: frozenset(),
    },
    "finding": {
        FINDING_CANDIDATE: frozenset({FINDING_VALIDATION, FINDING_REJECTED}),
        FINDING_VALIDATION: frozenset({FINDING_KILLED, FINDING_VALIDATED, FINDING_REJECTED}),
        FINDING_VALIDATED: frozenset({FINDING_POC_READY, FINDING_KILLED, FINDING_REJECTED}),
        FINDING_POC_READY: frozenset({FINDING_SCORED, FINDING_REJECTED}),
        FINDING_SCORED: frozenset({FINDING_REPORT_READY, FINDING_REJECTED}),
        FINDING_REPORT_READY: frozenset({FINDING_QA_PASSED, FINDING_REJECTED}),
        FINDING_QA_PASSED: frozenset({FINDING_HUMAN_APPROVED, FINDING_REJECTED}),
        FINDING_HUMAN_APPROVED: frozenset(),
        FINDING_KILLED: frozenset(),
        FINDING_REJECTED: frozenset(),
    },
    "session": {
        SESSION_RUNNING: frozenset({SESSION_ENDED}),
        SESSION_ENDED: frozenset(),
    },
    "approval": {
        APPROVAL_PENDING: frozenset({APPROVAL_APPROVED, APPROVAL_REJECTED, APPROVAL_EXPIRED}),
        APPROVAL_APPROVED: frozenset({APPROVAL_CONSUMED, APPROVAL_EXPIRED}),
        APPROVAL_REJECTED: frozenset(),
        APPROVAL_EXPIRED: frozenset(),
        APPROVAL_CONSUMED: frozenset(),
    },
}


def validate_transition(entity: str, from_status: str, to_status: str) -> bool:
    """Return True iff ``to_status`` is reachable from ``from_status`` for ``entity``.

    Raises InvalidTransitionError otherwise.
    """
    table = TRANSITIONS.get(entity)
    if table is None:
        raise InvalidTransitionError(f"unknown entity for transitions: {entity}")
    allowed = table.get(from_status)
    if allowed is None:
        raise InvalidTransitionError(f"unknown status {from_status!r} for entity {entity}")
    if to_status not in allowed:
        raise InvalidTransitionError(
            f"illegal {entity} transition: {from_status!r} -> {to_status!r}"
        )
    return True


__all__ = [
    "LEAD_OPEN",
    "LEAD_CLAIMED",
    "LEAD_CLOSED",
    "HYPO_OPEN",
    "HYPO_TESTING",
    "HYPO_SUPPORTED",
    "HYPO_REJECTED",
    "HYPO_INCONCLUSIVE",
    "HYPO_CANDIDATE",
    "TEST_PLANNED",
    "TEST_EXECUTED",
    "RESULT_SUPPORTS",
    "RESULT_REJECTS",
    "RESULT_INCONCLUSIVE",
    "FINDING_CANDIDATE",
    "FINDING_VALIDATION",
    "FINDING_KILLED",
    "FINDING_VALIDATED",
    "FINDING_POC_READY",
    "FINDING_SCORED",
    "FINDING_REPORT_READY",
    "FINDING_QA_PASSED",
    "FINDING_HUMAN_APPROVED",
    "FINDING_REJECTED",
    "SESSION_RUNNING",
    "SESSION_ENDED",
    "APPROVAL_PENDING",
    "APPROVAL_APPROVED",
    "APPROVAL_REJECTED",
    "APPROVAL_EXPIRED",
    "APPROVAL_CONSUMED",
    "VREVIEW_OPEN",
    "VREVIEW_SUBMITTED",
    "VR_SUPPORTED",
    "VR_REJECTED",
    "VR_INCONCLUSIVE",
    "TRANSITIONS",
    "validate_transition",
]
