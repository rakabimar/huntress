"""Per-program SQLite research state (HuntDB), records, and state machine."""

from .db import HuntDB, open_hunt_db
from .records import (
    SessionRecord,
    LeadRecord,
    HypothesisRecord,
    ResearchTestRecord,
    EvidenceRecord,
    FindingRecord,
    CheckpointRecord,
    AgentActionRecord,
    ApprovalRecord,
)
from . import constants as C
from .constants import validate_transition

__all__ = [
    "HuntDB",
    "open_hunt_db",
    "SessionRecord",
    "LeadRecord",
    "HypothesisRecord",
    "ResearchTestRecord",
    "EvidenceRecord",
    "FindingRecord",
    "CheckpointRecord",
    "AgentActionRecord",
    "ApprovalRecord",
    "C",
    "validate_transition",
]