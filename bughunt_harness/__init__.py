"""Portable AI Bug Hunting Harness.

A program-isolated, hypothesis-driven, evidence-gated research operating
environment that runs interchangeable AI research runtimes (Claude Code,
Codex, OpenCode) over the same methodology, skills, scope, and state.
"""

__version__ = "0.1.0"

# Version of the on-disk research-state schema. Bump when migrations change.
#   v1 = baseline (original schema)
#   v2 = approval audit fields + finding linkage + validation_review + auth_context
#        + rate_limit + request_record tables
STATE_SCHEMA_VERSION = 2