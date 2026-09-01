"""Portable AI Bug Hunting Harness.

A program-isolated, hypothesis-driven, evidence-gated research operating
environment that runs interchangeable AI research runtimes (Claude Code,
Codex, OpenCode) over the same methodology, skills, scope, and state.
"""

__version__ = "0.3.0"

# Version of the on-disk research-state schema. Bump when migrations change.
#   v1 = baseline (original schema)
#   v2 = approval audit fields + finding linkage + validation_review + auth_context
#        + rate_limit + request_record tables
#   v3 = autonomous runs, leases, and stronger provenance/security-principal links
#   v4 = persistent normalized recon runs, assets, endpoints, parameters, technology, changes
#   v6 = program intake imports, sources, ambiguities, approvals, and audit log
#   v7 = commit-pinned source repositories, observations, analysis runs, and
#        source-to-runtime mappings
#   v8 = source security models/symbols/invariants, run-scoped approvals,
#        specialist handoffs, and lightweight agent/tool/skill telemetry
#   v9 = executable specialist lifecycle and correlated tool invocation spans
STATE_SCHEMA_VERSION = 10
