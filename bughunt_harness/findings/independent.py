"""Launch an independent, role-bound validator runtime for one candidate.

The researcher process cannot submit a supported ValidationReview because its
session role is not ``finding-validator``.  This launcher creates a distinct
session, gives a fresh Claude process a narrow MCP configuration, and lets the
deterministic finalizer apply only a submitted structured review.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from ..errors import StateError


def _validator_mcp_config(ctx, session_id: int) -> Path:
    from ..adapters.base import REPO_ROOT

    directory = ctx.workspace / "state" / "validator-runtime"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"SES-{session_id:03d}.mcp.json"
    path.write_text(json.dumps({
        "mcpServers": {
            "bughunt": {
                "command": str(REPO_ROOT / "harness"),
                "args": ["mcp", "serve"],
                "env": {
                    "BUGHUNT_PROGRAM": ctx.slug,
                    "BUGHUNT_SESSION_ID": str(session_id),
                    "BUGHUNT_AGENT_ROLE": "finding-validator",
                },
            },
        },
    }, indent=2) + "\n", encoding="utf-8")
    return path


def run_independent_validator(
    ctx, finding_id: int, *, runtime: str = "claude", timeout_seconds: int = 600,
) -> dict:
    """Run one independent validator and deterministically apply its verdict."""
    if runtime != "claude":
        raise StateError("independent autonomous validation currently requires Claude Code")
    finding = ctx.db.get_finding(finding_id)
    if finding.status == "candidate":
        ctx.db.transition_finding(finding.id, "validation")
        finding = ctx.db.get_finding(finding.id)
    if finding.status != "validation":
        raise StateError(f"finding must be candidate/validation, is {finding.status!r}")
    review = ctx.db.latest_validation_review(finding.id)
    if review is not None and review.status == "submitted":
        # Crash/budget recovery: the independent session already crossed the
        # durable schema gate. Apply that exact review instead of paying for a
        # duplicate validator or leaving the Finding stranded in validation.
        result = ctx.db.finalize_validation(
            finding.id, scope_engine=ctx.scope, program_active=ctx.record.status == "active",
        )
        reviewer = (
            ctx.db.get_session(review.reviewer_session_id).public_id
            if review.reviewer_session_id is not None else ""
        )
        return {
            "finding": result.public_id, "status": result.status,
            "review": review.public_id, "verdict": review.verdict,
            "validator_session": reviewer, "recovered_submitted_review": True,
        }
    binary = shutil.which("claude")
    if not binary:
        raise StateError("Claude Code is not installed")
    if review is None or review.status != "open":
        review = ctx.db.begin_validation(
            finding.id, requested_by="autonomous-researcher",
            reviewer_type="finding-validator",
        )
    validator = ctx.db.start_session(runtime, "finding-validator", ctx.slug)
    if finding.creator_session_id == validator.id:
        raise StateError("validator session unexpectedly equals creator session")
    config = _validator_mcp_config(ctx, validator.id)
    env = os.environ.copy()
    # This is a deliberately separate non-interactive runtime, not a recursive
    # use of the creator's session. Remove parent-session markers before binding
    # the new validator identity below.
    env.pop("CLAUDECODE", None)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)
    env.update({
        "BUGHUNT_PROGRAM": ctx.slug,
        "BUGHUNT_SESSION_ID": str(validator.id),
        "BUGHUNT_AGENT_ROLE": "finding-validator",
    })
    prompt = (
        f"Independently validate {finding.public_id}. Read only its explicitly linked research "
        f"and engagement policy through Harness MCP. Attempt to disprove every required check. "
        f"Use at most one minimal controlled replay if indispensable. Submit exactly one structured "
        f"ValidationReview for {review.public_id}; do not create or modify the candidate and do not finalize it."
    )
    argv = [
        binary, "--print", "--agent", "finding-validator", "--add-dir", str(ctx.workspace),
        "--mcp-config", str(config), "--strict-mcp-config",
        "--tools", "", "--allowedTools", "mcp__bughunt__*",
        "--permission-mode", "dontAsk", "--max-budget-usd",
        os.environ.get("BUGHUNT_VALIDATOR_MAX_USD", "1.00"), prompt,
    ]
    try:
        completed = subprocess.run(
            argv, cwd=str(Path(__file__).resolve().parents[2]), env=env,
            capture_output=True, text=True, timeout=timeout_seconds, check=False,
        )
        submitted = ctx.db.latest_validation_review(finding.id)
        if submitted is None or submitted.id != review.id or submitted.status != "submitted":
            if completed.returncode != 0:
                raise StateError(
                    f"independent validator exited {completed.returncode} without a submitted review: "
                    f"{(completed.stderr or 'no diagnostic').strip()[:500]}"
                )
            raise StateError("independent validator returned without a submitted structured review")
        result = ctx.db.finalize_validation(
            finding.id, scope_engine=ctx.scope, program_active=ctx.record.status == "active",
        )
        response = {
            "finding": result.public_id, "status": result.status,
            "review": submitted.public_id, "verdict": submitted.verdict,
            "validator_session": validator.public_id,
        }
        if completed.returncode != 0:
            # The durable, schema-validated review was submitted by the exact
            # independent session before the provider terminated.  Preserve
            # that verdict and surface the post-submission runtime condition
            # rather than opening another review/retrying indefinitely.
            response["runtime_warning"] = (
                f"validator exited {completed.returncode} after submitting {submitted.public_id}"
            )
        return response
    finally:
        if ctx.db.get_session(validator.id).status == "running":
            ctx.db.end_session(validator.id)


__all__ = ["run_independent_validator"]
