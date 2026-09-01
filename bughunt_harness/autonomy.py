"""Bounded autonomous-hunt lifecycle and truthful state checkpoints.

The model chooses research hypotheses; this module owns the non-model control
plane: immutable session binding, hard budget accounting, stop decisions, and
durable resume state.  It deliberately contains no exploit logic.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .errors import StateError

if TYPE_CHECKING:  # pragma: no cover
    from .hunt import ProgramContext
    from .state.records import AutonomyRunRecord, CheckpointRecord


GOAL_STATUSES = {
    "validated_finding": {"validated", "poc_ready", "scored", "report_ready", "qa_passed"},
    "validated": {"validated", "poc_ready", "scored", "report_ready", "qa_passed"},
    "poc_ready": {"poc_ready", "scored", "report_ready", "qa_passed"},
    "scored": {"scored", "report_ready", "qa_passed"},
    "report_ready": {"report_ready", "qa_passed"},
    "qa_passed": {"qa_passed"},
    "budget_exhausted": set(),
}


def _lead_rank(ctx, lead) -> tuple[float, int]:
    """Explainable bounded bonuses; never touches policy or safety controls."""
    from .learning import ProgramLearning
    base = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}.get(lead.priority, 50.0)
    new_surface = 5.0 if lead.source in {"recon", "recon-watch", "javascript"} else 0.0
    coverage = 0.0
    if str(lead.entity).startswith("endpoint:"):
        try:
            endpoint_id = int(str(lead.entity).split(":", 1)[1])
            row = ctx.db._conn.execute(
                "SELECT state FROM coverage_observation WHERE endpoint_id=? ORDER BY id DESC LIMIT 1",
                (endpoint_id,),
            ).fetchone()
            coverage = 10.0 if row is None or row["state"] in {"DISCOVERED", "STALE_AFTER_CHANGE", "CHANGED_SINCE_TEST"} else 0.0
        except ValueError:
            pass
    explained = ProgramLearning(ctx.db).explain_score(
        base, new_surface_bonus=new_surface, coverage_bonus=coverage,
        signal=lead.source, skill="", specialist="", surface_type="",
    )
    return float(explained["total"]), -lead.id


def budget_dict(ctx: "ProgramContext") -> dict:
    data = ctx.engagement.autonomy.model_dump(
        exclude={"enabled", "goal", "stop_on_validated_finding", "auto_prepare_outputs"},
    )
    data["max_leads_per_run"] = (
        data.get("max_leads_per_run") or data.get("max_leads_per_session", 20)
    )
    return data


def start_autonomous_hunt(
    ctx: "ProgramContext", session_id: int, *, goal: str | None = None,
) -> "AutonomyRunRecord":
    """Start (or return) the run bound to an exact running session."""
    if not ctx.engagement.autonomy.enabled:
        raise StateError("autonomy.enabled is false; configure autonomy.yaml before autonomous hunting")
    selected = goal or ctx.engagement.autonomy.goal
    if selected not in GOAL_STATUSES:
        raise StateError(f"unsupported autonomy goal: {selected!r}")
    ctx.db.require_session(session_id, program_slug=ctx.slug, running=True)
    return ctx.db.start_autonomy_run(session_id, selected, budget_dict(ctx))


def _elapsed_minutes(started_at: str) -> float:
    started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - started).total_seconds() / 60.0)


def usage_snapshot(ctx: "ProgramContext", run: "AutonomyRunRecord") -> dict:
    activities = ctx.db.list_autonomy_activities(run.id)
    claimed_ids = {
        item.entity_id for item in activities
        if item.activity_type == "LEAD_VISITED" and item.entity_id is not None
    }
    per_lead: dict[str, int] = {}
    for item in activities:
        if item.activity_type == "HYPOTHESIS_CREATED" and item.metadata.get("lead_id") is not None:
            key = str(item.metadata["lead_id"])
            per_lead[key] = per_lead.get(key, 0) + 1
    inconclusive: dict[str, int] = {}
    failed: dict[str, int] = {}
    tests_per_hypothesis: dict[str, int] = {}
    for item in activities:
        if item.activity_type != "TEST_EXECUTED" or item.metadata.get("hypothesis_id") is None:
            continue
        key = str(item.metadata["hypothesis_id"])
        tests_per_hypothesis[key] = tests_per_hypothesis.get(key, 0) + 1
        if item.metadata.get("result") == "inconclusive":
            inconclusive[key] = inconclusive.get(key, 0) + 1
        elif item.metadata.get("result") == "rejects":
            failed[key] = failed.get(key, 0) + 1
    per_hypothesis_requests: dict[str, int] = {}
    request_count = 0
    for item in activities:
        if item.activity_type == "REQUEST_SENT":
            request_count += 1
        if item.activity_type == "REQUEST_SENT" and item.metadata.get("hypothesis_id") is not None:
            key = str(item.metadata["hypothesis_id"])
            per_hypothesis_requests[key] = per_hypothesis_requests.get(key, 0) + 1
    return {
        "elapsed_minutes": round(_elapsed_minutes(run.started_at), 3),
        "total_requests": request_count,
        "leads_claimed": len(claimed_ids),
        "leads_visited": len(claimed_ids),
        "hypotheses_per_lead": per_lead,
        "tests_per_hypothesis": tests_per_hypothesis,
        "requests_per_hypothesis": per_hypothesis_requests,
        "inconclusive_tests_per_hypothesis": inconclusive,
        "failed_tests_per_hypothesis": failed,
    }


def goal_reached(ctx: "ProgramContext", run: "AutonomyRunRecord") -> bool:
    # Compatibility flag is intentionally lower priority than later goals.
    if run.goal in {"validated_finding", "validated"} and ctx.engagement.autonomy.stop_on_validated_finding and any(
        finding.status in GOAL_STATUSES["validated_finding"]
        for finding in ctx.db.list_findings()
    ):
        return True
    wanted = GOAL_STATUSES[run.goal]
    return bool(wanted and any(f.status in wanted for f in ctx.db.list_findings()))


def budget_stop_reason(run: "AutonomyRunRecord", usage: dict) -> str | None:
    budget = run.budget
    scalar = (
        ("max_session_minutes", "elapsed_minutes"),
        ("max_total_requests", "total_requests"),
    )
    for limit_name, usage_name in scalar:
        if float(usage.get(usage_name, 0)) >= float(budget[limit_name]):
            return limit_name
    return None


def refresh_autonomy(ctx: "ProgramContext", session_id: int) -> dict:
    """Recompute usage and return the authoritative continue/stop decision."""
    run = ctx.db.active_autonomy_run(session_id)
    if run is None:
        raise StateError("no running autonomous hunt is bound to this session")
    if ctx.record.status != "active" or getattr(ctx, "intake_blocked", False):
        build_checkpoint_from_current_state(
            ctx, session_id, next_action="human review: program became inactive",
        )
        ctx.db.stop_autonomy_run(run.id, "program became inactive", "paused")
        return {"mode": "STOP", "reason": getattr(ctx, "intake_block_reason", "") or "program_inactive", "run": run.public_id}
    usage = usage_snapshot(ctx, run)
    run = ctx.db.update_autonomy_usage(run.id, usage)
    if goal_reached(ctx, run):
        build_checkpoint_from_current_state(ctx, session_id, next_action="review completed autonomous result")
        run = ctx.db.stop_autonomy_run(run.id, f"goal reached: {run.goal}", "goal_reached")
        return {"mode": "STOP", "reason": "goal_reached", "run": run.public_id, "usage": usage}
    reason = budget_stop_reason(run, usage)
    if reason:
        build_checkpoint_from_current_state(ctx, session_id, next_action=f"budget exhausted: {reason}")
        run = ctx.db.stop_autonomy_run(run.id, f"budget exhausted: {reason}", "budget_exhausted")
        return {"mode": "STOP", "reason": "budget_exhausted", "budget": reason, "run": run.public_id, "usage": usage}
    # ASK is scoped to the exact autonomous run.  An approval left pending by
    # an older session/run remains visible to humans but cannot pause this run.
    # Legacy unscoped rows fail safely: they authorize nothing and are ignored
    # here rather than silently corrupting new-run lifecycle semantics.
    pending = ctx.db.list_pending_approvals(
        autonomy_run_id=run.id, include_legacy_unscoped=False,
    )
    if pending:
        build_checkpoint_from_current_state(
            ctx, session_id, next_action=f"wait for approval {pending[0].public_id}",
            pending_approval_id=pending[0].id,
        )
        run = ctx.db.stop_autonomy_run(run.id, f"ASK pending: {pending[0].public_id}", "paused")
        return {"mode": "ASK", "reason": "approval_pending", "approval": pending[0].public_id, "run": run.public_id, "usage": usage}
    leads = ctx.db.list_leads()
    if hasattr(ctx, "policy") and not any(lead.status in {"open", "claimed"} for lead in leads):
        # Recon escalates incrementally and only through deterministic policy
        # gates. A run (including a partial one) counts as attempted so a
        # missing optional binary cannot cause a tight retry loop.
        from .recon import PROFILE_STAGES, STAGE_ACTION, recon_is_fresh, run_authorized_recon

        # A fresh completed profile can be reused across sessions.  A partial
        # or failed profile only suppresses retries in the current session, so
        # missing optional tools cannot create a tight loop while stale
        # inventory remains eligible for a later autonomous session.
        attempted = {
            item["profile"]
            for item in ctx.db.list_recon_runs(limit=100)
            if item["profile"]
            and (
                item.get("metadata", {}).get("session_id") == session_id
                or recon_is_fresh(ctx, item["profile"])
            )
        }
        for profile in ("passive", "light", "standard", "deep"):
            if profile in attempted:
                continue
            decisions = [ctx.policy.check(STAGE_ACTION[stage]).as_dict()["mode"] for stage in PROFILE_STAGES[profile]]
            if "DENY" in decisions:
                continue
            if "ASK" in decisions:
                hosts = ctx.db.list_assets(type="host", limit=1)
                if not hosts:
                    continue
                target = f"https://{hosts[0]['normalized_value']}"
                approval = ctx.db.request_approval(
                    "bounded_scan", target, requested_by="orchestrator",
                    note=f"bounded {profile} recon escalation after actionable Leads were exhausted",
                    program=ctx.slug, method="RECON", session_id=session_id,
                    constraints={
                        "recon_profile": profile, "max_requests": 500,
                        "targets": [target],
                        "max_concurrency": min(ctx.engagement.roe.max_concurrency, 10),
                        "duration_seconds": 900,
                    },
                )
                build_checkpoint_from_current_state(
                    ctx, session_id, next_action=f"request bounded approval before {profile} recon",
                    pending_approval_id=approval.id,
                )
                run = ctx.db.stop_autonomy_run(run.id, f"ASK pending: {approval.public_id}", "paused")
                return {"mode": "ASK", "reason": "recon_escalation_requires_approval", "profile": profile, "approval": approval.public_id, "run": run.public_id, "usage": usage}
            recon = run_authorized_recon(ctx, profile=profile, seeds=[], session_id=session_id)
            build_checkpoint_from_current_state(
                ctx, session_id, next_action="rank and claim recon-generated leads",
                recent_observations=[f"{recon.run_id} {profile} recon: {recon.reason}"],
            )
            return {"mode": "CONTINUE", "reason": "recon_executed", "profile": profile, "recon_run": recon.run_id, "usage": usage}
        leads = ctx.db.list_leads()
    active_lead = next(
        (lead for lead in leads if lead.status == "claimed" and lead.claimed_session == str(session_id)),
        None,
    )
    if active_lead is None:
        open_leads = [lead for lead in leads if lead.status == "open"]
        if open_leads:
            if usage["leads_claimed"] >= int(run.budget["max_leads_per_run"]):
                build_checkpoint_from_current_state(
                    ctx, session_id, next_action="budget exhausted: max_leads_per_run",
                )
                run = ctx.db.stop_autonomy_run(
                    run.id, "budget exhausted: max_leads_per_run", "budget_exhausted",
                )
                return {
                    "mode": "STOP", "reason": "budget_exhausted",
                    "budget": "max_leads_per_run", "run": run.public_id,
                    "usage": usage,
                }
            selected = max(open_leads, key=lambda lead: _lead_rank(ctx, lead))
            selected = ctx.db.claim_lead(selected.id, session_id)
            ctx.db.set_active_lead(session_id, selected.id)
            usage = usage_snapshot(ctx, run)
            run = ctx.db.update_autonomy_usage(run.id, usage)
            leads = ctx.db.list_leads()
    active_hypotheses = [
        h for h in ctx.db.list_hypotheses()
        if h.status in {"open", "testing", "inconclusive", "supported", "candidate"}
    ]
    if (not leads or all(lead.status == "closed" for lead in leads)) and not active_hypotheses:
        build_checkpoint_from_current_state(
            ctx, session_id, next_action="human review: no actionable leads remain",
        )
        run = ctx.db.stop_autonomy_run(run.id, "no actionable leads remain", "stopped")
        return {"mode": "STOP", "reason": "no_actionable_leads", "run": run.public_id, "usage": usage}
    limit_hints = {
        "lead_budget_reached": usage["leads_claimed"] >= int(run.budget["max_leads_per_run"]),
        "hypotheses_exhausted": [
            lead_id for lead_id, count in usage["hypotheses_per_lead"].items()
            if count >= int(run.budget["max_hypotheses_per_lead"])
        ],
        "request_budget_exhausted_hypotheses": [
            hyp_id for hyp_id, count in usage["requests_per_hypothesis"].items()
            if count >= int(run.budget["max_requests_per_hypothesis"])
        ],
        "test_budget_exhausted_hypotheses": [
            hyp_id for hyp_id, count in usage["tests_per_hypothesis"].items()
            if count >= int(run.budget["max_tests_per_hypothesis"])
        ],
        "inconclusive_limit_hypotheses": [
            hyp_id for hyp_id, count in usage["inconclusive_tests_per_hypothesis"].items()
            if count >= int(run.budget["max_inconclusive_tests_per_hypothesis"])
        ],
        "failed_limit_hypotheses": [
            hyp_id for hyp_id, count in usage["failed_tests_per_hypothesis"].items()
            if count >= int(run.budget["max_failed_tests_per_hypothesis"])
        ],
    }
    return {
        "mode": "CONTINUE", "reason": "within_session_budget", "run": run.public_id,
        "usage": usage, "limit_hints": limit_hints,
        "active_lead": next(
            (lead.public_id for lead in leads if lead.status == "claimed" and lead.claimed_session == str(session_id)),
            None,
        ),
    }


def build_checkpoint_from_current_state(
    ctx: "ProgramContext", session_id: int | None = None, *, next_action: str = "",
    pending_approval_id: int | None = None, recent_observations: list[str] | None = None,
) -> "CheckpointRecord":
    """Persist a resume-safe state summary derived from the database itself."""
    if session_id is not None:
        ctx.db.require_session(session_id, program_slug=ctx.slug)
    leads = ctx.db.list_leads()
    claimed = next(
        (
            lead for lead in leads
            if lead.status == "claimed" and (session_id is None or lead.claimed_session == str(session_id))
        ),
        next((lead for lead in leads if lead.status == "claimed"), None),
    )
    hypotheses = ctx.db.list_hypotheses(claimed.id if claimed else None)
    active_hypotheses = [h.id for h in hypotheses if h.status in {"open", "testing", "inconclusive"}]
    tests = ctx.db.list_tests()
    completed = [t.id for t in tests if t.status == "executed"]
    pending = [t.id for t in tests if t.status == "planned"]
    recent_completed = [t for t in tests if t.status == "executed"][:8]
    observations = [
        f"{t.public_id} {t.result or 'unknown'}: {t.observation[:300]}" for t in recent_completed
    ]
    observations = [*(recent_observations or []), *observations][:12]
    evidence = ctx.db.list_evidence()[:12]
    run = ctx.db.active_autonomy_run(session_id) if session_id is not None else ctx.db.active_autonomy_run()
    autonomy_state = asdict(run) if run else {}
    if not next_action:
        if pending:
            next_action = f"execute planned test TEST-{pending[-1]:03d} after policy preflight"
        elif active_hypotheses:
            next_action = f"plan the minimal distinguishing test for HYP-{active_hypotheses[-1]:03d}"
        elif claimed:
            next_action = f"form the next justified hypothesis for {claimed.public_id}"
        else:
            next_action = "rank and claim the next actionable lead"
    return ctx.db.save_checkpoint(
        active_lead_id=claimed.id if claimed else None,
        active_hypotheses=active_hypotheses,
        completed_tests=completed,
        pending_tests=pending,
        recent_observations=observations,
        evidence_refs=[e.public_id for e in evidence],
        next_action=next_action,
        session_id=session_id,
        autonomy_state=autonomy_state,
        pending_approval_id=pending_approval_id,
    )


__all__ = [
    "GOAL_STATUSES", "budget_dict", "start_autonomous_hunt", "usage_snapshot",
    "goal_reached", "budget_stop_reason", "refresh_autonomy",
    "build_checkpoint_from_current_state",
]
