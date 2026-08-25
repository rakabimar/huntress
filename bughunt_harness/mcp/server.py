"""Local Harness MCP server (stdio).

Exposes narrow, vendor-neutral tools over the harness state + request broker,
so agents never manipulate SQLite directly and every write retains provenance.
Tool schemas are narrow by design — there is deliberately no generic
``query_database`` / ``execute_shell`` / ``update_anything``.

The active program is resolved from ``BUGHUNT_PROGRAM`` (set by ``harness
start``) or the active-program file.  Program isolation is enforced inside
``load_program_context``.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ..hunt import compact_context, load_program_context
from ..state.constants import (
    HYPO_SUPPORTED,
    RESULT_SUPPORTS,
)
from ..state.records import FindingRecord


def _active_slug() -> str:
    slug = os.environ.get("BUGHUNT_PROGRAM")
    if slug:
        return slug
    from ..hunt import resolve_program_slug

    return resolve_program_slug(None)


_ID_RE = re.compile(r"^[A-Z]+-(\d+)$")


def _id(ref: Any) -> int:
    """Accept either a public id ('LEAD-018') or a bare int."""
    if isinstance(ref, int):
        return ref
    if isinstance(ref, str):
        m = _ID_RE.match(ref.strip())
        if m:
            return int(m.group(1))
        if ref.isdigit():
            return int(ref)
    raise ValueError(f"invalid id reference: {ref!r}")


def _make_mcp(name: str = "bughunt-harness"):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("MCP SDK not installed; pip install 'mcp'") from exc

    mcp = FastMCP(name)

    @mcp.tool()
    def get_active_engagement() -> dict:
        """Return the compact active-program context (scope, ROE, accounts, current state)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return compact_context(ctx)

    @mcp.tool()
    def get_scope_summary() -> dict:
        """Return a summary of the active program's include/exclude scope."""
        from ..hunt import scope_summary

        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return scope_summary(ctx.scope, ctx.engagement)

    @mcp.tool()
    def scope_preflight(target: str) -> dict:
        """Check whether a target is in scope. Returns a scope decision."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return ctx.scope.check(target).as_dict()

    @mcp.tool()
    def policy_preflight(action: str, target: str | None = None) -> dict:
        """Check whether an action (on a target) is allowed by policy. Returns a policy decision."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return ctx.policy.check(action, target).as_dict()

    @mcp.tool()
    def get_hunt_status() -> dict:
        """Return current hunt status: active lead, open hypotheses, latest checkpoint."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            leads = ctx.db.list_leads()
            hypos = ctx.db.list_hypotheses()
            return {
                "active_lead": next(({"id": l.public_id, "title": l.title, "status": l.status} for l in leads if l.status == "claimed"), None),
                "open_hypotheses": [{"id": h.public_id, "statement": h.statement} for h in hypos if h.status in ("open", "testing")],
                "latest_checkpoint": _cp(ctx),
            }

    # -- leads ------------------------------------------------------------
    @mcp.tool()
    def list_leads(status: str | None = None) -> list[dict]:
        """List leads for the active program."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return [_lead(l) for l in ctx.db.list_leads(status)]

    @mcp.tool()
    def get_lead(lead_id: str) -> dict:
        """Get a single lead by public id (e.g. LEAD-001)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _lead(ctx.db.get_lead(_id(lead_id)))

    @mcp.tool()
    def claim_lead(lead_id: str) -> dict:
        """Claim an open lead, binding it to the active session."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            session = ctx.db.latest_session()
            sid = session.id if session else 0
            return _lead(ctx.db.claim_lead(_id(lead_id), sid))

    @mcp.tool()
    def release_lead(lead_id: str) -> dict:
        """Release a claimed lead back to open."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _lead(ctx.db.release_lead(_id(lead_id)))

    @mcp.tool()
    def create_lead(title: str, entity: str = "", source: str = "manual", priority: str = "medium", rationale: str = "") -> dict:
        """Create a lead (status: open)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _lead(ctx.db.add_lead(title, entity, source, priority, rationale))

    @mcp.tool()
    def close_lead(lead_id: str) -> dict:
        """Close a claimed lead."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _lead(ctx.db.close_lead(_id(lead_id)))

    # -- hypotheses -------------------------------------------------------
    @mcp.tool()
    def list_hypotheses(lead_id: str | None = None, status: str | None = None) -> list[dict]:
        """List hypotheses for the active program (optionally filtered)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            lid = _id(lead_id) if lead_id else None
            return [_hyp(h) for h in ctx.db.list_hypotheses(lid, status)]

    @mcp.tool()
    def get_hypothesis(hypothesis_id: str) -> dict:
        """Get a single hypothesis by public id."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _hyp(ctx.db.get_hypothesis(_id(hypothesis_id)))

    @mcp.tool()
    def create_hypothesis(statement: str, rationale: str = "", lead_id: str | None = None, confidence: float | None = None) -> dict:
        """Create a hypothesis (status: open)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            lid = _id(lead_id) if lead_id else None
            return _hyp(ctx.db.create_hypothesis(statement, rationale, lid, confidence))

    @mcp.tool()
    def update_hypothesis(hypothesis_id: str, status: str | None = None, statement: str | None = None, rationale: str | None = None) -> dict:
        """Update a hypothesis status (validated transition) and/or fields."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            hid = _id(hypothesis_id)
            if status:
                ctx.db.set_hypothesis_status(hid, status)
            fields = {}
            if statement is not None:
                fields["statement"] = statement
            if rationale is not None:
                fields["rationale"] = rationale
            if fields:
                ctx.db.update_hypothesis(hid, **fields)
            return _hyp(ctx.db.get_hypothesis(hid))

    # -- research tests ---------------------------------------------------
    @mcp.tool()
    def list_tests(hypothesis_id: str | None = None) -> list[dict]:
        """List research tests (optionally by hypothesis)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            hid = _id(hypothesis_id) if hypothesis_id else None
            return [_test(t) for t in ctx.db.list_tests(hid)]

    @mcp.tool()
    def create_research_test(
        hypothesis_id: str, objective: str, method: str = "", baseline_ref: str = "",
        controlled_change: str = "", expected_if_true: str = "", expected_if_false: str = "",
    ) -> dict:
        """Create a planned research test for a hypothesis."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            t = ctx.db.add_test(_id(hypothesis_id), objective, method, baseline_ref, controlled_change, expected_if_true, expected_if_false)
            return _test(t)

    @mcp.tool()
    def complete_research_test(test_id: str, observation: str, result: str, evidence_refs: list[str] | None = None) -> dict:
        """Complete a planned test with an observation and result (supports/rejects/inconclusive)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            t = ctx.db.complete_test(_id(test_id), observation, result, evidence_refs)
            # Feedback: update hypothesis status when a supporting result arrives.
            if result == RESULT_SUPPORTS:
                hyp = ctx.db.get_hypothesis(t.hypothesis_id)
                if hyp.status in ("open", "testing"):
                    try:
                        ctx.db.set_hypothesis_status(hyp.id, HYPO_SUPPORTED)
                    except Exception:
                        pass
            return _test(t)

    # -- evidence ---------------------------------------------------------
    @mcp.tool()
    def list_evidence() -> list[dict]:
        """List evidence records for the active program."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return [_ev(e) for e in ctx.db.list_evidence()]

    @mcp.tool()
    def create_evidence(kind: str, ref: str, description: str = "", preview: str = "") -> dict:
        """Record an evidence metadata entry (files live on disk, not in the DB)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _ev(ctx.db.add_evidence(kind, ref, description, preview))

    # -- findings ---------------------------------------------------------
    @mcp.tool()
    def list_findings(status: str | None = None) -> list[dict]:
        """List findings for the active program."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return [_finding(f) for f in ctx.db.list_findings(status)]

    @mcp.tool()
    def get_finding(finding_id: str) -> dict:
        """Get a single finding by public id."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _finding(ctx.db.get_finding(_id(finding_id)))

    @mcp.tool()
    def create_finding_candidate(
        title: str, affected_target: str = "", category: str = "", impact_summary: str = "",
        evidence_refs: list[str] | None = None, lead_id: str | None = None,
        hypothesis_id: str | None = None, test_ids: list[str] | None = None,
    ) -> dict:
        """Create a finding in 'candidate' state (never validated directly)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            f = ctx.db.create_finding(
                title, affected_target, category, impact_summary, evidence_refs,
                lead_id=_id(lead_id) if lead_id else None,
                hypothesis_id=_id(hypothesis_id) if hypothesis_id else None,
                test_ids=[_id(t) for t in test_ids] if test_ids else None,
            )
            return _finding(f)

    @mcp.tool()
    def update_finding(
        finding_id: str, impact_summary: str | None = None, title: str | None = None,
        affected_target: str | None = None, category: str | None = None,
        evidence_refs: list[str] | None = None, lead_id: str | None = None,
        hypothesis_id: str | None = None, test_ids: list[str] | None = None,
    ) -> dict:
        """Update finding metadata/linkage. Status transitions go through the
        state machine (validation-review / poc / cvss / report tools) — NEVER
        set status directly here."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            fid = _id(finding_id)
            fields: dict[str, Any] = {}
            if impact_summary is not None:
                fields["impact_summary"] = impact_summary
            if title is not None:
                fields["title"] = title
            if affected_target is not None:
                fields["affected_target"] = affected_target
            if category is not None:
                fields["category"] = category
            if evidence_refs is not None:
                fields["evidence_refs"] = evidence_refs
            if lead_id is not None:
                fields["lead_id"] = _id(lead_id)
            if hypothesis_id is not None:
                fields["hypothesis_id"] = _id(hypothesis_id)
            if test_ids is not None:
                fields["test_ids"] = [_id(t) for t in test_ids]
            if fields:
                ctx.db.update_finding(fid, **fields)
            return _finding(ctx.db.get_finding(fid))

    # -- validation review (finding validation provenance — P0.7) ----------
    @mcp.tool()
    def begin_finding_validation(finding_id: str, requested_by: str = "", reviewer_type: str = "") -> dict:
        """Open a validation review for a finding (candidate moves -> validation)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            fid = _id(finding_id)
            f = ctx.db.get_finding(fid)
            if f.status == "candidate":
                ctx.db.transition_finding(fid, "validation")
            return _vreview(ctx.db.begin_validation(fid, requested_by=requested_by, reviewer_type=reviewer_type))

    @mcp.tool()
    def submit_validation_review(
        review_id: str, verdict: str, reasoning_summary: str = "",
        reviewer_runtime: str = "", reviewer_session: str = "",
    ) -> dict:
        """Submit a verdict (supported/rejected/inconclusive) for a validation review."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            r = ctx.db.submit_validation_review(
                _id(review_id), verdict, reasoning_summary=reasoning_summary,
                reviewer_runtime=reviewer_runtime, reviewer_session=reviewer_session,
            )
            return _vreview(r)

    @mcp.tool()
    def finalize_validation_review(finding_id: str) -> dict:
        """Apply a finding's submitted review verdict to its pipeline status."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            f = ctx.db.finalize_validation(_id(finding_id))
            return _finding(f)

    @mcp.tool()
    def list_validation_reviews(finding_id: str | None = None) -> list[dict]:
        """List validation reviews (optionally for one finding)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            fid = _id(finding_id) if finding_id else None
            return [_vreview(r) for r in ctx.db.list_validation_reviews(fid)]

    # -- checkpoints ------------------------------------------------------
    def _cp(ctx) -> dict | None:
        cp = ctx.db.latest_checkpoint()
        if cp is None:
            return None
        return {
            "id": cp.public_id, "active_lead_id": cp.active_lead_id,
            "completed_tests": cp.completed_tests, "pending_tests": cp.pending_tests,
            "next_action": cp.next_action, "created_at": cp.created_at,
        }

    @mcp.tool()
    def get_latest_checkpoint() -> dict | None:
        """Return the latest checkpoint summary."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _cp(ctx)

    @mcp.tool()
    def save_checkpoint(
        active_lead_id: str | None = None, active_hypotheses: list[int] | None = None,
        completed_tests: list[int] | None = None, pending_tests: list[int] | None = None,
        recent_observations: list[str] | None = None, evidence_refs: list[str] | None = None,
        next_action: str = "",
    ) -> dict:
        """Persist a checkpoint so another runtime can continue later."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            ck = ctx.db.save_checkpoint(
                active_lead_id=_id(active_lead_id) if active_lead_id else None,
                active_hypotheses=active_hypotheses or [],
                completed_tests=completed_tests or [],
                pending_tests=pending_tests or [],
                recent_observations=recent_observations or [],
                evidence_refs=evidence_refs or [],
                next_action=next_action,
            )
            return {"id": ck.public_id, "created_at": ck.created_at, "next_action": ck.next_action}

    # -- program knowledge ------------------------------------------------
    @mcp.tool()
    def get_program_knowledge(topic: str | None = None) -> dict:
        """Return program-specific knowledge files (architecture, auth model, etc.)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            kdir = ctx.workspace / "knowledge"
            out: dict[str, str] = {}
            files = sorted(kdir.glob("*.md")) if kdir.is_dir() else []
            for f in files:
                if topic and topic.lower() not in f.stem.lower():
                    continue
                out[f.stem] = f.read_text(encoding="utf-8")[:4000]
            return out

    # -- authorized HTTP --------------------------------------------------
    @mcp.tool()
    def send_authorized_http_request(
        target: str, method: str = "GET", action: str = "read_http",
        headers: dict[str, str] | None = None, body: str | None = None,
        json_body: dict | None = None, params: dict[str, str] | None = None,
        auth_context: str = "",
    ) -> dict:
        """Send ONE request through the controlled broker (scope+policy+ratelimit+redact)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            result = ctx.broker().execute(
                target=target, method=method, action=action, headers=headers,
                body=body, json_body=json_body, params=params, agent_role="mcp",
                auth_context=auth_context,
            )
            return result.as_dict()

    # -- approvals (agents request/list, humans decide via the CLI) --------
    @mcp.tool()
    def request_approval(action: str, target: str = "", requested_by: str = "", note: str = "", expires_at: str | None = None) -> dict:
        """Request human approval for an action. Agents cannot approve/reject."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            a = ctx.db.request_approval(action, target, requested_by=requested_by, note=note, expires_at=expires_at)
            return _approval(a)

    @mcp.tool()
    def get_approval(approval_id: str) -> dict:
        """Get a single approval by public id."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _approval(ctx.db.get_approval(_id(approval_id)))

    @mcp.tool()
    def list_pending_approvals() -> list[dict]:
        """List pending approvals awaiting human decision."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return [_approval(a) for a in ctx.db.list_pending_approvals()]

    # -- auth contexts (secret refs only; never credentials) ---------------
    @mcp.tool()
    def create_auth_context(account_id: str, type: str = "header_bundle", secret_refs: list[str] | None = None, metadata: dict | None = None, enabled: bool = True) -> dict:
        """Create an auth context (references secrets, stores no credential values)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _auth(ctx.db.create_auth_context(account_id, type, secret_refs, metadata, enabled))

    @mcp.tool()
    def list_auth_contexts(enabled: bool | None = None) -> list[dict]:
        """List auth contexts (optionally filtered by enabled)."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return [_auth(a) for a in ctx.db.list_auth_contexts(enabled)]

    @mcp.tool()
    def get_auth_context(auth_context_id: str) -> dict:
        """Get an auth context by id."""
        with load_program_context(_active_slug()) as ctx:  # type: ignore[arg-type]
            return _auth(ctx.db.get_auth_context(_id(auth_context_id)))

    return mcp


def run() -> None:
    """Entry point — run the MCP server over stdio."""
    _make_mcp().run()


if __name__ == "__main__":
    run()


# --------------------------------------------------------------------------- #
# entity -> safe dict helpers
# --------------------------------------------------------------------------- #
def _lead(l) -> dict:
    return {"id": l.public_id, "title": l.title, "entity": l.entity, "source": l.source,
            "status": l.status, "priority": l.priority, "rationale": l.rationale,
            "claimed_session": l.claimed_session, "created_at": l.created_at}


def _hyp(h) -> dict:
    return {"id": h.public_id, "lead_id": h.lead_id, "statement": h.statement,
            "rationale": h.rationale, "confidence": h.confidence, "status": h.status,
            "created_at": h.created_at}


def _test(t) -> dict:
    return {"id": t.public_id, "hypothesis_id": t.hypothesis_id, "objective": t.objective,
            "method": t.method, "status": t.status, "result": t.result,
            "observation": t.observation, "evidence_refs": t.evidence_refs,
            "expected_if_true": t.expected_if_true, "expected_if_false": t.expected_if_false,
            "controlled_change": t.controlled_change}


def _ev(e) -> dict:
    return {"id": e.public_id, "kind": e.kind, "ref": e.ref, "description": e.description,
            "preview": e.preview, "created_at": e.created_at}


def _finding(f: FindingRecord) -> dict:
    return {"id": f.public_id, "title": f.title, "affected_target": f.affected_target,
            "category": f.category, "status": f.status, "validation_state": f.validation_state,
            "impact_summary": f.impact_summary, "evidence_refs": f.evidence_refs,
            "cvss_data": f.cvss_data, "report_path": f.report_path,
            "lead_id": f.lead_id, "hypothesis_id": f.hypothesis_id, "test_ids": f.test_ids}


def _approval(a) -> dict:
    return {"id": a.public_id, "action": a.action, "target": a.target, "status": a.status,
            "requested_by": a.requested_by, "requested_at": a.requested_at, "note": a.note,
            "program": a.program, "method": a.method, "expires_at": a.expires_at,
            "decided_at": a.decided_at, "approved_by": a.approved_by}


def _vreview(r) -> dict:
    return {"id": r.public_id, "finding_id": r.finding_id, "verdict": r.verdict,
            "status": r.status, "reviewer_type": r.reviewer_type,
            "reviewer_runtime": r.reviewer_runtime, "reviewer_session": r.reviewer_session,
            "requested_by": r.requested_by, "reasoning_summary": r.reasoning_summary,
            "check_results": r.check_results, "evidence_refs": r.evidence_refs,
            "created_at": r.created_at}


def _auth(a) -> dict:
    return {"id": a.public_id, "account_id": a.account_id, "type": a.type,
            "enabled": a.enabled, "secret_refs": a.secret_refs, "metadata": a.metadata,
            "created_at": a.created_at}


__all__ = ["run", "_make_mcp"]