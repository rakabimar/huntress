"""``harness`` CLI — the complete command surface (spec §6).

Uses argparse (stdlib) for deterministic parsing and rich (when present) for
rendering.  Program-dependent commands accept ``--program <slug>`` and fall
back to the active program otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import get_config
from .errors import HarnessError


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
try:
    from rich.console import Console
    from rich.table import Table

    _console = Console()
    HAS_RICH = True
except Exception:  # pragma: no cover - rich is a declared dep
    _console = None
    HAS_RICH = False


def _out(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _table(title: str, columns: list[str], rows: list[list]) -> None:
    if HAS_RICH:
        t = Table(title=title)
        for c in columns:
            t.add_column(c)
        for r in rows:
            t.add_row(*[str(x) if x is not None else "" for x in r])
        _console.print(t)
    else:
        _out(title)
        _out(" | ".join(columns))
        for r in rows:
            _out(" | ".join(str(x) if x is not None else "" for x in r))


def _dump(obj) -> None:
    if isinstance(obj, str):
        _out(obj)
    else:
        _out(json.dumps(obj, indent=2, default=str))


# --------------------------------------------------------------------------- #
# shared arg helpers
# --------------------------------------------------------------------------- #
def _add_program_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--program", "-p", default=None, help="program slug (default: active program)")


def _add_finding_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--finding", required=True, help="finding public id (e.g. FIND-001)")


def _slug(explicit: str | None) -> str:
    from .hunt import resolve_program_slug

    return resolve_program_slug(explicit)


def _ctx(explicit: str | None):
    from .hunt import load_program_context

    return load_program_context(_slug(explicit))


def _parse_id(ref: str) -> int:
    import re

    m = re.match(r"^[A-Z]+-(\d+)$", ref.strip())
    if m:
        return int(m.group(1))
    if ref.strip().isdigit():
        return int(ref.strip())
    raise HarnessError(f"invalid id reference: {ref!r}")


def _split_list(s: str | None) -> list[str]:
    """Split a CLI-provided list that may use newlines or commas."""
    if not s:
        return []
    if "\n" in s:
        return [x.strip() for x in s.splitlines() if x.strip()]
    return [x.strip() for x in s.split(",") if x.strip()]


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_init(args) -> int:
    cfg = get_config()
    _out(f"harness v{__version__}")
    _out(f"home:          {cfg.home}")
    _out(f"programs dir:  {cfg.programs_dir}")
    _out(f"registry db:   {cfg.registry_db}")
    _out("Initializing registry...")
    from .registry import ProgramRegistry

    reg = ProgramRegistry(cfg)
    reg.close()
    _out("Ready. Next: `harness program create <slug>` then `harness doctor`.")
    return 0


def cmd_doctor(args) -> int:
    from .doctor import run_doctor

    report = run_doctor(args.program)
    _dump(report.render())
    # Exit 0 when env+core are sound (CORE/HUNT/FULL ready); exit 1 only when
    # the environment or install is broken (ENV_READY / NOT_READY).  A fresh
    # install with no program yet reports CORE_READY — sound, not an error — so
    # bootstrap can fail the script on a broken install without `|| true`.
    return report.exit_code


# --- program ---------------------------------------------------------------
def _program_create(args) -> int:
    from .registry import ProgramRegistry, utcnow
    from .engagement.workspace import slug_ok, workspace_path_for, create_workspace

    cfg = get_config()
    if not slug_ok(args.slug):
        _err(f"invalid slug {args.slug!r} (2-50 chars, a-z/0-9/-)")
        return 1
    ws = workspace_path_for(args.slug, cfg)
    reg = ProgramRegistry(cfg)
    try:
        rec = reg.create(
            slug=args.slug, name=args.name, platform=args.platform or "custom",
            program_url=args.url, workspace_path=str(ws), notes=args.notes,
        )
        try:
            create_workspace(rec, fixture=getattr(args, "fixture", False))
        except Exception:
            # Roll back the registration row if the workspace could not be created.
            try:
                reg.delete(args.slug)
            except Exception:
                pass
            raise
        reg.touch_last_opened(args.slug)
        reg.set_active(args.slug)
    except ValueError as exc:
        _err(str(exc))
        return 1
    finally:
        reg.close()
    _out(f"created program {args.slug!r} at {ws}")
    _out("Next: edit scope.yaml + roe.yaml, then `harness engagement validate -p " + args.slug + "`")
    return 0


def _program_list(args) -> int:
    from .registry import ProgramRegistry

    reg = ProgramRegistry()
    try:
        recs = reg.list(args.status)
    finally:
        reg.close()
    _table("Programs", ["slug", "name", "platform", "status", "last_opened"], [
        [r.slug, r.name, r.platform, r.status, r.last_opened_at] for r in recs
    ])
    return 0


def _program_show(args) -> int:
    from .registry import ProgramRegistry

    reg = ProgramRegistry()
    try:
        rec = reg.get(_slug(args.program))
    finally:
        reg.close()
    _dump(rec.as_dict())
    return 0


def _program_use(args) -> int:
    cfg = get_config()
    from .registry import ProgramRegistry

    reg = ProgramRegistry(cfg)
    try:
        reg.get(args.slug)
        reg.set_active(args.slug)
    finally:
        reg.close()
    _out(f"active program: {args.slug}")
    return 0


def _program_status(args, status: str) -> int:
    from .registry import ProgramRegistry
    from .engagement.workspace import write_program_status

    slug = _slug(args.program)
    reg = ProgramRegistry()
    try:
        reg.set_status(slug, status)
        rec = reg.get(slug)
    finally:
        reg.close()
    write_program_status(rec)
    _out(f"program {slug} -> {status}")
    return 0


def _program_export(args) -> int:
    import shutil

    slug = _slug(args.program)
    from .hunt import load_program_context

    with load_program_context(slug) as ctx:
        dest = Path(args.dest) if args.dest else Path.cwd() / f"{slug}-export"
        dest.mkdir(parents=True, exist_ok=True)
        EXCLUDE_DIRS = {"state", "evidence", "findings", "reports", "browser", "burp", "logs", "checkpoints", "artifacts", "recon"}
        for child in ctx.workspace.iterdir():
            if child.is_dir() and child.name in EXCLUDE_DIRS:
                continue
            target = dest / child.name
            if child.is_dir():
                shutil.copytree(child, target)
            else:
                shutil.copy2(child, target)
    _out(f"exported non-sensitive program data to {dest}")
    return 0


# --- engagement ------------------------------------------------------------
def _engagement_validate(args) -> int:
    slug = _slug(args.program)
    from .hunt import load_program_context

    try:
        with load_program_context(slug) as ctx:
            pass
    except HarnessError as exc:
        _err(f"ENGAGEMENT INVALID: {exc}")
        return 1
    _out(f"engagement valid for program {slug!r}")
    return 0


def _engagement_status(args) -> int:
    from .hunt import load_program_context, scope_summary, roe_summary

    with load_program_context(_slug(args.program)) as ctx:
        _dump({
            "program": {"slug": ctx.slug, "name": ctx.record.name, "platform": ctx.record.platform, "status": ctx.record.status},
            "scope": scope_summary(ctx.scope, ctx.engagement),
            "roe": roe_summary(ctx.engagement),
            "accounts": ctx.secrets.account_summaries(ctx.engagement.accounts.accounts),
        })
    return 0


# --- scope / policy --------------------------------------------------------
def _scope_check(args) -> int:
    with _ctx(args.program) as ctx:
        d = ctx.scope.check(args.target)
    _dump(d.as_dict())
    return 0


def _policy_check(args) -> int:
    with _ctx(args.program) as ctx:
        d = ctx.policy.check(args.action, args.target)
    _dump(d.as_dict())
    return 0 if d.decision != "deny" else 2


# --- lead ------------------------------------------------------------------
def _lead_list(args) -> int:
    with _ctx(args.program) as ctx:
        leads = ctx.db.list_leads(args.status)
    _table("Leads", ["id", "status", "priority", "title", "entity"], [
        [l.public_id, l.status, l.priority, l.title, l.entity] for l in leads
    ])
    return 0


def _lead_show(args) -> int:
    with _ctx(args.program) as ctx:
        l = ctx.db.get_lead(_parse_id(args.id))
        _dump({
            "id": l.public_id, "title": l.title, "entity": l.entity, "source": l.source,
            "status": l.status, "priority": l.priority, "rationale": l.rationale,
            "claimed_session": l.claimed_session, "created_at": l.created_at,
        })
    return 0


def _lead_add(args) -> int:
    with _ctx(args.program) as ctx:
        l = ctx.db.add_lead(args.title, entity=args.entity or "", source=args.source or "manual",
                             priority=args.priority or "medium", rationale=args.rationale or "")
    _out(f"created lead {l.public_id}")
    return 0


def _lead_claim(args) -> int:
    with _ctx(args.program) as ctx:
        session = ctx.db.latest_session()
        l = ctx.db.claim_lead(_parse_id(args.id), session.id if session else 0)
    _out(f"claimed lead {l.public_id}")
    return 0


def _lead_release(args) -> int:
    with _ctx(args.program) as ctx:
        l = ctx.db.release_lead(_parse_id(args.id))
    _out(f"released lead {l.public_id}")
    return 0


def _lead_close(args) -> int:
    with _ctx(args.program) as ctx:
        l = ctx.db.close_lead(_parse_id(args.id))
    _out(f"closed lead {l.public_id}")
    return 0


# --- hypothesis ------------------------------------------------------------
def _hyp_list(args) -> int:
    with _ctx(args.program) as ctx:
        hyps = ctx.db.list_hypotheses(None, args.status)
    _table("Hypotheses", ["id", "status", "statement", "confidence"], [
        [h.public_id, h.status, h.statement, h.confidence] for h in hyps
    ])
    return 0


def _hyp_show(args) -> int:
    with _ctx(args.program) as ctx:
        h = ctx.db.get_hypothesis(_parse_id(args.id))
        _dump({"id": h.public_id, "lead_id": h.lead_id, "statement": h.statement,
               "rationale": h.rationale, "confidence": h.confidence, "status": h.status,
               "created_at": h.created_at, "updated_at": h.updated_at})
    return 0


def _hyp_create(args) -> int:
    with _ctx(args.program) as ctx:
        lead_id = _parse_id(args.lead) if args.lead else None
        h = ctx.db.create_hypothesis(args.statement, rationale=args.rationale or "",
                                     lead_id=lead_id, confidence=args.confidence)
    _out(f"created hypothesis {h.public_id} (status={h.status})")
    return 0


def _hyp_update(args) -> int:
    with _ctx(args.program) as ctx:
        if args.status:
            h = ctx.db.set_hypothesis_status(_parse_id(args.id), args.status)
        else:
            fields = {}
            if args.statement is not None:
                fields["statement"] = args.statement
            if args.rationale is not None:
                fields["rationale"] = args.rationale
            h = ctx.db.update_hypothesis(_parse_id(args.id), **fields)
        _dump({"id": h.public_id, "status": h.status, "statement": h.statement})
    return 0


# --- test ------------------------------------------------------------------
def _test_list(args) -> int:
    with _ctx(args.program) as ctx:
        tests = ctx.db.list_tests(_parse_id(args.hypothesis) if args.hypothesis else None)
    _table("Tests", ["id", "status", "result", "objective"], [
        [t.public_id, t.status, t.result or "-", t.objective] for t in tests
    ])
    return 0


def _test_add(args) -> int:
    with _ctx(args.program) as ctx:
        t = ctx.db.add_test(_parse_id(args.hypothesis), args.objective, method=args.method or "",
                            controlled_change=args.change or "", expected_if_true=args.if_true or "",
                            expected_if_false=args.if_false or "")
    _out(f"created test {t.public_id} (status={t.status})")
    return 0


def _test_complete(args) -> int:
    with _ctx(args.program) as ctx:
        t = ctx.db.complete_test(_parse_id(args.id), args.observation, args.result,
                                 (args.evidence or "").split(",") if args.evidence else None)
        if args.result == "supports":
            try:
                hyp = ctx.db.get_hypothesis(t.hypothesis_id)
                if hyp.status in ("open", "testing"):
                    ctx.db.set_hypothesis_status(hyp.id, "supported")
            except HarnessError:
                pass
        _dump({"id": t.public_id, "status": t.status, "result": t.result})
    return 0


# --- evidence --------------------------------------------------------------
def _evidence_add(args) -> int:
    with _ctx(args.program) as ctx:
        e = ctx.db.add_evidence(args.kind, args.ref, args.description or "", args.preview or "")
    _out(f"recorded evidence {e.public_id}")
    return 0


def _evidence_list(args) -> int:
    with _ctx(args.program) as ctx:
        evs = ctx.db.list_evidence()
    _table("Evidence", ["id", "kind", "ref"], [[e.public_id, e.kind, e.ref] for e in evs])
    return 0


def _evidence_show(args) -> int:
    with _ctx(args.program) as ctx:
        e = ctx.db.get_evidence(_parse_id(args.id))
        _dump({"id": e.public_id, "kind": e.kind, "ref": e.ref, "description": e.description, "preview": e.preview})
    return 0


# --- finding ---------------------------------------------------------------
def _finding_list(args) -> int:
    with _ctx(args.program) as ctx:
        fs = ctx.db.list_findings(args.status)
    _table("Findings", ["id", "status", "title", "category"], [
        [f.public_id, f.status, f.title, f.category] for f in fs
    ])
    return 0


def _finding_show(args) -> int:
    with _ctx(args.program) as ctx:
        f = ctx.db.get_finding(_parse_id(args.id))
        _dump({"id": f.public_id, "title": f.title, "affected_target": f.affected_target,
               "category": f.category, "status": f.status, "validation_state": f.validation_state,
               "impact_summary": f.impact_summary, "evidence_refs": f.evidence_refs,
               "cvss_data": f.cvss_data, "report_path": f.report_path})
    return 0


def _finding_create(args) -> int:
    with _ctx(args.program) as ctx:
        f = ctx.db.create_finding(args.title, args.target or "", args.category or "",
                                  args.impact or "", (args.evidence or "").split(",") if args.evidence else None)
    _out(f"created finding candidate {f.public_id}")
    return 0


def _finding_validate(args) -> int:
    from .findings.validation import assess_finding
    from .scope.engine import ScopeEngine
    from .state.constants import FINDING_CANDIDATE, FINDING_VALIDATION, FINDING_KILLED

    with _ctx(args.program) as ctx:
        f = ctx.db.get_finding(_parse_id(args.id))
        tests = ctx.db.list_tests()
        evidence = ctx.db.list_evidence()
        verdict = assess_finding(f, scope_engine=ScopeEngine(ctx.engagement.scope), tests=tests, evidence=evidence)
        _dump(verdict.as_dict())
        # Apply the deterministic pre-gate.  Entering 'validated' is deliberately
        # NOT done here: adversarial validation goes through the validation-review
        # workflow (P0.7), finalized via `finding adjudicate`.
        if verdict.verdict == "supported":
            if f.status == FINDING_CANDIDATE:
                f = ctx.db.transition_finding(f.id, FINDING_VALIDATION)
                _out(f"-> entered validation: {f.public_id} (dispatch finding-validator / adjudicate next)")
            elif f.status == FINDING_VALIDATION:
                _out(f"-> already in validation: {f.public_id} (submit a validation review to finalize)")
        elif verdict.verdict == "killed":
            if f.status in (FINDING_CANDIDATE, FINDING_VALIDATION):
                f = ctx.db.transition_finding(f.id, FINDING_KILLED, validation_state="killed")
                _out(f"-> killed: {f.public_id}")
    return 0


def _finding_adjudicate(args) -> int:
    from .state.constants import FINDING_CANDIDATE, FINDING_VALIDATION

    with _ctx(args.program) as ctx:
        db = ctx.db
        fid = _parse_id(args.id)
        f = db.get_finding(fid)
        if f.status == FINDING_CANDIDATE:
            f = db.transition_finding(fid, FINDING_VALIDATION)
        elif f.status != FINDING_VALIDATION:
            _err(f"finding {f.public_id} must be 'candidate' or 'validation' to adjudicate (is {f.status})")
            return 1
        # Validation provenance: a submitted review is the ONLY path to validated.
        review = db.begin_validation(fid, requested_by="cli", reviewer_type="human")
        submitted = db.submit_validation_review(review.id, args.verdict, reasoning_summary=args.reason or "")
        result = db.finalize_validation(fid)
        _out(f"review {submitted.public_id} submitted ({submitted.verdict}); finding {result.public_id} -> {result.status}")
    return 0


def _finding_reject(args) -> int:
    from .state.constants import FINDING_REJECTED

    with _ctx(args.program) as ctx:
        f = ctx.db.transition_finding(_parse_id(args.id), FINDING_REJECTED)
        _out(f"rejected finding {f.public_id} (reason: {args.reason or '(none)'})")
    return 0


def _finding_cvss(args) -> int:
    from .cvss.engine import score_vector
    from .state.constants import FINDING_SCORED, FINDING_POC_READY

    result = score_vector(args.vector)
    with _ctx(args.program) as ctx:
        ctx.db.set_finding_cvss(_parse_id(args.id), result.as_dict())
        f = ctx.db.get_finding(_parse_id(args.id))
        if f.status == FINDING_POC_READY:
            try:
                ctx.db.transition_finding(f.id, FINDING_SCORED)
            except HarnessError:
                pass
        _dump(result.as_dict())
    return 0


# --- checkpoint ------------------------------------------------------------
def _checkpoint_save(args) -> int:
    with _ctx(args.program) as ctx:
        ck = ctx.db.save_checkpoint(
            active_lead_id=_parse_id(args.lead) if args.lead else None,
            active_hypotheses=[_parse_id(x) for x in (args.hypotheses or "").split(",") if x],
            next_action=args.next or "",
        )
    _out(f"saved checkpoint {ck.public_id}")
    return 0


def _checkpoint_show(args) -> int:
    with _ctx(args.program) as ctx:
        ck = ctx.db.get_checkpoint(_parse_id(args.id))
        _dump({"id": ck.public_id, "active_lead_id": ck.active_lead_id,
               "completed_tests": ck.completed_tests, "pending_tests": ck.pending_tests,
               "recent_observations": ck.recent_observations, "evidence_refs": ck.evidence_refs,
               "next_action": ck.next_action, "created_at": ck.created_at})
    return 0


def _checkpoint_latest(args) -> int:
    with _ctx(args.program) as ctx:
        ck = ctx.db.latest_checkpoint()
    if ck is None:
        _out("(no checkpoint yet)")
        return 0
    _dump({"id": ck.public_id, "next_action": ck.next_action, "completed_tests": ck.completed_tests})
    return 0


# --- knowledge -------------------------------------------------------------
def _knowledge_list(args) -> int:
    with _ctx(args.program) as ctx:
        kdir = ctx.workspace / "knowledge"
        files = sorted(kdir.glob("*.md")) if kdir.is_dir() else []
    for f in files:
        size = f.stat().st_size
        _out(f"- {f.name} ({size} bytes)")
    _out("\nProgram knowledge is program-scoped. Promote to global knowledge for cross-program reuse.")
    return 0


def _knowledge_promote(args) -> int:
    root = Path(__file__).resolve().parent.parent
    cand_dir = root / "knowledge" / "global-candidates"
    cand_dir.mkdir(parents=True, exist_ok=True)
    with _ctx(args.program) as ctx:
        src = ctx.workspace / "knowledge" / args.file
        if not src.is_file():
            _err(f"knowledge file not found: {src}")
            return 1
        content = src.read_text(encoding="utf-8")
    target = cand_dir / f"from-{Path(_slug(args.program))}-{args.file}"
    header = (
        "# GLOBAL KNOWLEDGE CANDIDATE (pending human review)\n"
        "# Review + sanitize BEFORE moving to knowledge/: remove program identifiers,\n"
        "# target domains, user data, secrets, and proprietary implementation details.\n\n"
    )
    target.write_text(header + content, encoding="utf-8")
    _out(f"promoted candidate -> {target}")
    _out("Review and sanitize, then move into knowledge/ to make it global.")
    return 0


def _knowledge_candidates(args) -> int:
    root = Path(__file__).resolve().parent.parent
    cand_dir = root / "knowledge" / "global-candidates"
    if not cand_dir.is_dir():
        _out("(no candidates)")
        return 0
    for f in sorted(cand_dir.glob("*.md")):
        _out(f"- {f.name}")
    return 0


def _knowledge_status(args) -> int:
    root = Path(__file__).resolve().parent.parent
    src = root / "knowledge" / "sources.yaml"
    if src.is_file():
        _out(src.read_text(encoding="utf-8"))
    else:
        _out("(knowledge/sources.yaml not yet created)")
    vendor = root / "vendor"
    if vendor.is_dir():
        _out("\nVendor pins:")
        for d in sorted(vendor.iterdir()):
            if d.is_dir():
                pins = [p.name for p in d.iterdir() if p.is_dir()]
                _out(f"- {d.name}: {', '.join(pins) or '(empty)'}")
    return 0


# --- skills ----------------------------------------------------------------
def _skill_list(args) -> int:
    from .skills.registry import list_skills

    for s in list_skills():
        _out(f"- {s['name']:32s} {s.get('maturity', 'experimental'):12s} {s.get('risk_class', 'R0')}")
    return 0


def _skill_validate(args) -> int:
    from .skills.registry import validate_all

    problems = validate_all()
    for p in problems:
        _err(f"[{'FAIL' if p['level']=='fail' else 'WARN'}] {p['skill']}: {p['message']}")
    _out(f"\n{len(problems)} problem(s).")
    return 0


def _skill_eval(args) -> int:
    from .skills.eval import run_eval

    results = run_eval(args.name)
    _dump(results)
    return 0


# --- cvss ------------------------------------------------------------------
def _cvss_score(args) -> int:
    from .cvss.engine import score_vector

    _dump(score_vector(args.vector).as_dict())
    return 0


# --- report ----------------------------------------------------------------
def _report_generate(args) -> int:
    from .reporting.report import ReportData
    from .reporting.qa import run_qa

    with _ctx(args.program) as ctx:
        f = ctx.db.get_finding(_parse_id(args.finding))
        evidence = ctx.db.list_evidence()
        ev_by_id = {e.public_id: e for e in evidence}
        ev_lines = [f"- {r} ({ev_by_id.get(r).ref if r in ev_by_id else '?'})" for r in f.evidence_refs]

        cvss_vec = ""
        severity = args.severity or ""
        if f.cvss_data:
            cvss_vec = f.cvss_data.get("vector", "")
            severity = severity or f.cvss_data.get("severity", "")

        report = ReportData(
            title=args.title or f.title,
            summary=args.summary or f.impact_summary,
            affected_asset=f.affected_target,
            weakness=args.weakness or f.category,
            severity=severity,
            cvss_vector=cvss_vec,
            steps=_split_list(args.steps),
            poc=args.poc or "",
            expected_result=args.expected or "",
            actual_result=args.actual or "",
            impact=f.impact_summary,
            evidence=ev_lines,
            remediation=args.remediation or "",
        )
        text = report.render()
        qa = run_qa(report, finding_status=f.status)
        rep_dir = ctx.workspace / "reports"
        rep_dir.mkdir(parents=True, exist_ok=True)
        out_path = rep_dir / f"{f.public_id}.md"
        out_path.write_text(text, encoding="utf-8")
        ctx.db.set_finding_report_path(f.id, str(out_path))
    _out(f"wrote report -> {out_path}")
    _out(f"QA: {'PASS' if qa.passed else 'FAIL'} ({len(qa.issues)} issue(s))")
    for i in qa.issues:
        _out(f"  [{i.level}] {i.code}: {i.message}")
    return 0 if qa.passed else 1


def _section(text: str, heading: str) -> str:
    """Extract the body of a ``## heading`` section from rendered markdown."""
    import re

    m = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$\n?(.*?)(?=^##\s|\Z)", text, re.DOTALL)
    return (m.group(1).strip() if m else "")


def _report_from_markdown(name: str, text: str) -> "ReportData":
    import re

    from .reporting.report import ReportData

    title = name
    m = re.search(r"(?m)^#\s+(.+)$", text)
    if m:
        title = m.group(1).strip()
    steps = [s.rstrip(".") for s in _section(text, "Steps to Reproduce").splitlines() if s.strip()]
    poc = _section(text, "Proof of Concept") or ""
    evidence = ["present"] if _section(text, "Evidence").strip() else []
    return ReportData(
        title=title,
        summary=_section(text, "Summary"),
        affected_asset=_section(text, "Affected Asset"),
        cvss_vector=_section(text, "CVSS Vector").strip("`"),
        severity=_section(text, "Severity"),
        steps=steps,
        poc=poc,
        actual_result=_section(text, "Actual Result"),
        impact=_section(text, "Security Impact"),
        evidence=evidence,
    )


def _report_qa(args) -> int:
    from pathlib import Path as P

    from .reporting.qa import run_qa as _qa

    path = P(args.file)
    if not path.is_file():
        _err(f"report file not found: {path}")
        return 1
    text = path.read_text(encoding="utf-8")
    qa = _qa(_report_from_markdown(path.name, text))
    for i in qa.issues:
        _out(f"[{i.level}] {i.code}: {i.message}")
    _out(f"\nQA: {'PASS' if qa.passed else 'FAIL'} ({len(qa.issues)} issue(s))")
    return 0 if qa.passed else 1


# --- poc -------------------------------------------------------------------
def _poc(args) -> int:
    from .reporting.poc import PoC
    from .state.constants import FINDING_VALIDATED

    with _ctx(args.program) as ctx:
        f = ctx.db.get_finding(_parse_id(args.finding))
        poc_dir = ctx.workspace / "poc"
        poc_dir.mkdir(parents=True, exist_ok=True)
        doc = PoC(
            prerequisites=_split_list(args.prerequisites),
            account_setup=args.account_setup or "",
            baseline_behavior=args.baseline or "",
            controlled_change=args.controlled or "",
            reproduction_steps=_split_list(args.steps),
            observed_result=args.observed or "",
            impact_verification=args.impact or "",
            cleanup=args.cleanup or "",
            manual_only=bool(args.manual_only),
        )
        out_path = poc_dir / f"{f.public_id}.md"
        out_path.write_text(doc.render(), encoding="utf-8")
        # Advance the pipeline: a documented PoC promotes validated -> poc_ready.
        if f.status == FINDING_VALIDATED:
            f = ctx.db.transition_finding(f.id, "poc_ready")
    _out(f"wrote PoC -> {out_path}")
    _out(f"finding {f.public_id} -> {f.status}")
    return 0


# --- mcp -------------------------------------------------------------------
def _mcp_status(args) -> int:
    from .detection import detect_browser, detect_burp

    status = {}
    status["harness_mcp"] = {"available": _mcp_available()}
    status["burp"] = detect_burp()
    status["browser_playwright"] = detect_browser()
    _dump(status)
    return 0


def _mcp_available() -> bool:
    try:
        import mcp  # noqa: F401

        return True
    except ImportError:
        return False


def _mcp_serve(args) -> int:
    from .mcp.server import run

    run()
    return 0


# --- sync / start ----------------------------------------------------------
# --- approval ---------------------------------------------------------------
def _approval_list(args) -> int:
    with _ctx(args.program) as ctx:
        rows = ctx.db.list_approvals(args.status)
    _table("Approvals", ["id", "action", "target", "status", "requested_at"], [
        [a.public_id, a.action, a.target, a.status, a.requested_at] for a in rows
    ])
    return 0


def _approval_show(args) -> int:
    with _ctx(args.program) as ctx:
        a = ctx.db.get_approval(_parse_id(args.id))
        _dump({"id": a.public_id, "action": a.action, "target": a.target, "status": a.status,
               "requested_by": a.requested_by, "requested_at": a.requested_at, "note": a.note,
               "program": a.program, "method": a.method, "params_hash": a.params_hash,
               "expires_at": a.expires_at, "used_at": a.used_at,
               "approved_by": a.approved_by, "decided_at": a.decided_at})
    return 0


def _approval_decide(args, status: str) -> int:
    with _ctx(args.program) as ctx:
        a = ctx.db.decide_approval(_parse_id(args.id), status, decided_by="human")
    _out(f"approval {a.public_id} -> {a.status}")
    return 0


def _approval_expire(args) -> int:
    with _ctx(args.program) as ctx:
        a = ctx.db.expire_approval(_parse_id(args.id))
    _out(f"approval {a.public_id} -> {a.status}")
    return 0


def _sync(args) -> int:
    from .adapters.sync import sync_all

    result = sync_all(runtimes=(args.runtime or None))
    _dump(result)
    return 0


def _start(args) -> int:
    slug = _slug(args.program)
    from .adapters.session import start_session

    return start_session(args.runtime, slug)


def _hook(args) -> int:
    from .hooks import run_hook

    return run_hook(args.event)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness", description="Portable AI Bug Hunting Harness")
    p.add_argument("--version", action="version", version=f"harness {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def sp(name, **kw):
        return sub.add_parser(name, **kw)

    # init / doctor
    sp("init", help="initialize harness directories and registry")
    d = sp("doctor", help="run readiness checks")
    _add_program_arg(d)

    # program
    pr = sp("program", help="manage programs")
    prsub = pr.add_subparsers(dest="sub", required=True)
    pc = prsub.add_parser("create", help="create a program workspace")
    pc.add_argument("slug")
    pc.add_argument("--name", required=True)
    pc.add_argument("--platform", default="custom")
    pc.add_argument("--url", default=None)
    pc.add_argument("--notes", default=None)
    pc.add_argument("--fixture", action="store_true",
                    help="write a synthetic *.test scope for local/offline testing only")
    pl = prsub.add_parser("list"); pl.add_argument("--status", default=None)
    ps = prsub.add_parser("show"); _add_program_arg(ps)
    pu = prsub.add_parser("use"); pu.add_argument("slug")
    pa = prsub.add_parser("archive"); _add_program_arg(pa)
    pac = prsub.add_parser("activate"); _add_program_arg(pac)
    pe = prsub.add_parser("export"); _add_program_arg(pe); pe.add_argument("--dest", default=None)

    # engagement
    eng = sp("engagement", help="engagement config")
    engsub = eng.add_subparsers(dest="sub", required=True)
    ev = engsub.add_parser("validate"); _add_program_arg(ev)
    es = engsub.add_parser("status"); _add_program_arg(es)

    # scope / policy
    sc = sp("scope", help="scope operations")
    scsub = sc.add_subparsers(dest="sub", required=True)
    scc = scsub.add_parser("check"); _add_program_arg(scc); scc.add_argument("target")
    po = sp("policy", help="policy operations")
    posub = po.add_subparsers(dest="sub", required=True)
    poc = posub.add_parser("check"); _add_program_arg(poc); poc.add_argument("--action", required=True); poc.add_argument("--target", default=None)

    # lead
    l = sp("lead", help="leads")
    lsub = l.add_subparsers(dest="sub", required=True)
    ll = lsub.add_parser("list"); _add_program_arg(ll); ll.add_argument("--status", default=None)
    lsh = lsub.add_parser("show"); _add_program_arg(lsh); lsh.add_argument("id")
    la = lsub.add_parser("add"); _add_program_arg(la); la.add_argument("--title", required=True)
    la.add_argument("--entity", default=None); la.add_argument("--source", default=None)
    la.add_argument("--priority", default=None); la.add_argument("--rationale", default=None)
    lc = lsub.add_parser("claim"); _add_program_arg(lc); lc.add_argument("id")
    lr = lsub.add_parser("release"); _add_program_arg(lr); lr.add_argument("id")
    lcl = lsub.add_parser("close"); _add_program_arg(lcl); lcl.add_argument("id")

    # hypothesis
    h = sp("hypothesis", help="hypotheses")
    hsub = h.add_subparsers(dest="sub", required=True)
    hl = hsub.add_parser("list"); _add_program_arg(hl); hl.add_argument("--status", default=None)
    hsh = hsub.add_parser("show"); _add_program_arg(hsh); hsh.add_argument("id")
    hc = hsub.add_parser("create"); _add_program_arg(hc); hc.add_argument("--statement", required=True)
    hc.add_argument("--lead", default=None); hc.add_argument("--rationale", default=None); hc.add_argument("--confidence", type=float, default=None)
    hu = hsub.add_parser("update"); _add_program_arg(hu); hu.add_argument("id")
    hu.add_argument("--status", default=None); hu.add_argument("--statement", default=None); hu.add_argument("--rationale", default=None)

    # test
    t = sp("test", help="research tests")
    tsub = t.add_subparsers(dest="sub", required=True)
    tl = tsub.add_parser("list"); _add_program_arg(tl); tl.add_argument("--hypothesis", default=None)
    ta = tsub.add_parser("add"); _add_program_arg(ta); ta.add_argument("--hypothesis", required=True); ta.add_argument("--objective", required=True)
    ta.add_argument("--method", default=None); ta.add_argument("--change", default=None)
    ta.add_argument("--if-true", default=None); ta.add_argument("--if-false", default=None)
    tc = tsub.add_parser("complete"); _add_program_arg(tc); tc.add_argument("id")
    tc.add_argument("--result", required=True, choices=["supports", "rejects", "inconclusive"])
    tc.add_argument("--observation", required=True); tc.add_argument("--evidence", default=None)

    # evidence
    e = sp("evidence", help="evidence")
    esub = e.add_subparsers(dest="sub", required=True)
    ea = esub.add_parser("add"); _add_program_arg(ea); ea.add_argument("--kind", required=True); ea.add_argument("--ref", required=True)
    ea.add_argument("--description", default=None); ea.add_argument("--preview", default=None)
    el = esub.add_parser("list"); _add_program_arg(el)
    esh = esub.add_parser("show"); _add_program_arg(esh); esh.add_argument("id")

    # finding
    f = sp("finding", help="findings")
    fsub = f.add_subparsers(dest="sub", required=True)
    fl = fsub.add_parser("list"); _add_program_arg(fl); fl.add_argument("--status", default=None)
    fsh = fsub.add_parser("show"); _add_program_arg(fsh); fsh.add_argument("id")
    fc = fsub.add_parser("create"); _add_program_arg(fc); fc.add_argument("--title", required=True)
    fc.add_argument("--target", default=None); fc.add_argument("--category", default=None)
    fc.add_argument("--impact", default=None); fc.add_argument("--evidence", default=None)
    fv = fsub.add_parser("validate"); _add_program_arg(fv); fv.add_argument("id")
    fa = fsub.add_parser("adjudicate"); _add_program_arg(fa); fa.add_argument("id")
    fa.add_argument("--verdict", required=True, choices=["supported", "rejected", "inconclusive"]); fa.add_argument("--reason", default=None)
    fr = fsub.add_parser("reject"); _add_program_arg(fr); fr.add_argument("id"); fr.add_argument("--reason", default=None)
    fcv = fsub.add_parser("cvss"); _add_program_arg(fcv); fcv.add_argument("id"); fcv.add_argument("--vector", required=True)

    # approval
    ap = sp("approval", help="human approval queue")
    apsub = ap.add_subparsers(dest="sub", required=True)
    apl = apsub.add_parser("list"); _add_program_arg(apl); apl.add_argument("--status", default=None)
    apsh = apsub.add_parser("show"); _add_program_arg(apsh); apsh.add_argument("id")
    apap = apsub.add_parser("approve"); _add_program_arg(apap); apap.add_argument("id")
    aprj = apsub.add_parser("reject"); _add_program_arg(aprj); aprj.add_argument("id")
    apex = apsub.add_parser("expire"); _add_program_arg(apex); apex.add_argument("id")

    # checkpoint
    ck = sp("checkpoint", help="checkpoints")
    cksub = ck.add_subparsers(dest="sub", required=True)
    cks = cksub.add_parser("save"); _add_program_arg(cks); cks.add_argument("--lead", default=None)
    cks.add_argument("--hypotheses", default=None); cks.add_argument("--next", default=None)
    cksh = cksub.add_parser("show"); _add_program_arg(cksh); cksh.add_argument("id")
    ckl = cksub.add_parser("latest"); _add_program_arg(ckl)

    # knowledge
    k = sp("knowledge", help="knowledge management")
    ksub = k.add_subparsers(dest="sub", required=True)
    kl = ksub.add_parser("list"); _add_program_arg(kl)
    kp = ksub.add_parser("promote"); _add_program_arg(kp); kp.add_argument("--file", required=True)
    kc = ksub.add_parser("candidates")
    ks = ksub.add_parser("status")

    # skills
    s = sp("skill", help="skills")
    ssub = s.add_subparsers(dest="sub", required=True)
    sl = ssub.add_parser("list")
    sv = ssub.add_parser("validate")
    se = ssub.add_parser("eval"); se.add_argument("name", nargs="?")

    # cvss
    c = sp("cvss", help="score a CVSS vector")
    c.add_argument("vector")

    # report
    r = sp("report", help="reports")
    rsub = r.add_subparsers(dest="sub", required=True)
    rg = rsub.add_parser("generate"); _add_program_arg(rg); _add_finding_arg(rg)
    rg.add_argument("--title", default=None); rg.add_argument("--summary", default=None)
    rg.add_argument("--weakness", default=None); rg.add_argument("--severity", default=None)
    rg.add_argument("--steps", default=None); rg.add_argument("--poc", default=None)
    rg.add_argument("--expected", default=None); rg.add_argument("--actual", default=None)
    rg.add_argument("--remediation", default=None)
    rq = rsub.add_parser("qa"); rq.add_argument("file")

    # poc
    pc = sp("poc", help="document a proof-of-concept and advance to poc_ready")
    _add_program_arg(pc); _add_finding_arg(pc)
    pc.add_argument("--steps", default=None)
    pc.add_argument("--prerequisites", default=None)
    pc.add_argument("--observed", default=None)
    pc.add_argument("--baseline", default=None)
    pc.add_argument("--controlled", default=None)
    pc.add_argument("--impact", default=None)
    pc.add_argument("--account-setup", default=None)
    pc.add_argument("--cleanup", default=None)
    pc.add_argument("--manual-only", action="store_true")

    # mcp
    m = sp("mcp", help="MCP")
    msub = m.add_subparsers(dest="sub", required=True)
    ms = msub.add_parser("status")
    msv = msub.add_parser("serve")

    # sync / start
    sy = sp("sync", help="generate runtime configs from canonical files")
    sy.add_argument("--runtime", action="append", choices=["claude", "codex", "opencode"], default=None)
    st = sp("start", help="bind a session to a program and launch a runtime")
    st.add_argument("runtime", choices=["claude", "codex", "opencode"])
    _add_program_arg(st)

    hk = sp("hook", help="(internal) lifecycle hook entry invoked by runtime configs")
    hk.add_argument(
        "event",
        choices=[
            "session-start",
            "user-prompt-submit",
            "pre-tool-use",
            "post-tool-use",
            "stop",
            "session-end",
            "pre-compact",
        ],
    )

    return p


def _dispatch(args) -> int:
    cmd, sub = args.command, getattr(args, "sub", None)

    handlers = {
        "init": cmd_init,
        "doctor": cmd_doctor,
        "program": {
            "create": _program_create, "list": _program_list, "show": _program_show, "use": _program_use,
            "archive": lambda a: _program_status(a, "archived"), "activate": lambda a: _program_status(a, "active"),
            "export": _program_export,
        },
        "engagement": {"validate": _engagement_validate, "status": _engagement_status},
        "scope": {"check": _scope_check},
        "policy": {"check": _policy_check},
        "lead": {"list": _lead_list, "show": _lead_show, "add": _lead_add, "claim": _lead_claim, "release": _lead_release, "close": _lead_close},
        "hypothesis": {"list": _hyp_list, "show": _hyp_show, "create": _hyp_create, "update": _hyp_update},
        "test": {"list": _test_list, "add": _test_add, "complete": _test_complete},
        "evidence": {"add": _evidence_add, "list": _evidence_list, "show": _evidence_show},
        "finding": {
            "list": _finding_list, "show": _finding_show, "create": _finding_create, "validate": _finding_validate,
            "adjudicate": _finding_adjudicate, "reject": _finding_reject, "cvss": _finding_cvss,
        },
        "checkpoint": {"save": _checkpoint_save, "show": _checkpoint_show, "latest": _checkpoint_latest},
        "knowledge": {"list": _knowledge_list, "promote": _knowledge_promote, "candidates": _knowledge_candidates, "status": _knowledge_status},
        "approval": {
            "list": _approval_list, "show": _approval_show,
            "approve": lambda a: _approval_decide(a, "approved"),
            "reject": lambda a: _approval_decide(a, "rejected"),
            "expire": _approval_expire,
        },
        "skill": {"list": _skill_list, "validate": _skill_validate, "eval": _skill_eval},
        "cvss": _cvss_score,
        "report": {"generate": _report_generate, "qa": _report_qa},
        "poc": _poc,
        "mcp": {"status": _mcp_status, "serve": _mcp_serve},
        "sync": _sync,
        "start": _start,
        "hook": _hook,
    }

    h = handlers.get(cmd)
    if isinstance(h, dict):
        h = h.get(sub)
    if h is None:
        _err(f"no handler for {cmd} {sub or ''}")
        return 2
    return h(args)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except HarnessError as exc:
        _err(f"error: {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())