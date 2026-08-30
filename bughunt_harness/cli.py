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


def _bound_or_new_session(ctx, role: str, runtime: str = "cli"):
    raw = os.environ.get("BUGHUNT_SESSION_ID", "").strip()
    if raw.isdigit():
        return ctx.db.require_session(int(raw), program_slug=ctx.slug)
    return ctx.db.start_session(runtime, role, ctx.slug)


def _require_human_cli(capability: str) -> None:
    role = os.environ.get("BUGHUNT_AGENT_ROLE", "").strip().lower()
    if role and role not in {"human", "manual", "debug"}:
        raise HarnessError(f"{capability} is human-only and unavailable to agent role {role!r}")


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_init(args) -> int:
    cfg = get_config()
    cfg.write_default_config()
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

    report = run_doctor(
        args.program, deep=bool(getattr(args, "deep", False)),
        model_smoke=bool(getattr(args, "model_smoke", False)),
        runtime=getattr(args, "runtime", "claude"),
    )
    _dump(report.render())
    # Exit 0 when env+core are sound (CORE/HUNT/FULL ready); exit 1 only when
    # the environment or install is broken (ENV_READY / NOT_READY).  A fresh
    # install with no program yet reports CORE_READY — sound, not an error — so
    # bootstrap can fail the script on a broken install without `|| true`.
    return report.exit_code


def _acceptance_model_smoke(args) -> int:
    from .acceptance import run_model_smoke

    result = run_model_smoke(runtime=args.runtime, timeout_seconds=args.timeout)
    _dump(result.as_dict())
    return 0 if result.ok else 1


def _acceptance_whitebox_model_smoke(args) -> int:
    from .acceptance import run_whitebox_model_smoke

    result = run_whitebox_model_smoke(runtime=args.runtime, timeout_seconds=args.timeout)
    _dump(result.as_dict())
    return 0 if result.ok else 1


def _acceptance_recover_whitebox_model_smoke(args) -> int:
    from .acceptance import recover_whitebox_model_smoke

    result = recover_whitebox_model_smoke(args.program)
    _dump(result.as_dict())
    return 0 if result.ok else 1


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
            slug=args.slug, name=args.name or args.slug, platform=args.platform or "custom",
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


def _program_activate(args) -> int:
    """Activate only a complete, internally consistent engagement."""
    from .engagement.workspace import load_engagement, write_program_status
    from .registry import ProgramRegistry

    _require_human_cli("program activation")
    slug = _slug(args.program)
    from .program_intake.service import ProgramIntakeService
    intake_service = ProgramIntakeService()
    try:
        # Imported authorization can never be force-activated around its
        # human approval/hash gate. Legacy/manual programs remain compatible.
        intake_service.assert_activation_ready(slug)
    except HarnessError as exc:
        _err(f"activation refused: {exc}")
        return 1
    reg = ProgramRegistry()
    try:
        rec = reg.get(slug)
        marker = Path(rec.workspace_path) / ".force-activated"
        try:
            engagement = load_engagement(Path(rec.workspace_path))
            by_name = engagement.headers.by_name()
            missing_headers = [
                name for name in engagement.roe.required_headers
                if name.lower() not in by_name
            ]
            if missing_headers:
                raise HarnessError(
                    f"required_headers lack headers.yaml metadata: {missing_headers}"
                )
        except Exception as exc:  # validation boundary
            if not args.force:
                _err(f"activation refused: engagement validation failed: {exc}")
                return 1
            marker.write_text(
                f"FORCED administrative activation; not HUNT_READY. Reason: {type(exc).__name__}: {exc}\n",
                encoding="utf-8",
            )
            _err("WARNING: forced activation is administrative only; doctor will not report HUNT_READY")
        else:
            marker.unlink(missing_ok=True)
        reg.set_status(slug, "active")
        rec = reg.get(slug)
        reg.set_active(slug)
    finally:
        reg.close()
    write_program_status(rec)
    intake_service.mark_active(slug)
    _out(f"program {slug} -> active")
    return 0


def _program_export(args) -> int:
    import shutil

    slug = _slug(args.program)
    from .hunt import load_program_context

    with load_program_context(slug) as ctx:
        dest = Path(args.dest) if args.dest else Path.cwd() / f"{slug}-export"
        dest.mkdir(parents=True, exist_ok=True)
        EXCLUDE_DIRS = {"state", "intake", "evidence", "findings", "reports", "browser", "burp", "logs", "checkpoints", "artifacts", "recon"}
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


def _program_import(args) -> int:
    from .program_intake.service import ProgramIntakeService
    from .program_intake.policy_parser import constrained_model_extractor

    source_file = args.from_file or args.from_json
    llm_extract = constrained_model_extractor(args.llm_policy_parser) if args.llm_policy_parser else None
    result = ProgramIntakeService().import_program(
        platform=args.platform, handle=args.handle, url=args.url,
        credential_name=args.credential, from_file=Path(source_file) if source_file else None,
        slug=args.slug, confirm_generic_url=args.confirm_generic_url,
        llm_extract=llm_extract,
    )
    _dump(result)
    return 0


def _program_intake_status(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _dump(ProgramIntakeService().status(_slug(args.program)))
    return 0


def _program_review(args) -> int:
    from .program_intake.service import ProgramIntakeService
    service = ProgramIntakeService()
    slug = _slug(args.program)
    summary = service.review(slug, args.import_id)
    if not args.interactive:
        _dump(summary)
        return 0
    open_items = [item for item in service.ambiguities(slug, args.import_id) if item["status"] == "OPEN"]
    for index, item in enumerate(open_items, 1):
        _out(f"[{index}/{len(open_items)}] {item['severity']} {item['category']}")
        _out(item["reason"])
        if item["proposed_value"] is not None:
            _out("Recommended: " + json.dumps(item["proposed_value"], default=str))
        choice = input("[A] Approve recommendation  [E] Edit JSON/value  [S] Skip: ").strip().lower()
        if choice == "a" and item["proposed_value"] is not None:
            service.resolve_ambiguity(slug, item["public_id"], value=item["proposed_value"])
        elif choice == "e":
            raw = input("Value (JSON or text): ")
            service.resolve_ambiguity(slug, item["public_id"], value=_json_or_text(raw))
    _dump(service.review(slug, args.import_id))
    return 0


def _program_ambiguities(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _dump(ProgramIntakeService().ambiguities(_slug(args.program), args.import_id))
    return 0


def _program_ambiguity_resolve(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _require_human_cli("program ambiguity resolution")
    _dump(ProgramIntakeService().resolve_ambiguity(
        _slug(args.program), args.id, value=_json_or_text(args.value), resolved_by=args.resolved_by,
    ))
    return 0


def _program_approve_import(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _require_human_cli("program import approval")
    service = ProgramIntakeService()
    slug = _slug(args.program)
    summary = service.review(slug)
    _dump({
        "program": summary["program"], "scope": summary["scope"],
        "open_critical": sum(item["severity"] == "CRITICAL" and item["status"] == "OPEN"
                             for item in summary["clarifications"]),
        "local_safety_defaults": summary["local_safety_defaults"],
        "effect": "promote exact normalized draft; activation remains separate",
    })
    if input("Approve this exact import draft? [y/N] ").strip().lower() not in {"y", "yes"}:
        _out("approval cancelled; nothing changed")
        return 1
    _dump(service.approve(slug, approved_by=args.approved_by, actor_kind="human", notes=args.notes or ""))
    return 0


def _program_refresh(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _dump(ProgramIntakeService().refresh(
        _slug(args.program), credential_name=args.credential,
        from_file=Path(args.from_file) if args.from_file else None,
    ))
    return 0


def _program_diff(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _dump(ProgramIntakeService().diff(_slug(args.program), args.import_id))
    return 0


def _program_provenance(args) -> int:
    from .program_intake.service import ProgramIntakeService
    _dump(ProgramIntakeService().provenance(_slug(args.program), scope=args.scope))
    return 0


def _platform_status(args) -> int:
    from .program_intake.adapters import adapter_for
    from .program_intake.credentials import PlatformCredentialStore
    credentials = PlatformCredentialStore().list_safe()
    _dump({"platforms": [{
        "platform": name,
        "adapter": "PASS",
        "capabilities": adapter_for(name).capabilities.model_dump(mode="json"),
        "credentials": [row for row in credentials if row["platform"] == name],
        "api_reachability": "NOT_CHECKED (status is offline by default)",
    } for name in ("hackerone", "bugcrowd", "intigriti", "yeswehack", "generic")]})
    return 0


def _platform_credential_add(args) -> int:
    from .program_intake.credentials import PlatformCredentialStore
    _require_human_cli("platform credential changes")
    token_ref = args.token_ref or input("Token secret reference (env:/keyring:/file:): ").strip()
    username_ref = args.username_ref
    if args.platform == "hackerone" and not username_ref:
        username_ref = input("API username secret reference (env:/keyring:/file:): ").strip()
    PlatformCredentialStore().add(
        args.platform, args.name, username_ref=username_ref, token_ref=token_ref,
    )
    _out(f"configured {args.platform}/{args.name}; value: [REDACTED]")
    return 0


def _platform_credential_list(args) -> int:
    from .program_intake.credentials import PlatformCredentialStore
    _dump(PlatformCredentialStore().list_safe())
    return 0


def _json_or_text(raw: str):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        lowered = raw.strip().lower()
        if lowered == "true": return True
        if lowered == "false": return False
        return raw


# --- engagement ------------------------------------------------------------
def _engagement_validate(args) -> int:
    slug = _slug(args.program)
    from .hunt import load_program_context

    try:
        from .program_intake.service import ProgramIntakeService
        ProgramIntakeService().assert_activation_ready(slug)
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


def _policy_matrix(args) -> int:
    from .actions import ACTIONS

    with _ctx(args.program) as ctx:
        rows = []
        for name in sorted(ACTIONS):
            decision = ctx.policy.check(name)
            rows.append([name, decision.as_dict()["mode"], decision.risk_class, decision.reason])
    _table("Autonomy policy matrix", ["ACTION", "MODE", "RISK", "REASON"], rows)
    return 0


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
        session = _bound_or_new_session(ctx, "researcher")
        l = ctx.db.claim_lead(_parse_id(args.id), session.id)
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
        session = _bound_or_new_session(ctx, "researcher")
        f = ctx.db.create_finding(
            args.title, args.target or "", args.category or "", args.impact or "",
            _split_list(args.evidence),
            lead_id=_parse_id(args.lead) if args.lead else None,
            hypothesis_id=_parse_id(args.hypothesis) if args.hypothesis else None,
            test_ids=[_parse_id(v) for v in _split_list(args.tests)],
            creator_session_id=session.id,
        )
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
                review = ctx.db.begin_validation(
                    f.id, requested_by="cli-researcher", reviewer_type="finding-validator",
                )
                _out(f"-> entered validation: {f.public_id}; review {review.public_id} awaits an independent finding-validator")
            elif f.status == FINDING_VALIDATION:
                _out(f"-> already in validation: {f.public_id} (submit a validation review to finalize)")
        elif verdict.verdict == "killed":
            if f.status in (FINDING_CANDIDATE, FINDING_VALIDATION):
                f = ctx.db.transition_finding(f.id, FINDING_KILLED, validation_state="killed")
                _out(f"-> killed: {f.public_id}")
    return 0


def _finding_adjudicate(args) -> int:
    from .state.constants import FINDING_CANDIDATE, FINDING_VALIDATION

    if os.environ.get("BUGHUNT_SESSION_ID"):
        _err("finding adjudicate is human CLI-only; an AI session must use the independent validator runtime")
        return 1
    with _ctx(args.program) as ctx:
        db = ctx.db
        fid = _parse_id(args.id)
        f = db.get_finding(fid)
        if f.status == FINDING_CANDIDATE:
            f = db.transition_finding(fid, FINDING_VALIDATION)
        elif f.status != FINDING_VALIDATION:
            _err(f"finding {f.public_id} must be 'candidate' or 'validation' to adjudicate (is {f.status})")
            return 1
        # A separate role-bound session is the provenance boundary.  Human CLI
        # input supplies the independent validator's structured judgment; the
        # deterministic finalizer remains the sole path to `validated`.
        review = db.latest_validation_review(fid)
        if review is None or review.status != "open":
            review = db.begin_validation(fid, requested_by="cli", reviewer_type="finding-validator")
        validator = db.start_session("cli", "finding-validator", ctx.slug)
        passed = args.verdict == "supported"
        if passed and not all((args.prerequisite, args.boundary, args.attacker_control)):
            db.end_session(validator.id)
            _err("supported adjudication requires --prerequisite, --boundary, and --attacker-control")
            return 1
        checks = {
            "scope_eligible": {"passed": passed},
            "reproducible": {"passed": passed, "evidence": f.evidence_refs},
            "prerequisites": {"value": args.prerequisite or "not established"},
            "security_boundary": {"value": args.boundary or "not established"},
            "attacker_control": {"value": args.attacker_control or "not established"},
            "demonstrated_impact": {"value": f.impact_summary if passed else "not demonstrated", "evidence": f.evidence_refs},
            "intended_behavior": {"passed": passed},
            "false_positive_analysis": {"passed": passed},
            "evidence_quality": {"passed": passed},
            "minimal_impact": {"passed": passed},
            "program_exclusions": {"passed": passed},
        }
        submitted = db.submit_validation_review(
            review.id, args.verdict, reasoning_summary=args.reason or "",
            reviewer_runtime="cli", reviewer_session=validator.public_id,
            check_results=checks, evidence_refs=f.evidence_refs if passed else [],
            reviewer_role="finding-validator", reviewer_session_id=validator.id,
        )
        db.end_session(validator.id)
        result = db.finalize_validation(
            fid, scope_engine=ctx.scope, program_active=ctx.record.status == "active",
        )
        _out(f"review {submitted.public_id} submitted ({submitted.verdict}); finding {result.public_id} -> {result.status}")
    return 0


def _finding_validate_auto(args) -> int:
    from .findings.independent import run_independent_validator

    with _ctx(args.program) as ctx:
        result = run_independent_validator(
            ctx, _parse_id(args.id), runtime=args.runtime, timeout_seconds=args.timeout,
        )
    _dump(result)
    return 0


def _finding_reject(args) -> int:
    from .state.constants import FINDING_REJECTED

    with _ctx(args.program) as ctx:
        f = ctx.db.transition_finding(_parse_id(args.id), FINDING_REJECTED)
        _out(f"rejected finding {f.public_id} (reason: {args.reason or '(none)'})")
    return 0


def _finding_cvss(args) -> int:
    import yaml

    from .cvss.reasoning import score_with_reasoning
    from .state.constants import FINDING_SCORED, FINDING_POC_READY

    with _ctx(args.program) as ctx:
        f = ctx.db.get_finding(_parse_id(args.id))
        if not args.reasoning:
            _err("finding CVSS requires --reasoning <yaml-or-json> with per-metric rationale/evidence/uncertainty")
            return 1
        reasoning_path = Path(args.reasoning)
        if not reasoning_path.is_file():
            _err(f"CVSS reasoning file not found: {reasoning_path}")
            return 1
        reasoning = yaml.safe_load(reasoning_path.read_text(encoding="utf-8")) or {}
        result = score_with_reasoning(
            args.vector, reasoning, finding_evidence=f.evidence_refs,
        )
        ctx.db.set_finding_cvss(f.id, result)
        f = ctx.db.get_finding(f.id)
        if f.status == FINDING_POC_READY:
            try:
                ctx.db.transition_finding(f.id, FINDING_SCORED)
            except HarnessError:
                pass
        _dump(result)
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
    if getattr(args, "behavioral", False):
        from .skills.behavioral import run_behavioral_evals
        results = run_behavioral_evals(
            runtime=args.runtime, skill=args.name, timeout_seconds=args.timeout,
            ablation=args.ablation, runs=args.runs, judge=args.judge,
            judge_runtime=args.judge_runtime,
            output_path=args.output,
        )
    else:
        from .skills.eval import run_eval
        results = run_eval(args.name)
    _dump(results)
    return 0


def _skill_audit(args) -> int:
    from .skills.registry import quality_audit
    _dump(quality_audit())
    return 0


# --- source / whitebox -----------------------------------------------------
def _source_detect(args) -> int:
    from .source import detect_source_tools
    _dump(detect_source_tools())
    return 0


def _source_install_guide(args) -> int:
    from .source import source_install_guide
    _dump(source_install_guide())
    return 0


def _source_add(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).add_repository(
            args.repo, args.ref, repository_id=args.repository_id or "",
            program_relation=args.relation, license_info=args.license or "",
        ))
    return 0


def _source_list(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.list_source_repositories(status=args.status))
    return 0


def _source_show(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.get_source_repository(args.repository))
    return 0


def _source_update(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).update_repository(args.repository, args.ref or ""))
    return 0


def _source_changes(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).detect_changes(args.repository))
    return 0


def _source_prepare_dependencies(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).prepare_dependency_snapshot(args.repository, args.snapshot))
    return 0


def _source_relate_service(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).relate_service(
            args.repository, hosts=args.host, base_paths=args.base_path,
            runtime_version=args.runtime_version or "", confirmed_by=args.confirmed_by,
        ))
    return 0


def _source_context(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).build_context(args.repository))
    return 0


def _source_search(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).search(
            args.repository, args.pattern, glob=args.glob or "",
            regex=args.regex, limit=args.limit,
        ))
    return 0


def _source_read(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).read_file(
            args.repository, args.file, line_start=args.line_start,
            line_end=args.line_end,
        ))
    return 0


def _source_audit(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        service = SourceService(ctx)
        if args.analysis == "authorization":
            result = service.audit_authorization_inconsistencies(args.repository)
        elif args.analysis == "dataflow":
            result = service.analyze_dataflow(args.repository)
        elif args.analysis == "differential":
            result = service.differential_review(args.repository)
        elif args.analysis == "semgrep":
            result = service.run_semgrep(args.repository, args.rule)
        elif args.analysis == "codeql":
            result = service.run_codeql(args.repository, args.database, args.rule)
        elif args.analysis == "dependencies":
            result = service.run_dependency_scan(args.repository)
        elif args.analysis == "secrets":
            result = service.run_secret_scan(args.repository)
        else:
            result = service.build_context(args.repository)
        _dump(result)
    return 0


def _source_observations(args) -> int:
    with _ctx(args.program) as ctx:
        repository_id = None
        if args.repository:
            repository_id = ctx.db.get_source_repository(args.repository)["id"]
        _dump(ctx.db.list_source_observations(
            repository_id, status=args.status, min_confidence=args.min_confidence,
            limit=args.limit,
        ))
    return 0


def _source_map(args) -> int:
    from .source import SourceService
    with _ctx(args.program) as ctx:
        _dump(SourceService(ctx).correlate_runtime(args.repository))
    return 0


def _source_symbols(args) -> int:
    with _ctx(args.program) as ctx:
        repo = ctx.db.get_source_repository(args.repository)
        _dump(ctx.db.list_source_symbols(repo["id"], name=args.name or "", kind=args.kind or "", limit=args.limit))
    return 0


def _source_sandbox(args) -> int:
    from .source_sandbox import SandboxLimits, SourceSandboxExecutor
    with _ctx(args.program) as ctx:
        executor = SourceSandboxExecutor(ctx)
        if args.plan:
            result = executor.plan(args.repository, args.operation, entrypoint=args.entrypoint or "")
        else:
            if not args.session:
                raise HarnessError("--session is required to request/use sandbox approval")
            result = executor.execute(
                args.repository, args.operation, session_id=_parse_id(args.session),
                approval_id=_parse_id(args.approval) if args.approval else None,
                entrypoint=args.entrypoint or "",
                limits=SandboxLimits(wall_seconds=args.timeout),
            )
        _dump(result)
    return 0


def _hunt_metrics(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.hunt_metrics(_parse_id(args.run)))
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
        if f.status != "scored":
            _err(f"report generation requires a scored finding (is {f.status})")
            return 1
        evidence = [e for e in ctx.db.list_evidence() if e.public_id in set(f.evidence_refs)]
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
            prerequisites=_split_list(args.prerequisites),
            steps=_split_list(args.steps),
            poc=args.poc or (
                Path(f.poc_path).read_text(encoding="utf-8")
                if f.poc_path and Path(f.poc_path).is_file() else ""
            ),
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
        if qa.passed:
            f = ctx.db.transition_finding(f.id, "report_ready")
            f = ctx.db.transition_finding(f.id, "qa_passed")
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
        weakness=_section(text, "Weakness"),
        cvss_vector=_section(text, "CVSS Vector").strip("`"),
        severity=_section(text, "Severity"),
        prerequisites=[
            line.lstrip("- ").strip()
            for line in _section(text, "Prerequisites").splitlines() if line.strip()
        ],
        steps=steps,
        poc=poc,
        expected_result=_section(text, "Expected Result"),
        actual_result=_section(text, "Actual Result"),
        impact=_section(text, "Security Impact"),
        evidence=evidence,
        remediation=_section(text, "Remediation"),
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
    from .reporting.poc import PoC, run_poc_qa
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
        qa = run_poc_qa(doc, evidence_refs=f.evidence_refs, finding_status=f.status)
        if qa.passed and f.status == FINDING_VALIDATED:
            ctx.db.set_finding_poc_path(f.id, str(out_path))
            f = ctx.db.transition_finding(f.id, "poc_ready")
    _out(f"wrote PoC -> {out_path}")
    _out(f"finding {f.public_id} -> {f.status}")
    for issue in qa.issues:
        _out(f"  [fail] {issue}")
    return 0 if qa.passed else 1


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

    return start_session(
        args.runtime, slug, autonomous=bool(getattr(args, "autonomous", False)),
        goal=getattr(args, "goal", None),
    )


def _hunt(args) -> int:
    from .adapters.session import start_session

    return start_session(args.runtime, _slug(args.program), autonomous=True, goal=args.goal)


def _recon_detect(args) -> int:
    from .recon import detect_recon_tools

    _dump(detect_recon_tools())
    return 0


def _recon_run(args) -> int:
    from .recon import run_authorized_recon

    created = False
    with _ctx(args.program) as ctx:
        raw = os.environ.get("BUGHUNT_SESSION_ID", "").strip()
        if raw.isdigit():
            session = ctx.db.require_session(int(raw), program_slug=ctx.slug, running=True)
        else:
            session = ctx.db.start_session("cli", "recon-executor", ctx.slug)
            created = True
        try:
            result = run_authorized_recon(
                ctx, stage=args.stage, profile=args.profile, seeds=args.seed, session_id=session.id,
                max_results=args.max_results, timeout_seconds=args.timeout,
                approval_id=_parse_id(args.approval) if args.approval else None,
            )
            _dump(result.as_dict())
            return 0 if result.ok else 2 if result.mode == "ASK" else 1
        finally:
            if created:
                ctx.db.end_session(session.id)


def _recon_runs(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.list_recon_runs(limit=args.limit))
    return 0


def _recon_show(args) -> int:
    with _ctx(args.program) as ctx:
        run = ctx.db.get_recon_run(_parse_id(args.id))
        run["changes"] = ctx.db.list_recon_changes(recon_run_id=run["id"], limit=args.limit)
        _dump(run)
    return 0


def _recon_diff(args) -> int:
    from .recon import diff_recon_runs
    with _ctx(args.program) as ctx:
        _dump(diff_recon_runs(ctx, _parse_id(args.first), _parse_id(args.second)))
    return 0


def _recon_assets(args, asset_type: str | None = None) -> int:
    with _ctx(args.program) as ctx:
        items = ctx.db.list_assets(
            type=asset_type, interesting=True if args.interesting else None,
            min_score=args.min_score, host=args.host or "", source=args.source or "",
            since=args.since or "", limit=args.limit,
        )
        if args.new:
            latest = ctx.db.list_recon_runs(limit=1)
            ids = {c["entity_id"] for c in ctx.db.list_recon_changes(recon_run_id=latest[0]["id"], change_type="NEW_ASSET") } if latest else set()
            items = [item for item in items if item["id"] in ids]
        _dump(items)
    return 0


def _recon_hosts(args) -> int:
    return _recon_assets(args, "host")


def _recon_urls(args) -> int:
    return _recon_assets(args, "url")


def _recon_endpoints(args) -> int:
    with _ctx(args.program) as ctx:
        items = ctx.db.list_endpoints(
            interesting=True if args.interesting else None, min_score=args.min_score,
            host=args.host or "", source=args.source or "", since=args.since or "", limit=args.limit,
        )
        if args.new:
            latest = ctx.db.list_recon_runs(limit=1)
            ids = {c["entity_id"] for c in ctx.db.list_recon_changes(recon_run_id=latest[0]["id"], change_type="NEW_ENDPOINT")} if latest else set()
            items = [item for item in items if item["id"] in ids]
        _dump(items)
    return 0


def _recon_parameters(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.list_endpoint_parameters(host=args.host or "", since=args.since or "", limit=args.limit))
    return 0


def _recon_technologies(args) -> int:
    with _ctx(args.program) as ctx:
        _dump(ctx.db.list_technology_observations(since=args.since or "", limit=args.limit))
    return 0


def _recon_changes(args) -> int:
    with _ctx(args.program) as ctx:
        runs = ctx.db.list_recon_runs(limit=1)
        run_id = _parse_id(args.run) if args.run else (runs[0]["id"] if runs else None)
        _dump(ctx.db.list_recon_changes(recon_run_id=run_id, change_type=args.type or "", since=args.since or "", limit=args.limit))
    return 0


def _recon_interesting(args) -> int:
    from .recon import get_recon_summary
    with _ctx(args.program) as ctx:
        summary = get_recon_summary(ctx, limit=args.limit)
        _dump(summary["top_research_surfaces"])
    return 0


def _recon_summary(args) -> int:
    from .recon import get_recon_summary
    with _ctx(args.program) as ctx:
        _dump(get_recon_summary(ctx, limit=args.limit))
    return 0


def _recon_install_guide(args) -> int:
    from .recon import detect_recon_tools
    tools = detect_recon_tools()
    _dump({"missing": [{"tool": name, "profiles": item["profiles"], "install": item["recommended_install_reference"]} for name, item in tools.items() if not item["available"]], "note": "Guidance only; the harness never installs binaries automatically."})
    return 0


def _auth_list(args) -> int:
    """Show credential availability only; never emit refs or resolved values."""
    with _ctx(args.program) as ctx:
        _dump({"program": ctx.slug, "auth_contexts": ctx.secrets.account_summaries(
            ctx.engagement.accounts.accounts,
        )})
    return 0


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
    d.add_argument("--deep", action="store_true", help="run safe local integration and readiness probes")
    d.add_argument("--model-smoke", action="store_true", help="run the optional paid real-model localhost acceptance hunt")
    d.add_argument("--runtime", choices=["claude", "codex"], default="claude")

    acceptance = sp("acceptance", help="optional local-only acceptance workflows")
    acceptance_sub = acceptance.add_subparsers(dest="sub", required=True)
    model_smoke = acceptance_sub.add_parser("model-smoke", help="run a real model-driven localhost hunt")
    model_smoke.add_argument("--runtime", choices=["claude", "codex"], default="claude")
    model_smoke.add_argument("--timeout", type=int, default=2400)
    whitebox_smoke = acceptance_sub.add_parser(
        "whitebox-model-smoke", help="run the paid real-model WHITEBOX to runtime acceptance",
    )
    whitebox_smoke.add_argument("--runtime", choices=["claude", "codex"], default="claude")
    whitebox_smoke.add_argument("--timeout", type=int, default=2400)
    whitebox_recover = acceptance_sub.add_parser(
        "recover-whitebox-model-smoke",
        help="apply an already-submitted independent review after a local smoke runtime exit",
    )
    whitebox_recover.add_argument("--program", required=True)

    # program
    pr = sp("program", help="manage programs")
    prsub = pr.add_subparsers(dest="sub", required=True)
    pc = prsub.add_parser("create", help="create a program workspace")
    pc.add_argument("slug")
    pc.add_argument("--name", default=None)
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
    pac.add_argument("--force", action="store_true", help="administrative override; never HUNT_READY")
    pe = prsub.add_parser("export"); _add_program_arg(pe); pe.add_argument("--dest", default=None)
    pi = prsub.add_parser("import", help="import an official platform program into a review draft")
    pi.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti", "yeswehack", "generic", "custom"], default=None)
    pi.add_argument("--handle", default=None); pi.add_argument("--url", default=None)
    pi.add_argument("--credential", default=None); pi.add_argument("--slug", default=None)
    pi.add_argument("--from-file", default=None); pi.add_argument("--from-json", default=None)
    pi.add_argument("--confirm-generic-url", action="store_true")
    pi.add_argument(
        "--llm-policy-parser", choices=["claude"], default=None,
        help="propose unresolved policy rules with a constrained no-tool model; human approval remains required",
    )
    pis = prsub.add_parser("intake-status"); _add_program_arg(pis)
    prv = prsub.add_parser("review"); _add_program_arg(prv)
    prv.add_argument("--import-id", default=None); prv.add_argument("--json", action="store_true")
    prv.add_argument("--interactive", action="store_true")
    pamb = prsub.add_parser("ambiguities"); _add_program_arg(pamb); pamb.add_argument("--import-id", default=None)
    pares = prsub.add_parser("ambiguity", help="resolve one grouped intake ambiguity")
    pares_sub = pares.add_subparsers(dest="ambiguity_action", required=True)
    pares_resolve = pares_sub.add_parser("resolve"); _add_program_arg(pares_resolve)
    pares_resolve.add_argument("id"); pares_resolve.add_argument("--value", required=True)
    pares_resolve.add_argument("--resolved-by", default="human")
    papi = prsub.add_parser("approve-import"); _add_program_arg(papi)
    papi.add_argument("--approved-by", default="human"); papi.add_argument("--notes", default=None)
    pref = prsub.add_parser("refresh"); _add_program_arg(pref)
    pref.add_argument("--credential", default=None); pref.add_argument("--from-file", default=None)
    pdiff = prsub.add_parser("diff"); _add_program_arg(pdiff); pdiff.add_argument("--import-id", default=None)
    pprov = prsub.add_parser("provenance"); _add_program_arg(pprov); pprov.add_argument("--scope", default=None)

    # Platform credential definitions contain references only.
    platform_cmd = sp("platform", help="platform adapter and credential status")
    platform_sub = platform_cmd.add_subparsers(dest="sub", required=True)
    platform_sub.add_parser("status")
    credential_cmd = platform_sub.add_parser("credential")
    credential_sub = credential_cmd.add_subparsers(dest="credential_action", required=True)
    credential_add = credential_sub.add_parser("add")
    credential_add.add_argument("platform", choices=["hackerone", "bugcrowd", "intigriti"])
    credential_add.add_argument("name"); credential_add.add_argument("--username-ref", default=None)
    credential_add.add_argument("--token-ref", default=None)
    credential_sub.add_parser("list")

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
    pom = posub.add_parser("matrix"); _add_program_arg(pom)

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
    fc.add_argument("--lead", default=None); fc.add_argument("--hypothesis", default=None)
    fc.add_argument("--tests", default=None)
    fv = fsub.add_parser("validate"); _add_program_arg(fv); fv.add_argument("id")
    fva = fsub.add_parser("validate-auto", help="launch a separate role-bound autonomous validator")
    _add_program_arg(fva); fva.add_argument("id")
    fva.add_argument("--runtime", choices=["claude"], default="claude")
    fva.add_argument("--timeout", type=int, default=600)
    fa = fsub.add_parser("adjudicate"); _add_program_arg(fa); fa.add_argument("id")
    fa.add_argument("--verdict", required=True, choices=["supported", "rejected", "inconclusive"]); fa.add_argument("--reason", default=None)
    fa.add_argument("--prerequisite", default=None); fa.add_argument("--boundary", default=None)
    fa.add_argument("--attacker-control", default=None)
    fr = fsub.add_parser("reject"); _add_program_arg(fr); fr.add_argument("id"); fr.add_argument("--reason", default=None)
    fcv = fsub.add_parser("cvss"); _add_program_arg(fcv); fcv.add_argument("id"); fcv.add_argument("--vector", required=True)
    fcv.add_argument("--reasoning", default=None, help="YAML/JSON per-metric rationale and evidence")

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
    ssub.add_parser("audit", help="warn on shallow, duplicated, or fixture-poor skills")
    se = ssub.add_parser("eval"); se.add_argument("name", nargs="?")
    se.add_argument("--behavioral", action="store_true", help="run optional paid model behavioral cases")
    se.add_argument("--runtime", choices=["claude", "codex"], default="claude")
    se.add_argument("--timeout", type=int, default=180)
    se.add_argument("--ablation", action="store_true", help="compare the same behavioral fixtures with and without the skill")
    se.add_argument("--runs", type=int, default=1, help="repeat each arm; use at least 3 for serious evaluation")
    se.add_argument("--judge", action="store_true", help="use an optional independent semantic judge model")
    se.add_argument("--judge-runtime", choices=["claude", "codex"], default=None)
    se.add_argument("--output", default=None, help="persist the sanitized JSON result to this path")

    # source / whitebox (no generic shell or repository execution surface)
    source_cmd = sp("source", help="program-isolated, commit-pinned whitebox source analysis")
    source_sub = source_cmd.add_subparsers(dest="sub", required=True)
    source_sub.add_parser("detect", help="detect safe local source-analysis capabilities")
    source_sub.add_parser("install-guide", help="show optional source-tool installation guidance")
    source_add = source_sub.add_parser("add", help="register a human-supplied official source repository")
    _add_program_arg(source_add); source_add.add_argument("--repo", required=True)
    source_add.add_argument("--ref", default="HEAD"); source_add.add_argument("--repository-id", default=None)
    source_add.add_argument("--relation", default="in_scope_source"); source_add.add_argument("--license", default=None)
    source_list = source_sub.add_parser("list"); _add_program_arg(source_list); source_list.add_argument("--status", default=None)
    source_show = source_sub.add_parser("show"); _add_program_arg(source_show); source_show.add_argument("repository")
    source_update = source_sub.add_parser("update"); _add_program_arg(source_update)
    source_update.add_argument("repository"); source_update.add_argument("--ref", default=None)
    source_changes = source_sub.add_parser("changes", help="summarize commit-pinned security-relevant source changes")
    _add_program_arg(source_changes); source_changes.add_argument("repository")
    source_deps = source_sub.add_parser(
        "prepare-dependencies",
        help="import a human-prepared offline dependency cache without executing repository scripts",
    )
    _add_program_arg(source_deps); source_deps.add_argument("repository")
    source_deps.add_argument("--snapshot", required=True)
    source_relation = source_sub.add_parser(
        "relate-service", help="record a human-confirmed repository/runtime service relation",
    )
    _add_program_arg(source_relation); source_relation.add_argument("repository")
    source_relation.add_argument("--host", action="append", default=[])
    source_relation.add_argument("--base-path", action="append", default=[])
    source_relation.add_argument("--runtime-version", default=None)
    source_relation.add_argument("--confirmed-by", default="human")
    source_context = source_sub.add_parser("context", help="persist compact architecture and control context")
    _add_program_arg(source_context); source_context.add_argument("repository")
    source_search = source_sub.add_parser("search", help="bounded ripgrep search over one pinned snapshot")
    _add_program_arg(source_search); source_search.add_argument("repository"); source_search.add_argument("pattern")
    source_search.add_argument("--glob", default=None); source_search.add_argument("--regex", action="store_true")
    source_search.add_argument("--limit", type=int, default=50)
    source_read = source_sub.add_parser("read", help="read a bounded, redacted source range")
    _add_program_arg(source_read); source_read.add_argument("repository"); source_read.add_argument("file")
    source_read.add_argument("--line-start", type=int, default=1); source_read.add_argument("--line-end", type=int, default=220)
    source_audit = source_sub.add_parser("audit", help="run one bounded source analysis")
    _add_program_arg(source_audit); source_audit.add_argument("repository")
    source_audit.add_argument("--analysis", choices=["context", "authorization", "dataflow", "differential", "semgrep", "codeql", "dependencies", "secrets"], default="authorization")
    source_audit.add_argument("--rule", default="")
    source_audit.add_argument("--database", default="")
    source_obs = source_sub.add_parser("observations"); _add_program_arg(source_obs)
    source_obs.add_argument("--repository", default=None); source_obs.add_argument("--status", default=None)
    source_obs.add_argument("--min-confidence", type=float, default=0.0); source_obs.add_argument("--limit", type=int, default=200)
    source_map = source_sub.add_parser("map-runtime", help="correlate source routes with persistent recon endpoints")
    _add_program_arg(source_map); source_map.add_argument("repository")
    source_symbols = source_sub.add_parser("symbols", help="query the commit-scoped source symbol index")
    _add_program_arg(source_symbols); source_symbols.add_argument("repository")
    source_symbols.add_argument("--name", default=None); source_symbols.add_argument("--kind", default=None)
    source_symbols.add_argument("--limit", type=int, default=500)
    source_sandbox = source_sub.add_parser("sandbox", help="plan or run one semantic network-off source action")
    _add_program_arg(source_sandbox); source_sandbox.add_argument("repository")
    source_sandbox.add_argument("--operation", choices=["build", "test", "reproducer", "fuzz"], required=True)
    source_sandbox.add_argument("--entrypoint", default=None); source_sandbox.add_argument("--session", default=None)
    source_sandbox.add_argument("--approval", default=None); source_sandbox.add_argument("--timeout", type=int, default=120)
    source_sandbox.add_argument("--plan", action="store_true")

    # cvss
    c = sp("cvss", help="score a CVSS vector")
    c.add_argument("vector")

    # report
    r = sp("report", help="reports")
    rsub = r.add_subparsers(dest="sub", required=True)
    rg = rsub.add_parser("generate"); _add_program_arg(rg); _add_finding_arg(rg)
    rg.add_argument("--title", default=None); rg.add_argument("--summary", default=None)
    rg.add_argument("--weakness", default=None); rg.add_argument("--severity", default=None)
    rg.add_argument("--prerequisites", default=None)
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
    st.add_argument("--autonomous", action="store_true")
    goal_choices = ["validated_finding", "validated", "poc_ready", "scored", "report_ready", "qa_passed", "budget_exhausted"]
    st.add_argument("--goal", choices=goal_choices, default=None)

    hu = sp("hunt", help="start a bounded autonomous hunt (Claude by default)")
    _add_program_arg(hu)
    hu.add_argument("--runtime", choices=["claude", "codex", "opencode"], default="claude")
    hu.add_argument("--goal", choices=goal_choices, default=None)

    metrics = sp("metrics", help="compact empirical metrics for one autonomy run")
    _add_program_arg(metrics); metrics.add_argument("--run", required=True)

    recon = sp("recon", help="scope-aware bounded recon executor")
    recon_sub = recon.add_subparsers(dest="sub", required=True)
    recon_sub.add_parser("detect", help="show supported local recon tool availability")
    recon_sub.add_parser("install-guide", help="print installation references; never installs")
    recon_run = recon_sub.add_parser("run", help="run an authorized bounded recon profile or stage")
    _add_program_arg(recon_run)
    recon_mode = recon_run.add_mutually_exclusive_group(required=True)
    recon_mode.add_argument("--profile", choices=["passive", "light", "standard", "deep"])
    recon_mode.add_argument("--stage", choices=["passive", "historical", "dns", "http", "validate", "crawl", "js", "burp", "technology", "score", "leads", "nuclei", "ffuf", "ports"])
    recon_run.add_argument("--seed", action="append", default=[], help="in-scope seed; omitted seeds derive from configured scope/inventory")
    recon_run.add_argument("--max-results", type=int, default=200)
    recon_run.add_argument("--timeout", type=int, default=120)
    recon_run.add_argument("--approval", default=None, help="approved bounded recon plan id for deep/R3 stages")
    recon_runs = recon_sub.add_parser("runs", help="list persistent recon runs"); _add_program_arg(recon_runs); recon_runs.add_argument("--limit", type=int, default=50)
    recon_show = recon_sub.add_parser("show", help="show one recon run"); _add_program_arg(recon_show); recon_show.add_argument("id"); recon_show.add_argument("--limit", type=int, default=200)
    recon_diff = recon_sub.add_parser("diff", help="diff inventory changes recorded by two runs"); _add_program_arg(recon_diff); recon_diff.add_argument("first"); recon_diff.add_argument("second")
    def add_recon_filters(parser, *, scoring=True):
        _add_program_arg(parser)
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--interesting", action="store_true")
        if scoring: parser.add_argument("--min-score", type=int, default=0)
        parser.add_argument("--host", default=None); parser.add_argument("--source", default=None)
        parser.add_argument("--since", default=None); parser.add_argument("--limit", type=int, default=200)
    for name in ("assets", "hosts", "urls", "endpoints"):
        add_recon_filters(recon_sub.add_parser(name, help=f"list recon {name}"))
    recon_params = recon_sub.add_parser("parameters", help="list parameter names/shapes"); _add_program_arg(recon_params); recon_params.add_argument("--host", default=None); recon_params.add_argument("--since", default=None); recon_params.add_argument("--limit", type=int, default=500)
    recon_tech = recon_sub.add_parser("technologies", help="list technology observations"); _add_program_arg(recon_tech); recon_tech.add_argument("--since", default=None); recon_tech.add_argument("--limit", type=int, default=500)
    recon_changes = recon_sub.add_parser("changes", help="list run-to-run changes"); _add_program_arg(recon_changes); recon_changes.add_argument("--run", default=None); recon_changes.add_argument("--type", default=None); recon_changes.add_argument("--since", default=None); recon_changes.add_argument("--limit", type=int, default=500)
    recon_interesting = recon_sub.add_parser("interesting", help="rank meaningful research surfaces"); _add_program_arg(recon_interesting); recon_interesting.add_argument("--limit", type=int, default=20)
    recon_summary = recon_sub.add_parser("summary", help="compact AI-oriented recon summary"); _add_program_arg(recon_summary); recon_summary.add_argument("--limit", type=int, default=10)

    auth = sp("auth", help="model-safe AuthContext status")
    auth_sub = auth.add_subparsers(dest="sub", required=True)
    auth_list = auth_sub.add_parser("list", help="show roles and credential availability, never secrets")
    _add_program_arg(auth_list)

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
        "acceptance": {"model-smoke": _acceptance_model_smoke,
                       "whitebox-model-smoke": _acceptance_whitebox_model_smoke,
                       "recover-whitebox-model-smoke": _acceptance_recover_whitebox_model_smoke},
        "program": {
            "create": _program_create, "list": _program_list, "show": _program_show, "use": _program_use,
            "archive": lambda a: _program_status(a, "archived"), "activate": _program_activate,
            "export": _program_export, "import": _program_import,
            "intake-status": _program_intake_status, "review": _program_review,
            "ambiguities": _program_ambiguities,
            "ambiguity": lambda a: _program_ambiguity_resolve(a),
            "approve-import": _program_approve_import, "refresh": _program_refresh,
            "diff": _program_diff, "provenance": _program_provenance,
        },
        "platform": {
            "status": _platform_status,
            "credential": lambda a: _platform_credential_add(a) if a.credential_action == "add" else _platform_credential_list(a),
        },
        "engagement": {"validate": _engagement_validate, "status": _engagement_status},
        "scope": {"check": _scope_check},
        "policy": {"check": _policy_check, "matrix": _policy_matrix},
        "lead": {"list": _lead_list, "show": _lead_show, "add": _lead_add, "claim": _lead_claim, "release": _lead_release, "close": _lead_close},
        "hypothesis": {"list": _hyp_list, "show": _hyp_show, "create": _hyp_create, "update": _hyp_update},
        "test": {"list": _test_list, "add": _test_add, "complete": _test_complete},
        "evidence": {"add": _evidence_add, "list": _evidence_list, "show": _evidence_show},
        "finding": {
            "list": _finding_list, "show": _finding_show, "create": _finding_create, "validate": _finding_validate,
            "validate-auto": _finding_validate_auto, "adjudicate": _finding_adjudicate,
            "reject": _finding_reject, "cvss": _finding_cvss,
        },
        "checkpoint": {"save": _checkpoint_save, "show": _checkpoint_show, "latest": _checkpoint_latest},
        "knowledge": {"list": _knowledge_list, "promote": _knowledge_promote, "candidates": _knowledge_candidates, "status": _knowledge_status},
        "approval": {
            "list": _approval_list, "show": _approval_show,
            "approve": lambda a: _approval_decide(a, "approved"),
            "reject": lambda a: _approval_decide(a, "rejected"),
            "expire": _approval_expire,
        },
        "skill": {"list": _skill_list, "validate": _skill_validate, "audit": _skill_audit, "eval": _skill_eval},
        "source": {
            "detect": _source_detect, "install-guide": _source_install_guide,
            "add": _source_add, "list": _source_list, "show": _source_show,
            "update": _source_update, "changes": _source_changes,
            "prepare-dependencies": _source_prepare_dependencies,
            "relate-service": _source_relate_service, "context": _source_context,
            "search": _source_search, "read": _source_read, "audit": _source_audit,
            "observations": _source_observations, "map-runtime": _source_map,
            "symbols": _source_symbols, "sandbox": _source_sandbox,
        },
        "cvss": _cvss_score,
        "report": {"generate": _report_generate, "qa": _report_qa},
        "poc": _poc,
        "mcp": {"status": _mcp_status, "serve": _mcp_serve},
        "sync": _sync,
        "start": _start,
        "hunt": _hunt,
        "metrics": _hunt_metrics,
        "recon": {
            "detect": _recon_detect, "install-guide": _recon_install_guide, "run": _recon_run,
            "runs": _recon_runs, "show": _recon_show, "diff": _recon_diff,
            "assets": _recon_assets, "hosts": _recon_hosts, "urls": _recon_urls,
            "endpoints": _recon_endpoints, "parameters": _recon_parameters,
            "technologies": _recon_technologies, "changes": _recon_changes,
            "interesting": _recon_interesting, "summary": _recon_summary,
        },
        "auth": {"list": _auth_list},
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
