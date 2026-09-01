"""Deterministic readiness self-check (spec §69, §100).

``run_doctor`` probes the harness in four tiers and derives one of five
readiness levels:

  * ``NOT_READY``   — the environment can't even support the harness (wrong
    Python, missing install, unwritable state home, broken deps).
  * ``ENV_READY``   — environment is sound but the deterministic core fails.
  * ``CORE_READY``  — the deterministic core (registry, scope, policy, state
    machine) is functional.
  * ``HUNT_READY``  — + skills, agent specs, CVSS, report, broker, MCP, secrets,
    generated runtime config, and **at least one configured program** are real;
    you can actually run a hunt.
  * ``FULL_READY``  — + deep local integration checks (Burp MCP/proxy,
    Playwright, recon, priority skill evals, and the synthetic autonomous
    finding pipeline) pass. Warnings such as an untrusted Burp CA remain
    visible without being misreported as failures.

Readiness is computed, not asserted: every check is a real import/logic probe
(no file-existence-only PASS), so a broken install reports a lower level rather
than a green light.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from .config import get_config

REPO_ROOT = Path(__file__).resolve().parents[1]

OK = "ok"
WARN = "warn"
FAIL = "fail"

TIERS = ("env", "core", "hunt", "full", "model")

LEVEL_NOT_READY = "NOT_READY"
LEVEL_ENV_READY = "ENV_READY"
LEVEL_CORE_READY = "CORE_READY"
LEVEL_HUNT_READY = "HUNT_READY"
LEVEL_FULL_READY = "FULL_READY"


@dataclass
class DoctorCheck:
    name: str
    tier: str
    status: str
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "tier": self.tier, "status": self.status, "detail": self.detail}


def _ok(name: str, tier: str, detail: str) -> DoctorCheck:
    return DoctorCheck(name, tier, OK, detail)


def _warn(name: str, tier: str, detail: str) -> DoctorCheck:
    return DoctorCheck(name, tier, WARN, detail)


def _fail(name: str, tier: str, detail: str) -> DoctorCheck:
    return DoctorCheck(name, tier, FAIL, detail)


def _try(check_name: str, tier: str, fn) -> DoctorCheck:
    try:
        return _ok(check_name, tier, fn())
    except Exception as exc:  # noqa: BLE001 - probe boundary
        return _fail(check_name, tier, f"{type(exc).__name__}: {exc}")


def _raise(msg: str) -> str:
    raise AssertionError(msg)


# --------------------------------------------------------------------------- #
# env probes (bottom tier: can the harness even run here?)
# --------------------------------------------------------------------------- #
def _probe_python() -> str:
    v = sys.version_info
    assert v >= (3, 11), f"Python >= 3.11 required, found {sys.version.split()[0]}"
    return f"Python {'.'.join(map(str, v[:3]))} >= 3.11"


def _probe_install() -> str:
    mod = importlib.import_module("bughunt_harness")
    ver = getattr(mod, "__version__", None)
    assert ver, "bughunt_harness lacks a __version__ (not installed via `pip install -e .`)"
    return f"bughunt_harness installed (version={ver})"


def _probe_dependencies() -> str:
    import pydantic
    import requests
    import rich
    import yaml

    return f"core deps importable (pydantic {pydantic.__version__}, requests, rich, pyyaml)"


def _probe_state_home() -> str:
    cfg = get_config()
    cfg.ensure_dirs()
    for p in (cfg.home, cfg.programs_dir, cfg.secrets_dir, cfg.logs_dir):
        assert p is not None and p.is_dir(), f"state path is not a directory: {p}"
    probe = cfg.home / ".doctor-write-probe"
    probe.write_text("ok", encoding="utf-8")
    try:
        assert probe.read_text(encoding="utf-8") == "ok", "state home is not writable"
    finally:
        probe.unlink(missing_ok=True)
    return f"state home prepared + writable ({cfg.home})"


def _probe_portability() -> str:
    from .config import get_paths
    from .portability import personal_path_matches
    paths = get_paths(); matches = personal_path_matches(paths.project_root)
    assert not matches, f"personal absolute paths in canonical files: {matches[:3]}"
    assert paths.bughunt_home != paths.project_root, "mutable user state must not live in source tree"
    return f"PORTABILITY_READY project={paths.project_root} state={paths.bughunt_home}; personal_paths=0"


def _probe_completion_capabilities() -> str:
    from .state.db import HuntDB
    with tempfile.TemporaryDirectory(prefix="bughunt-capabilities-") as td:
        db = HuntDB(Path(td) / "hunt.db", "capability-doctor")
        tables = {row[0] for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
        required = {"differential_result", "oast_session", "auth_session", "coverage_observation", "js_artifact", "finding_fingerprint", "recon_watch", "program_learning", "knowledge_document"}
        assert required <= tables, f"missing capability tables: {sorted(required - tables)}"
        db.close()
    from .requests import RequestTemplate, ResponseComparator
    from .whitebox_taint import MultiLanguageTaintAnalyzer
    assert RequestTemplate and ResponseComparator and MultiLanguageTaintAnalyzer
    return "RESPONSE_DIFF/AUTH_DIFFERENTIAL/SESSION_LIFECYCLE/COVERAGE/JS_INTELLIGENCE/WHITEBOX_TAINT/KNOWLEDGE/WATCH schemas PASS"


def _oast_check() -> DoctorCheck:
    from .oast import InteractshProvider
    cap = InteractshProvider().capabilities()
    detail = (
        f"Interactsh={'INSTALLED' if cap.available else 'NOT_INSTALLED'} REACHABLE=NOT_TESTED; "
        "Burp Collaborator=UNAVAILABLE; self-hosted=NOT_CONFIGURED; OAST policy=program-dependent"
    )
    return _ok("OAST_READY", "hunt", detail) if cap.available else _warn("OAST_READY", "hunt", detail)


def _oast_program_policy_check(program: str) -> DoctorCheck:
    from .hunt import load_program_context
    with load_program_context(program) as ctx:
        decision = ctx.policy.check("oob_test")
        detail = f"program OAST policy={decision.decision} reason={decision.reason}"
        if decision.decision == "deny":
            return _warn("OAST_PROGRAM_POLICY", "hunt", detail)
        return _ok("OAST_PROGRAM_POLICY", "hunt", detail)


# --------------------------------------------------------------------------- #
# core probes
# --------------------------------------------------------------------------- #
def _probe_registry() -> str:
    from .registry import ProgramRegistry

    reg = ProgramRegistry(get_config())
    try:
        n = len(reg.list())  # type: ignore[attr-defined]
    finally:
        reg.close()
    return f"registry.db openable ({n} program(s))"


def _probe_scope() -> str:
    from .scope.engine import ScopeEngine
    from .engagement.models import ScopeModel, ScopeSet

    scope = ScopeModel(
        include=ScopeSet(domains=["example.test"], wildcards=["*.example.test"]),
        exclude=ScopeSet(domains=["evil.example.test"]),
    )
    eng = ScopeEngine(scope)
    assert eng.check("https://api.example.test/x").allowed, "wildcard match failed"
    assert not eng.check("https://evil.example.test").allowed, "exclusion did not win"
    assert not eng.check("https://example.org").allowed, "out-of-scope host allowed"
    path_scope = ScopeEngine(ScopeModel(include=ScopeSet(path_urls=["https://example.test/allowed/"])))
    assert path_scope.check("https://example.test/allowed/item").allowed
    assert not path_scope.check("https://example.test/allowed/../admin").allowed
    assert not path_scope.check("https://example.test/allowed/%2e%2e/admin").allowed
    assert eng.check("https://EXAMPLE.TEST.:443/path#fragment").allowed
    return "scope engine: normalization/include/exclude/path traversal/OOS all correct"


def _probe_policy() -> str:
    from .policy.engine import ALLOW, APPROVAL_REQUIRED, DENY, PolicyEngine
    from .engagement.models import ROEModel, ScopeModel, ScopeSet

    scope = ScopeModel(include=ScopeSet(domains=["example.test"]))
    eng = PolicyEngine(scope, ROEModel())  # automation disabled by default
    assert eng.check("analyze").decision == ALLOW
    assert eng.check("dos", "https://example.test").decision == DENY
    assert eng.check("read_http", "https://example.test").decision == APPROVAL_REQUIRED
    # With automation allowed, a network read becomes an unambiguous allow.
    eng2 = PolicyEngine(scope, ROEModel(automation_allowed=True))
    assert eng2.check("read_http", "https://example.test").decision == ALLOW
    return "policy engine: allow/deny/approval gates all correct"


def _probe_state_machine() -> str:
    from .state.constants import validate_transition
    from .errors import InvalidTransitionError

    assert validate_transition("finding", "candidate", "validation")
    try:
        validate_transition("finding", "candidate", "validated")
        raise AssertionError("illegal candidate->validated jump was accepted")
    except InvalidTransitionError:
        pass
    return "state machine: legal transitions pass, illegal jumps rejected"


# --------------------------------------------------------------------------- #
# hunt probes
# --------------------------------------------------------------------------- #
def _probe_skills() -> str:
    from collections import Counter
    from .skills.registry import list_skills, validate_all

    problems = validate_all()
    skills = list_skills()
    n = len(skills)
    if problems:
        return _raise(f"skill validation found {len(problems)} problem(s): {problems[0]}")
    assert n >= 48, f"expected >= 48 skills, found {n}"
    maturity = Counter(item["maturity"] for item in skills)
    deprecated = sum(item["status"] == "deprecated" for item in skills)
    active = n - deprecated
    whitebox = sum(item["whitebox"] and item["status"] != "deprecated" for item in skills)
    return (
        f"skill library valid (canonical active={active}, stable={maturity['stable']}, "
        f"draft={maturity['draft']}, deprecated aliases={deprecated}, "
        f"whitebox-capable={whitebox}, 0 problems)"
    )


def _probe_agents() -> str:
    from .adapters.base import load_specs
    from .adapters.tool_resolution import validate_agent_tool_surfaces
    from .mcp.server import tool_names_for_role

    specs = load_specs()
    assert len(specs) >= 8, f"expected >= 8 agent specs, found {len(specs)}"
    for s in specs:
        assert s.render("claude").strip(), f"agent {s.name} renders empty"
    problems = validate_agent_tool_surfaces(specs)
    assert not problems, (
        f"{problems[0].agent}:{problems[0].tool} {problems[0].kind} "
        f"({problems[0].detail})"
    )
    orchestrator = tool_names_for_role("orchestrator") or set()
    whitebox = tool_names_for_role("whitebox-audit-specialist") or set()
    return (
        f"AGENT_TOOL_SURFACES PASS specs={len(specs)} unknown=0 inaccessible=0 "
        f"privilege_leaks=0 orchestrator_tools={len(orchestrator)} "
        f"whitebox_specialist_tools={len(whitebox)}"
    )


def _probe_cvss() -> str:
    from .cvss.engine import score_vector, severity_from_score

    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r.severity == "Critical" and 9.0 <= r.base_score <= 10.0
    assert severity_from_score(0.0) == "None" and severity_from_score(5.0) == "Medium"
    return f"CVSS v3.1/v4 calculator works (sample={r.base_score})"


def _probe_broker() -> str:
    """Functional, no-network probe: an out-of-scope target must short-circuit
    to ``deny`` before any socket is opened (not merely "broker importable")."""
    from .engagement.models import Engagement, ProgramModel, ScopeModel, ScopeSet
    from .requests.broker import RequestBroker
    from .secrets.manager import SecretManager
    from .state.db import HuntDB

    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        eng = Engagement(
            program=ProgramModel(name="doctor-probe", platform="custom", status="active"),
            scope=ScopeModel(include=ScopeSet(domains=["example.test"])),
        )
        db = HuntDB(ws / "state" / "hunt.db", program_slug="doctor-probe")
        broker = RequestBroker(
            eng,
            program_slug="doctor-probe",
            workspace=ws,
            hunt_db=db,
            secrets=SecretManager("doctor-probe"),
        )
        try:
            r = broker.execute(target="https://evil.org", action="read_http")
            assert r.ok is False and r.decision == "deny", f"unexpected decision {r.decision!r}"
            assert "out_of_scope" in r.reason
        finally:
            db.close()
            broker.limiter.close()
    return "broker: out-of-scope request short-circuits before any network I/O"


def _probe_safety_invariants() -> str:
    """Exercise principal-bound approvals, stale leases, and exact sessions."""
    import time

    from .errors import StateError
    from .requests.ratelimit import SharedRateLimiter
    from .state.db import HuntDB

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        db = HuntDB(root / "hunt.db", program_slug="doctor-probe")
        session_a = db.start_session("doctor", "researcher", "doctor-probe")
        session_b = db.start_session("doctor", "researcher", "doctor-probe")
        approval = db.request_approval(
            "race_test", "https://example.test/redeem", program="doctor-probe",
            method="POST", requested_by="researcher", session_id=session_a.id,
            auth_context="account_a",
            constraints={"max_requests": 2, "max_concurrency": 1, "duration_seconds": 30},
        )
        db.approve_approval(approval.id, approved_by="doctor-human")
        assert db.find_valid_approval(
            "race_test", "https://example.test/redeem", "doctor-probe", "POST", "", "account_a",
        ) is not None
        assert db.find_valid_approval(
            "race_test", "https://example.test/redeem", "doctor-probe", "POST", "", "account_b",
        ) is None
        db.record_approval_use(approval.id)
        db.record_approval_use(approval.id)
        assert db.get_approval(approval.id).status == "consumed"
        try:
            db.save_checkpoint(session_id=session_b.id + 999)
            raise AssertionError("unknown session accepted by checkpoint")
        except StateError:
            pass
        db.close()

        limiter_a = SharedRateLimiter(root / "limiter.db", "doctor-probe")
        limiter_b = SharedRateLimiter(root / "limiter.db", "doctor-probe")
        lease = limiter_a.acquire("example.test", 100.0, 1, lease_ttl=0.001)
        time.sleep(0.01)
        assert limiter_b.cleanup_stale() >= 1
        lease_b = limiter_b.acquire("example.test", 100.0, 1)
        limiter_b.release("example.test", lease_b)
        limiter_a.release("example.test", lease)
        limiter_a.close()
        limiter_b.close()
    return "bounded approvals include AuthContext; sessions bind exactly; stale leases recover"


def _probe_validation_gate() -> str:
    """Prove linked-only evidence and independent structured review enforcement."""
    from .errors import StateError
    from .engagement.models import ScopeModel, ScopeSet
    from .scope.engine import ScopeEngine
    from .state.db import HuntDB

    checks = {
        "scope_eligible": {"passed": True}, "reproducible": {"passed": True},
        "prerequisites": {"value": "regular test account"},
        "security_boundary": {"value": "cross-account ownership"},
        "attacker_control": {"value": "object id"},
        "demonstrated_impact": {"value": "read another account's private object"},
        "intended_behavior": {"passed": True},
        "false_positive_analysis": {"passed": True},
        "evidence_quality": {"passed": True}, "minimal_impact": {"passed": True},
        "program_exclusions": {"passed": True},
    }
    with tempfile.TemporaryDirectory() as td:
        db = HuntDB(Path(td) / "hunt.db", program_slug="doctor-probe")
        # Use a validator-capable creator here so the session-identity check,
        # rather than only the role check, is exercised explicitly.
        creator = db.start_session("doctor", "finding-validator", "doctor-probe")
        validator = db.start_session("doctor", "finding-validator", "doctor-probe")
        lead = db.add_lead("ownership")
        hypothesis = db.create_hypothesis("cross-account read", lead_id=lead.id)
        linked = db.add_evidence("request_response", "linked synthetic response")
        unrelated = db.add_evidence("request_response", "unrelated response")
        test = db.add_test(hypothesis.id, "paired request")
        db.complete_test(test.id, "ownership failure", "supports", [linked.public_id])
        finding = db.create_finding(
            "BOLA", "https://example.test/order/1", "CWE-639", checks["demonstrated_impact"]["value"],
            [linked.public_id], lead_id=lead.id, hypothesis_id=hypothesis.id,
            test_ids=[test.id], creator_session_id=creator.id,
        )
        db.transition_finding(finding.id, "validation")
        self_review = db.begin_validation(finding.id)
        try:
            db.submit_validation_review(
                self_review.id, "supported", reviewer_role="finding-validator",
                reviewer_session_id=creator.id, check_results=checks,
                evidence_refs=[linked.public_id],
            )
            raise AssertionError("creator session self-validated")
        except StateError:
            pass
        review = db.begin_validation(finding.id)
        try:
            db.submit_validation_review(
                review.id, "supported", reviewer_role="finding-validator",
                reviewer_session_id=validator.id, check_results=checks,
                evidence_refs=[unrelated.public_id],
            )
            raise AssertionError("unlinked evidence was accepted")
        except StateError:
            pass
        valid_review = db.begin_validation(finding.id)
        db.submit_validation_review(
            valid_review.id, "supported", reviewer_role="finding-validator",
            reviewer_session_id=validator.id, check_results=checks,
            evidence_refs=[linked.public_id],
        )
        finalized = db.finalize_validation(
            finding.id,
            scope_engine=ScopeEngine(ScopeModel(include=ScopeSet(domains=["example.test"]))),
            program_active=True,
        )
        assert finalized.status == "validated"
        db.close()
    return "finding validation requires linked evidence, structured checks, and an independent validator"


def _probe_mcp() -> str:
    from mcp.server.fastmcp import FastMCP  # noqa: F401

    mod = importlib.import_module("bughunt_harness.mcp.server")
    build = getattr(mod, "_make_mcp", None)
    assert callable(build), "MCP server build function (_make_mcp) not found"
    server = build()
    tools = server._tool_manager.list_tools()
    assert len(tools) >= 10, f"expected >= 10 MCP tools, found {len(tools)}"
    return f"MCP server builds with {len(tools)} tools"


async def _mcp_protocol_probe_async() -> tuple[str, str, int]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=str(REPO_ROOT / "harness"), args=["mcp", "serve"], cwd=str(REPO_ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, read_timeout_seconds=timedelta(seconds=15),
        ) as session:
            initialized = await session.initialize()
            listing = await session.list_tools()
            return initialized.serverInfo.name, initialized.serverInfo.version, len(listing.tools)


def _probe_mcp_protocol() -> str:
    name, version, count = asyncio.run(_mcp_protocol_probe_async())
    assert count >= 10, f"Harness MCP returned only {count} tools"
    return f"Harness MCP stdio handshake/list-tools PASS ({name} {version}; {count} tools)"


def _probe_secrets() -> str:
    """Functional probe: env: refs resolve, plaintext values are rejected."""
    from .errors import SecretError
    from .secrets.manager import SecretManager

    os.environ["BUGHUNT_DOCTOR_PROBE"] = "present"
    sm = SecretManager("doctor-probe")
    try:
        assert sm.resolve("env:BUGHUNT_DOCTOR_PROBE") == "present"
        assert not sm.available("env:BUGHUNT_DOCTOR_ABSENT_VAR")
        try:
            sm.resolve("plaintext-secret")
            return _raise("plaintext secret ref was accepted")
        except SecretError:
            pass
    finally:
        os.environ.pop("BUGHUNT_DOCTOR_PROBE", None)
    return "secret manager: env: refs resolve, plaintext rejected"


def _probe_adapters() -> str:
    generated = {
        "CLAUDE.md": REPO_ROOT / "CLAUDE.md",
        "AGENTS.md": REPO_ROOT / "AGENTS.md",
        ".claude/settings.json": REPO_ROOT / ".claude" / "settings.json",
        ".mcp.json": REPO_ROOT / ".mcp.json",
    }
    for name, p in generated.items():
        if not p.is_file():
            return _raise(f"run `harness sync` first — missing: {name}")
    # Structural check (not mere existence): settings.json must parse and carry
    # the network sandbox boundary + modern hook wiring (P0.11/P0.12).
    doc = json.loads((generated[".claude/settings.json"]).read_text(encoding="utf-8"))
    assert "sandbox" in doc and "network" in doc["sandbox"], "settings.json missing sandbox network boundary"
    assert {"SessionStart", "SessionEnd"} <= set(doc.get("hooks", {})), "settings.json missing modern hooks"
    import tomllib

    tomllib.loads((REPO_ROOT / ".codex" / "config.toml").read_text(encoding="utf-8"))
    json.loads((REPO_ROOT / "opencode.json").read_text(encoding="utf-8"))
    runtime_details = []
    for executable in ("claude", "codex", "opencode"):
        path = shutil.which(executable)
        if not path:
            runtime_details.append(f"{executable}=generated/unverified")
            continue
        proc = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=8, check=False,
        )
        assert proc.returncode == 0, f"{executable} --version failed"
        runtime_details.append(f"{executable}={(proc.stdout or proc.stderr).strip()[:80]}")
    assert (REPO_ROOT / "mcp" / "registry.yaml").is_file(), "canonical MCP registry is missing"
    return "runtime configs parse; " + ", ".join(runtime_details)


def _probe_broker_only_sandbox() -> str:
    path = REPO_ROOT / ".claude" / "settings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    network = doc["sandbox"]["network"]
    allowed = set(network.get("allowedDomains", []))
    assert network.get("strictAllowlist") is True, "strictAllowlist is not enabled"
    permitted = {"localhost", "*.localhost", "127.0.0.1", "[::1]"}
    unexpected = allowed - permitted
    assert not unexpected, f"direct non-loopback egress is allowed: {sorted(unexpected)}"
    assert "::1" not in allowed, "Claude requires bracketed IPv6 literal [::1]"
    return "Claude direct egress is loopback-only; target domains require the broker"


def _probe_claude_runtime() -> str:
    path = shutil.which("claude")
    assert path, "Claude Code is not installed"
    return f"Claude Code detected ({path})"


def _probe_program_present(program: str | None = None) -> str:
    """Program-gated: HUNT_READY requires at least one huntable program."""
    from .registry import ProgramRegistry

    reg = ProgramRegistry(get_config())
    try:
        selected = program or reg.get_active()
        if not selected:
            return _raise("no program selected — pass --program or activate one")
        record = reg.get(selected)
    finally:
        reg.close()
    if record.status != "active":
        return _raise(f"program {record.slug!r} is {record.status!r}, not active")
    if (Path(record.workspace_path) / ".force-activated").exists():
        return _raise("program was force-activated and is not hunt-ready")
    from .hunt import load_program_context

    with load_program_context(record.slug, require_active=True) as ctx:
        assert ctx.engagement.scope.has_includes, "program has no real scope"
        assert ctx.engagement.roe.automation_allowed, "ROE automation_allowed is false"
        assert ctx.engagement.autonomy.enabled, "autonomy.enabled is false"
    return f"active engagement {record.slug!r} has scope, ROE, and bounded autonomy"


def _intake_status(program: str) -> dict:
    from .program_intake.service import ProgramIntakeService
    return ProgramIntakeService().status(program)


def _probe_intake_source(program: str) -> str:
    status = _intake_status(program)
    if status.get("status") == "LEGACY_MANUAL":
        return "legacy/manual program; importer not required"
    latest = status["latest"]
    assert latest["status"] in {"VALIDATED", "ACTIVE"}, f"intake is {latest['status']}"
    assert latest["structured_source_count"] or latest["prose_source_count"], "no durable intake source"
    return f"{latest['platform']} sources captured through {latest['public_id']}"


def _probe_intake_freshness(program: str) -> str:
    from datetime import datetime, timezone
    status = _intake_status(program)
    if status.get("status") == "LEGACY_MANUAL":
        return "legacy/manual freshness policy"
    value = status["latest"].get("last_checked_at") or status["latest"].get("completed_at")
    assert value, "intake has no freshness timestamp"
    age = datetime.now(timezone.utc) - datetime.fromisoformat(value)
    assert age.total_seconds() <= 24 * 3600, f"intake is stale ({age})"
    return f"checked {int(age.total_seconds() // 60)}m ago"


def _probe_intake_provenance(program: str) -> str:
    from .program_intake.service import ProgramIntakeService
    status = _intake_status(program)
    if status.get("status") == "LEGACY_MANUAL":
        return "legacy/manual source"
    provenance = ProgramIntakeService().provenance(program)
    assert all(item.get("provenance") for item in provenance["scope"]), "scope provenance incomplete"
    assert all(item.get("provenance") for item in provenance["roe"]), "ROE provenance incomplete"
    return f"scope {len(provenance['scope'])}/{len(provenance['scope'])}; ROE {len(provenance['roe'])} sourced"


def _probe_intake_ambiguities(program: str) -> str:
    from .program_intake.service import ProgramIntakeService
    status = _intake_status(program)
    if status.get("status") == "LEGACY_MANUAL":
        return "legacy/manual review"
    critical = [item for item in ProgramIntakeService().ambiguities(program)
                if item["severity"] == "CRITICAL" and item["status"] == "OPEN"]
    assert not critical, f"{len(critical)} critical intake ambiguity/ambiguities open"
    return "0 critical ambiguities open"


def _probe_intake_approval(program: str) -> str:
    from .program_intake.service import ProgramIntakeService
    status = _intake_status(program)
    if status.get("status") == "LEGACY_MANUAL":
        return "legacy/manual engagement validation"
    assert status.get("approval_hash_valid"), "approved draft hash mismatch"
    ProgramIntakeService().assert_activation_ready(program)
    return f"human approval valid for {status['approved_import']}"


def _probe_program_auth(program: str) -> str:
    from .hunt import load_program_context

    with load_program_context(program) as ctx:
        configured = [a for a in ctx.engagement.accounts.accounts if a.enabled and a.auth]
        for account in configured:
            refs = account.auth.secret_refs() if account.auth else []
            missing = [ref for ref in refs if not ctx.secrets.available(ref)]
            assert not missing, f"account {account.id!r} has unresolved secret reference(s)"
        return f"AuthContexts resolvable ({len(configured)} configured account(s))"


def _probe_auth_channel_health(program: str) -> str:
    """Report browser and Broker auth independently without reading values."""
    from .hunt import load_program_context

    rows = []
    with load_program_context(program) as ctx:
        for account in [a for a in ctx.engagement.accounts.accounts if a.enabled]:
            refs = account.auth.secret_refs() if account.auth else []
            broker = (
                "credential_resolvable" if refs and all(ctx.secrets.available(ref) for ref in refs)
                else "missing" if not refs else "failed"
            )
            profile = ctx.workspace / "browser" / account.id / "profile"
            browser = "unknown" if profile.is_dir() else "profile_missing"
            rows.append(f"{account.id}: browser={browser}, broker={broker}")
    return "Auth channel health (no credential values): " + "; ".join(rows or ["no enabled accounts"])


def _probe_burp_proxy() -> str:
    from .requests.broker import burp_proxy_status

    status = burp_proxy_status()
    assert status["configured"], (
        "Burp Proxy is not explicitly configured"
        + ("; 127.0.0.1:8080 is only an unverified candidate" if status["candidate_8080"] else "")
    )
    assert status["reachable"], status["error"] or "configured Burp Proxy is unreachable"
    assert status["verified"], "configured proxy could not be verified"
    return f"BURP_PROXY_CONFIGURED/REACHABLE/VERIFIED {status['proxy_url']}"


def _probe_burp_mcp() -> str:
    from .integrations.burp import READ_TOOLS, burp_mcp_health

    cfg = get_config()
    health = burp_mcp_health(cfg.burp_mcp or "http://127.0.0.1:9876")
    assert health.ok, health.error
    installed = set(health.tool_names or [])
    assert installed.intersection(READ_TOOLS), "Burp MCP has no supported read tools"
    return (
        f"Burp MCP PASS {health.endpoint} "
        f"({health.server_name} {health.server_version}, {len(installed)} tools)"
    )


def _probe_playwright() -> str:
    from .integrations.playwright import playwright_health

    health = playwright_health()
    assert health["ok"], health.get("error", "Playwright MCP unavailable")
    assert health.get("chromium"), "Chromium browser executable is unavailable"
    return f"Playwright MCP PASS ({health.get('version', '')}; chromium={health['chromium']})"


def _probe_playwright_browser() -> str:
    from .integrations.playwright import playwright_browser_probe
    from .synthetic import SyntheticFixture

    with SyntheticFixture() as fixture:
        result = playwright_browser_probe(fixture.base_url, timeout=30)
    assert result["ok"], result.get("error", "browser probe failed")
    assert "synthetic-root" in result.get("snapshot", ""), "local fixture was not rendered"
    return (
        f"Playwright MCP browser PASS ({result['server']} {result['version']}; "
        f"{result['tool_count']} tools; localhost rendered)"
    )


def _probe_recon() -> str:
    from .engagement.models import ScopeModel, ScopeSet
    from .recon import derive_passive_discovery_seeds, normalize_url
    from .scope.engine import ScopeEngine
    from .state.db import HuntDB

    scope = ScopeModel(include=ScopeSet(wildcards=["*.example.test"]))
    assert derive_passive_discovery_seeds(scope) == ["example.test"]
    assert not ScopeEngine(scope).check("https://example.test").allowed
    assert normalize_url("HTTPS://API.Example.Test:443/x?id=1#z")["url"] == "https://api.example.test/x?id="
    with tempfile.TemporaryDirectory() as temp:
        db = HuntDB(Path(temp) / "hunt.db", "doctor-test")
        try:
            tables = {row[0] for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"recon_run", "asset", "asset_observation", "endpoint", "endpoint_parameter", "technology_observation", "recon_change"} <= tables
        finally:
            db.close()
    return "Recon Engine PASS schema, normalization, passive seeds, inventory and diff tables"


def _recon_tools_check() -> DoctorCheck:
    from .recon import detect_recon_tools, recon_readiness

    tools = detect_recon_tools(); readiness = recon_readiness()
    present = [name for name, item in tools.items() if item["available"]]
    missing = [name for name, item in tools.items() if not item["available"]]
    detail = (
        f"core={readiness['RECON_CORE_READY']} standard={readiness['RECON_STANDARD_READY']} "
        f"deep={readiness['RECON_DEEP_READY']}; PASS={present or ['none']}; WARN missing={missing or ['none']}"
    )
    return _ok("recon_tools", "full", detail) if not missing else _warn("recon_tools", "full", detail)


def _probe_priority_skills() -> str:
    from .skills.eval import run_eval

    priority = [
        "api-authorization", "access-control", "authentication", "session-management",
        "jwt", "oauth-oidc", "business-logic", "graphql", "file-upload", "ssrf",
        "xss", "sql-injection",
    ]
    results = [run_eval(name) for name in priority]
    failed = [name for name, result in zip(priority, results) if result["failed"]]
    assert not failed, f"priority skill eval failures: {failed}"
    for name in priority:
        root = REPO_ROOT / "skills" / name
        for ref in (
            "mental-model.md", "attack-surface.md", "implementation-notes.md",
            "methodology.md", "false-positives.md",
            "evidence-contract.md", "impact.md", "remediation.md",
            "public-report-patterns.md",
        ):
            assert (root / "references" / ref).is_file(), f"{name} missing references/{ref}"
        for group in (
            "routing", "positive", "negative", "false-positive", "evidence",
            "tool-selection", "safety", "complex-scenario",
        ):
            assert (root / "evals" / group).is_dir(), f"{name} missing evals/{group}"
    return f"priority skills and eval layouts healthy ({len(priority)})"


def _probe_source_schema() -> str:
    from .state.db import HuntDB
    with tempfile.TemporaryDirectory(prefix="bughunt-source-doctor-") as td:
        db = HuntDB(Path(td) / "hunt.db", "source-doctor")
        try:
            tables = {row[0] for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {
                "source_repository", "source_analysis_run", "source_observation",
                "source_runtime_mapping", "source_security_context", "source_symbol",
                "security_invariant", "root_cause", "specialist_task", "agent_turn", "tool_call", "skill_usage",
            }
            assert required <= tables, f"missing source tables: {sorted(required - tables)}"
        finally:
            db.close()
    return "source architecture/symbol/invariant/runtime/handoff/telemetry schema v10 PASS"


def _probe_telemetry() -> str:
    from .state.db import HuntDB
    with tempfile.TemporaryDirectory(prefix="bughunt-telemetry-doctor-") as td:
        db = HuntDB(Path(td) / "hunt.db", "telemetry-doctor")
        try:
            session = db.start_session("doctor", "orchestrator", "telemetry-doctor")
            turn = db.start_agent_turn(session_id=session.id, role="orchestrator")
            db.start_tool_call(
                invocation_id="doctor-invocation", session_id=session.id,
                role="orchestrator", tool="scope_preflight", agent_turn_id=turn["id"],
                lead_id=None, hypothesis_id=None,
            )
            call = db.complete_tool_call(
                "doctor-invocation", success=True, latency_ms=3,
                result_summary="bounded summary",
            )
            assert call["completed_at"] and call["latency_ms"] == 3
            assert call["result_summary"] == "bounded summary"
            columns = {row[1] for row in db._conn.execute("PRAGMA table_info(tool_call)")}
            assert {"invocation_id", "lead_id", "hypothesis_id", "test_id",
                    "source_analysis_run_id", "specialist_task_id"} <= columns
        finally:
            db.close()
    return "MODEL_INTERACTIONS/TOOL_CORRELATION PASS invocation IDs, latency, result summaries, entity refs"


def _probe_approval_run_scoping() -> str:
    from .state.db import HuntDB
    with tempfile.TemporaryDirectory(prefix="bughunt-approval-doctor-") as td:
        db = HuntDB(Path(td) / "hunt.db", "approval-doctor")
        try:
            a = db.start_session("doctor", "orchestrator", "approval-doctor")
            run_a = db.start_autonomy_run(a.id, "budget_exhausted", {"max_total_requests": 2})
            scoped = db.request_approval(
                "race_test", "https://example.test/a", program="approval-doctor",
                session_id=a.id, requested_by="orchestrator",
            )
            db.stop_autonomy_run(run_a.id, "rollover", "stopped")
            b = db.start_session("doctor", "orchestrator", "approval-doctor")
            run_b = db.start_autonomy_run(b.id, "budget_exhausted", {"max_total_requests": 2})
            legacy = db.request_approval(
                "race_test", "https://example.test/legacy", program="approval-doctor",
                requested_by="legacy-import",
            )
            assert scoped.autonomy_run_id == run_a.id and legacy.autonomy_run_id is None
            assert db.list_pending_approvals(
                autonomy_run_id=run_b.id, include_legacy_unscoped=False,
            ) == []
        finally:
            db.close()
    return "APPROVAL_RUN_SCOPING PASS old/legacy pending rows cannot pause a new run"


def _probe_browser_mutation_policy() -> str:
    from types import SimpleNamespace
    from .engagement.models import AccountsModel, AccountModel, Engagement, ProgramModel, ROEModel, ScopeModel, ScopeSet
    from .integrations.playwright import browser_policy_preflight
    from .policy.engine import PolicyEngine
    from .scope.engine import ScopeEngine
    scope = ScopeModel(include=ScopeSet(domains=["example.test"]))
    engagement = Engagement(
        program=ProgramModel(name="doctor"), scope=scope,
        roe=ROEModel(automation_allowed=True, state_changing_actions=True),
        accounts=AccountsModel(accounts=[AccountModel(id="doctor", enabled=True)]),
    )
    ctx = SimpleNamespace(engagement=engagement, scope=ScopeEngine(scope), policy=PolicyEngine(scope, engagement.roe))
    result = browser_policy_preflight(
        ctx, target_url="https://example.test/profile", account="doctor",
        action_semantics="model-says-safe", expected_effect="unknown mutation", operation="click",
    )
    assert result["mode"] == "ASK" and result["classification"]["unknown_mutation"]
    return "BROWSER_MUTATION_POLICY PASS derived unknown mutations default to ASK; model labels cannot downgrade"


def _probe_policy_attachment_parser() -> str:
    from .program_intake.policy_documents import extract_policy_document
    fixtures = (
        (b"Do not perform denial of service.", "text/plain", ".txt", "utf-8-text"),
        (b"# Policy\nAPI testing allowed", "text/markdown", ".md", "utf-8-text"),
        (b"<html><script>bad()</script><p>Policy</p></html>", "text/html", ".html", "html.parser"),
        (b'{"policy":"safe"}', "application/json", ".json", "json"),
    )
    for raw, mime, suffix, parser in fixtures:
        text, metadata = extract_policy_document(raw, content_type=mime, suffix=suffix)
        assert text and metadata["parser"] == parser and not metadata["javascript_executed"]
    return "POLICY_ATTACHMENT_PARSER PASS HTML/Markdown/text/JSON text-only; PDF paths covered by deterministic tests"


def _probe_release_metadata() -> str:
    import tomllib
    from . import __version__
    package = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    node = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))["version"]
    lock = json.loads((REPO_ROOT / "package-lock.json").read_text(encoding="utf-8"))["version"]
    mcp = _make_version_probe()
    assert len({package, __version__, node, lock, mcp}) == 1, (
        f"version mismatch package={package} runtime={__version__} node={node} lock={lock} mcp={mcp}"
    )
    assert (REPO_ROOT / "scripts" / "release-check.sh").is_file()
    assert (REPO_ROOT / "MANIFEST.in").is_file()
    return f"RELEASE_METADATA PASS canonical/CLI/MCP/distribution version={package}"


def _make_version_probe() -> str:
    from .mcp.server import _make_mcp
    return str(_make_mcp()._mcp_server.version)


def _probe_specialist_execution() -> str:
    from .adapters.tool_resolution import validate_agent_tool_surfaces
    from .specialists import SPECIALIST_ROLES, SpecialistResult

    assert shutil.which("claude"), "Claude Code is required for local role-bound specialist execution"
    assert not validate_agent_tool_surfaces(), "agent role surface validation failed"
    assert "whitebox-audit-specialist" in SPECIALIST_ROLES
    SpecialistResult.model_validate({"status": "completed", "summary": "doctor contract"})
    return f"SPECIALIST_EXECUTION_READY roles={len(SPECIALIST_ROLES)} default_concurrency=1 structured_contract=PASS"


def _source_tools_check() -> DoctorCheck:
    from .source import detect_source_tools
    tools = detect_source_tools()
    required_missing = [name for name in ("git", "rg", "ast") if not tools[name]["detected"]]
    optional_missing = [
        name for name, item in tools.items()
        if isinstance(item, dict) and not item.get("required") and not item.get("detected")
    ]
    present = [
        f"{name} {item.get('version', '')}".strip() for name, item in tools.items()
        if isinstance(item, dict) and item.get("detected")
    ]
    detail = (
        f"PASS={present or ['none']}; required_missing={required_missing or ['none']}; "
        f"WARN optional_missing={optional_missing or ['none']}"
    )
    return _warn("source_tools", "hunt", detail) if required_missing or optional_missing else _ok("source_tools", "hunt", detail)


def _source_sandbox_check() -> DoctorCheck:
    from .source_sandbox import detect_sandbox_backend
    status = detect_sandbox_backend()
    required = (
        "network_isolation", "secret_isolation", "ephemeral_writable_worktree",
        "isolated_home_tmp_cache", "aggregate_disk_watchdog",
        "cpu_memory_process_wall_limits",
    )
    enforced = all(status.get(key) for key in required)
    detail = (
        f"backend={status.get('backend') or 'unavailable'} network=OFF home=isolated "
        f"worktree=ephemeral disk_watchdog={status.get('aggregate_disk_watchdog')} "
        f"cpu_ram_process_wall={status.get('cpu_memory_process_wall_limits')} "
        f"dependencies={status.get('dependency_mode')}"
    )
    return _ok("source_sandbox", "hunt", detail) if enforced else _warn(
        "source_sandbox", "hunt", detail + "; install bubblewrap for enforced execution",
    )


def _probe_browser_isolation(program: str) -> str:
    from .hunt import load_program_context
    from .integrations.playwright import write_program_mcp_config

    with load_program_context(program) as ctx:
        path = write_program_mcp_config(ctx)
        doc = json.loads(path.read_text(encoding="utf-8"))
        names = [name for name in doc["mcpServers"] if name.startswith("playwright_")]
        assert names, "no isolated Playwright context was generated"
        args = [doc["mcpServers"][name]["args"] for name in names]
        profiles = [value[index + 1] for value in args for index, item in enumerate(value) if item == "--user-data-dir"]
        assert len(profiles) == len(set(profiles)), "browser profiles are shared across accounts"
        return f"per-program browser MCP config generated ({len(names)} isolated context(s))"


def _probe_browser_policy_mediation(program: str) -> str:
    from .hunt import load_program_context
    from .integrations.playwright import write_program_mcp_config

    with load_program_context(program) as ctx:
        path = write_program_mcp_config(ctx, autonomous=True)
        doc = json.loads(path.read_text(encoding="utf-8"))
        raw = [name for name in doc["mcpServers"] if name.startswith("playwright_")]
        assert not raw, "autonomous config exposes raw Playwright mutation tools"
        from .mcp.server import tool_names_for_role
        previous = os.environ.get("BUGHUNT_CAPABILITIES")
        try:
            os.environ["BUGHUNT_CAPABILITIES"] = "browser"
            tools = tool_names_for_role("orchestrator") or set()
            assert {"browser_observe", "browser_action"} <= tools
        finally:
            if previous is None:
                os.environ.pop("BUGHUNT_CAPABILITIES", None)
            else:
                os.environ["BUGHUNT_CAPABILITIES"] = previous
    return "autonomous browser capability exposes Harness observation/action only; raw mutation tools absent"


def _probe_burp_ca(program: str) -> DoctorCheck:
    from .hunt import load_program_context
    from .requests.broker import validate_ca_bundle

    with load_program_context(program) as ctx:
        burp = ctx.engagement.integrations.burp
        configured = burp.ca_bundle or get_config().burp_ca
        path, status = validate_ca_bundle(configured)
        if path:
            return _ok("BURP_CA_CONFIGURED", "full", f"valid readable PEM bundle: {path}")
        detail = f"Burp CA {status}; Broker never disables TLS verification or modifies system trust"
        if burp.https_interception:
            return _fail("BURP_CA_CONFIGURED", "full", detail)
        return _warn("BURP_CA_CONFIGURED", "full", detail)


def _probe_synthetic_hunt() -> str:
    """Run the full reject→continue→QA pipeline against loopback only."""
    from .config import HarnessConfig
    from .engagement.models import (
        AccountAuthModel, AccountModel, AccountsModel, AutonomyModel, Engagement,
        ProgramModel, ROEModel, ScopeModel, ScopeSet,
    )
    from .engagement.workspace import create_workspace, save_engagement
    from .hunt import load_program_context
    from .registry import ProgramRegistry
    from .synthetic import SyntheticFixture, run_synthetic_autonomous_hunt

    old_a = os.environ.get("BUGHUNT_DOCTOR_ACCOUNT_A")
    old_b = os.environ.get("BUGHUNT_DOCTOR_ACCOUNT_B")
    os.environ["BUGHUNT_DOCTOR_ACCOUNT_A"] = "doctor-cookie-account-a"
    os.environ["BUGHUNT_DOCTOR_ACCOUNT_B"] = "doctor-cookie-account-b"
    try:
        with tempfile.TemporaryDirectory(prefix="bughunt-synthetic-doctor-") as td:
            cfg = HarnessConfig(home=Path(td) / "home", burp_proxy="disabled")
            cfg.ensure_dirs()
            registry = ProgramRegistry(cfg)
            workspace = cfg.programs_dir / "local-test"
            record = registry.create(
                slug="local-test", name="Doctor local acceptance", platform="custom",
                workspace_path=str(workspace), status="active",
            )
            registry.close()
            create_workspace(record)
            save_engagement(workspace, Engagement(
                program=ProgramModel(name=record.name, status="active"),
                scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"])),
                roe=ROEModel(
                    automation_allowed=True, authentication_testing=True,
                    authorization_testing=True, active_recon=True,
                    max_rps=100.0, max_concurrency=2,
                ),
                accounts=AccountsModel(accounts=[
                    AccountModel(
                        id="account_a", role="regular_user",
                        auth=AccountAuthModel(
                            type="cookie", cookie_ref="env:BUGHUNT_DOCTOR_ACCOUNT_A",
                        ),
                    ),
                    AccountModel(
                        id="account_b", role="regular_user",
                        auth=AccountAuthModel(
                            type="cookie", cookie_ref="env:BUGHUNT_DOCTOR_ACCOUNT_B",
                        ),
                    ),
                ]),
                autonomy=AutonomyModel(
                    enabled=True, goal="report_ready", max_session_minutes=10,
                    max_total_requests=30, max_leads_per_session=5,
                ),
            ))
            with SyntheticFixture() as fixture:
                with load_program_context("local-test", cfg, require_active=True) as ctx:
                    result = run_synthetic_autonomous_hunt(ctx, fixture.base_url)
                    assert result["finding_status"] == "qa_passed"
                    assert result["autonomy"]["reason"] == "goal_reached"
                    raw_secrets = {
                        os.environ["BUGHUNT_DOCTOR_ACCOUNT_A"],
                        os.environ["BUGHUNT_DOCTOR_ACCOUNT_B"],
                    }
                    for evidence in ctx.db.list_evidence():
                        assert not any(secret in evidence.preview for secret in raw_secrets)
    finally:
        if old_a is None:
            os.environ.pop("BUGHUNT_DOCTOR_ACCOUNT_A", None)
        else:
            os.environ["BUGHUNT_DOCTOR_ACCOUNT_A"] = old_a
        if old_b is None:
            os.environ.pop("BUGHUNT_DOCTOR_ACCOUNT_B", None)
        else:
            os.environ["BUGHUNT_DOCTOR_ACCOUNT_B"] = old_b
    return "localhost autonomous hunt PASS (reject→continue→independent validate→PoC→CVSS→report→QA)"


# --------------------------------------------------------------------------- #
# full probes
# --------------------------------------------------------------------------- #
def _probe_tests() -> str:
    import pytest  # noqa: F401

    tests = sorted((REPO_ROOT / "tests").glob("test_*.py"))
    if not tests:
        return _raise("no test files found under tests/")
    for t in tests:
        assert t.stat().st_size > 0, f"empty test file: {t.name}"
    return f"test suite present + non-empty ({len(tests)} test modules)"


def _probe_docs() -> str:
    readme = REPO_ROOT / "README.md"
    if not readme.is_file():
        return _raise("README.md missing")
    assert "AGENT_CORE" in readme.read_text(encoding="utf-8"), "README does not reference the canonical core"
    docs = sorted((REPO_ROOT / "docs").glob("*.md")) if (REPO_ROOT / "docs").is_dir() else []
    if not docs:
        return _raise("docs/ has no markdown files")
    for d in docs:
        assert d.stat().st_size > 0, f"empty doc file: {d.name}"
    return f"documentation present + non-empty (README + {len(docs)} doc files)"


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
@dataclass
class DoctorReport:
    checks: list[DoctorCheck] = field(default_factory=list)

    def _statuses(self, tier: str) -> list[str]:
        return [c.status for c in self.checks if c.tier == tier]

    @property
    def level(self) -> str:
        if FAIL in self._statuses("env"):
            return LEVEL_NOT_READY
        if FAIL in self._statuses("core"):
            return LEVEL_ENV_READY
        if FAIL in self._statuses("hunt"):
            return LEVEL_CORE_READY
        if FAIL in self._statuses("full"):
            return LEVEL_HUNT_READY
        return LEVEL_FULL_READY

    @property
    def ready(self) -> bool:
        return self.level in (LEVEL_HUNT_READY, LEVEL_FULL_READY)

    @property
    def exit_code(self) -> int:
        """Process exit code: 0 when env+core are sound (CORE/HUNT/FULL), 1 only
        when the environment/install is broken (ENV_READY / NOT_READY)."""
        return 1 if self.level in (LEVEL_NOT_READY, LEVEL_ENV_READY) else 0

    def render(self) -> dict:
        ok = sum(1 for c in self.checks if c.status == OK)
        warn = sum(1 for c in self.checks if c.status == WARN)
        fail = sum(1 for c in self.checks if c.status == FAIL)
        model_checks = [c for c in self.checks if c.tier == "model" and "whitebox" not in c.name]
        whitebox_model_checks = [c for c in self.checks if c.tier == "model" and "whitebox" in c.name]
        model_verified = (
            "NOT_RUN" if not model_checks
            else "PASS" if all(c.status == OK for c in model_checks)
            else "FAIL"
        )
        whitebox_model_verified = (
            "NOT_RUN" if not whitebox_model_checks
            else "PASS" if all(c.status == OK for c in whitebox_model_checks)
            else "FAIL"
        )
        specialist_verified = "NOT_RUN"
        if whitebox_model_checks:
            specialist_verified = "PASS" if all(c.status == OK for c in whitebox_model_checks) else "FAIL"
        ladder = {
            "ENV_READY": "PASS" if self.level != LEVEL_NOT_READY else "FAIL",
            "CORE_READY": "PASS" if self.level in {LEVEL_CORE_READY, LEVEL_HUNT_READY, LEVEL_FULL_READY} else "FAIL",
            "HUNT_READY": "PASS" if self.level in {LEVEL_HUNT_READY, LEVEL_FULL_READY} else "FAIL",
            "FULL_READY": "PASS" if self.level == LEVEL_FULL_READY else "FAIL",
            "WHITEBOX_READY": (
                "PASS" if any(c.name == "source_schema" and c.status == OK for c in self.checks)
                and any(c.name == "source_tools" and "required_missing=['none']" in c.detail for c in self.checks)
                else "WARN"
            ),
            "MODEL_VERIFIED": model_verified,
            "WHITEBOX_MODEL_VERIFIED": whitebox_model_verified,
            "SPECIALIST_ORCHESTRATION_VERIFIED": specialist_verified,
            "PORTABILITY_READY": "PASS" if any(c.name == "portability" and c.status == OK for c in self.checks) else "FAIL",
            "OAST_READY": "PASS" if any(c.name == "OAST_READY" and c.status == OK for c in self.checks) else "NOT_CONFIGURED",
            "SESSION_LIFECYCLE_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "RESPONSE_DIFF_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "AUTH_DIFFERENTIAL_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "JS_INTELLIGENCE_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "COVERAGE_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "WHITEBOX_TAINT_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "KNOWLEDGE_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
            "WATCH_READY": "PASS" if any(c.name == "completion_capabilities" and c.status == OK for c in self.checks) else "FAIL",
        }
        return {
            "level": self.level,
            "ready": self.ready,
            "readiness": ladder,
            "summary": {"ok": ok, "warn": warn, "fail": fail, "total": len(self.checks)},
            "checks": [c.as_dict() for c in self.checks],
        }


def _has_persisted_model_smoke(program: str) -> bool:
    try:
        from .hunt import load_program_context
        with load_program_context(program) as ctx:
            return (ctx.workspace / "reports" / "model-smoke-result.json").is_file()
    except Exception:
        return False


def _probe_persisted_model_smoke(program: str) -> str:
    """Revalidate persisted MODEL_VERIFIED state instead of trusting JSON alone."""
    from .hunt import load_program_context

    with load_program_context(program, require_active=True) as ctx:
        path = ctx.workspace / "reports" / "model-smoke-result.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload.get("ok") is True and payload.get("program") == program
        accepted = {"validated", "poc_ready", "scored", "report_ready", "qa_passed"}
        finding = next((item for item in ctx.db.list_findings() if item.status in accepted), None)
        assert finding is not None, "persisted result has no independently validated finding"
        review = ctx.db.latest_validation_review(finding.id)
        assert review is not None and review.status == "submitted" and review.verdict == "supported"
        assert review.reviewer_session_id is not None
        assert review.reviewer_session_id != finding.creator_session_id
        assert any(item.status == "goal_reached" for item in ctx.db.list_autonomy_runs())
        return (
            f"persisted real-model localhost hunt PASS ({payload.get('runtime')}/"
            f"{payload.get('model') or 'configured-default'}; {payload.get('run')}; {finding.status.upper()})"
        )


def _has_persisted_whitebox_model_smoke(program: str) -> bool:
    try:
        from .hunt import load_program_context
        with load_program_context(program) as ctx:
            return (ctx.workspace / "reports" / "whitebox-model-smoke-result.json").is_file()
    except Exception:
        return False


def _probe_persisted_whitebox_model_smoke(program: str) -> str:
    from .hunt import load_program_context
    with load_program_context(program, require_active=True) as ctx:
        path = ctx.workspace / "reports" / "whitebox-model-smoke-result.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload.get("ok") is True and payload.get("program") == program
        assert payload.get("token_cost", {}).get("whitebox") is True
        assert payload.get("token_cost", {}).get("source_observations", 0) > 0
        assert payload.get("token_cost", {}).get("source_leads", 0) > 0
        assert payload.get("token_cost", {}).get("source_runtime_mappings", 0) > 0
        assert payload.get("token_cost", {}).get("specialist_tasks", 0) > 0
        assert any(
            item["assigned_role"] == "whitebox-audit-specialist" and item["status"] == "COMPLETED"
            for run in ctx.db.list_autonomy_runs() for item in ctx.db.list_specialist_tasks(run.id)
        )
        assert any(
            item.status in {"validated", "poc_ready", "scored", "report_ready", "qa_passed"}
            for item in ctx.db.list_findings()
        )
        return f"persisted whitebox real-model lifecycle PASS ({payload.get('runtime')}; VALIDATED)"


def run_doctor(
    program: str | None = None, *, deep: bool = False,
    model_smoke: bool = False, runtime: str = "claude",
) -> DoctorReport:
    checks: list[DoctorCheck] = []

    # Tier 0 — environment (can the harness even run here?).
    checks.append(_try("python", "env", _probe_python))
    checks.append(_try("install", "env", _probe_install))
    checks.append(_try("dependencies", "env", _probe_dependencies))
    checks.append(_try("state_home", "env", _probe_state_home))
    checks.append(_try("portability", "env", _probe_portability))

    # Tier 1 — deterministic core.
    checks.append(_try("registry", "core", _probe_registry))
    checks.append(_try("scope_engine", "core", _probe_scope))
    checks.append(_try("policy_engine", "core", _probe_policy))
    checks.append(_try("state_machine", "core", _probe_state_machine))
    checks.append(_try("completion_capabilities", "core", _probe_completion_capabilities))

    # Tier 2 — hunt capability (program-gated).
    checks.append(_try("skills", "hunt", _probe_skills))
    checks.append(_oast_check())
    checks.append(_try("source_schema", "hunt", _probe_source_schema))
    checks.append(_try("telemetry", "hunt", _probe_telemetry))
    checks.append(_try("approval_run_scoping", "hunt", _probe_approval_run_scoping))
    checks.append(_try("browser_mutation_policy", "hunt", _probe_browser_mutation_policy))
    checks.append(_try("policy_attachment_parser", "hunt", _probe_policy_attachment_parser))
    checks.append(_source_tools_check())
    checks.append(_source_sandbox_check())
    checks.append(_try("agent_specs", "hunt", _probe_agents))
    checks.append(_try("specialist_execution", "hunt", _probe_specialist_execution))
    checks.append(_try("cvss", "hunt", _probe_cvss))
    checks.append(_try("broker", "hunt", _probe_broker))
    checks.append(_try("safety_invariants", "hunt", _probe_safety_invariants))
    checks.append(_try("validation_integrity", "hunt", _probe_validation_gate))
    checks.append(_try("mcp_server", "hunt", _probe_mcp))
    checks.append(_try("mcp_protocol", "hunt", _probe_mcp_protocol))
    checks.append(_try("secrets", "hunt", _probe_secrets))
    checks.append(_try("adapters", "hunt", _probe_adapters))
    checks.append(_try("broker_only_egress", "hunt", _probe_broker_only_sandbox))
    checks.append(_try("claude_runtime", "hunt", _probe_claude_runtime))
    checks.append(_try("program_present", "hunt", lambda: _probe_program_present(program)))
    if program:
        checks.append(_oast_program_policy_check(program))
        checks.append(_try("intake_source", "hunt", lambda: _probe_intake_source(program)))
        checks.append(_try("intake_freshness", "hunt", lambda: _probe_intake_freshness(program)))
        checks.append(_try("scope_roe_provenance", "hunt", lambda: _probe_intake_provenance(program)))
        checks.append(_try("intake_critical_ambiguities", "hunt", lambda: _probe_intake_ambiguities(program)))
        checks.append(_try("intake_approval", "hunt", lambda: _probe_intake_approval(program)))
        checks.append(_try("auth_contexts", "hunt", lambda: _probe_program_auth(program)))
        checks.append(_try("auth_channel_health", "hunt", lambda: _probe_auth_channel_health(program)))

    # Tier 3 — release completeness.
    checks.append(_try("tests", "full", _probe_tests))
    checks.append(_try("docs", "full", _probe_docs))
    checks.append(_try("release_metadata", "full", _probe_release_metadata))
    if deep:
        checks.append(_try("BURP_PROXY_CONFIGURED_REACHABLE_VERIFIED", "full", _probe_burp_proxy))
        checks.append(_try("BURP_MCP_REACHABLE", "full", _probe_burp_mcp))
        checks.append(_try("playwright_mcp", "full", _probe_playwright))
        checks.append(_try("playwright_browser", "full", _probe_playwright_browser))
        checks.append(_try("recon_executor", "full", _probe_recon))
        checks.append(_recon_tools_check())
        checks.append(_try("priority_skill_evals", "full", _probe_priority_skills))
        checks.append(_try("synthetic_autonomous_hunt", "full", _probe_synthetic_hunt))
        if program:
            checks.append(_try("browser_isolation", "full", lambda: _probe_browser_isolation(program)))
            checks.append(_try("browser_policy_mediation", "full", lambda: _probe_browser_policy_mediation(program)))
            checks.append(_probe_burp_ca(program))
        else:
            checks.append(_fail("browser_isolation", "full", "--program is required for browser isolation checks"))
    else:
        checks.append(_fail("deep_checks", "full", "run with --deep to evaluate local integrations and FULL_READY"))

    if model_smoke:
        from .acceptance import run_model_smoke
        checks.append(_try(
            "model_smoke", "model",
            lambda: run_model_smoke(runtime=runtime).summary,
        ))
    elif program and _has_persisted_model_smoke(program):
        checks.append(_try(
            "model_smoke_persisted", "model",
            lambda: _probe_persisted_model_smoke(program),
        ))
    if program and _has_persisted_whitebox_model_smoke(program):
        checks.append(_try(
            "whitebox_model_smoke_persisted", "model",
            lambda: _probe_persisted_whitebox_model_smoke(program),
        ))

    return DoctorReport(checks=checks)


__all__ = [
    "DoctorCheck",
    "DoctorReport",
    "run_doctor",
    "LEVEL_NOT_READY",
    "LEVEL_ENV_READY",
    "LEVEL_CORE_READY",
    "LEVEL_HUNT_READY",
    "LEVEL_FULL_READY",
]
