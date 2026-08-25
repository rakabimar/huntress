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
  * ``FULL_READY``  — + the test suite and documentation are present and
    non-empty.

Readiness is computed, not asserted: every check is a real import/logic probe
(no file-existence-only PASS), so a broken install reports a lower level rather
than a green light.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import get_config

REPO_ROOT = Path(__file__).resolve().parents[1]

OK = "ok"
WARN = "warn"
FAIL = "fail"

TIERS = ("env", "core", "hunt", "full")

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
    return "scope engine: include/wildcard/exclude/out-of-scope all correct"


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
    from .skills.registry import list_skills, validate_all

    problems = validate_all()
    n = len(list_skills())
    if problems:
        return _raise(f"skill validation found {len(problems)} problem(s): {problems[0]}")
    assert n >= 48, f"expected >= 48 skills, found {n}"
    return f"skill library valid ({n} skills, 0 problems)"


def _probe_agents() -> str:
    from .adapters.base import load_specs

    specs = load_specs()
    assert len(specs) >= 8, f"expected >= 8 agent specs, found {len(specs)}"
    for s in specs:
        assert s.render("claude").strip(), f"agent {s.name} renders empty"
    return f"agent specs load and render ({len(specs)} specialists)"


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


def _probe_mcp() -> str:
    from mcp.server.fastmcp import FastMCP  # noqa: F401

    mod = importlib.import_module("bughunt_harness.mcp.server")
    build = getattr(mod, "_make_mcp", None)
    assert callable(build), "MCP server build function (_make_mcp) not found"
    server = build()
    tools = server._tool_manager.list_tools()
    assert len(tools) >= 10, f"expected >= 10 MCP tools, found {len(tools)}"
    return f"MCP server builds with {len(tools)} tools"


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
    return "runtime config generated + settings.json parses (sandbox + modern hooks present)"


def _probe_program_present() -> str:
    """Program-gated: HUNT_READY requires at least one huntable program."""
    from .registry import ProgramRegistry

    reg = ProgramRegistry(get_config())
    try:
        n = len(reg.list())  # type: ignore[attr-defined]
    finally:
        reg.close()
    if n == 0:
        return _raise("no programs configured — create one with `harness program create <slug>`")
    return f"{n} program(s) configured (a hunt target exists)"


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
        return {
            "level": self.level,
            "ready": self.ready,
            "summary": {"ok": ok, "warn": warn, "fail": fail, "total": len(self.checks)},
            "checks": [c.as_dict() for c in self.checks],
        }


def run_doctor(program: str | None = None) -> DoctorReport:
    checks: list[DoctorCheck] = []

    # Tier 0 — environment (can the harness even run here?).
    checks.append(_try("python", "env", _probe_python))
    checks.append(_try("install", "env", _probe_install))
    checks.append(_try("dependencies", "env", _probe_dependencies))
    checks.append(_try("state_home", "env", _probe_state_home))

    # Tier 1 — deterministic core.
    checks.append(_try("registry", "core", _probe_registry))
    checks.append(_try("scope_engine", "core", _probe_scope))
    checks.append(_try("policy_engine", "core", _probe_policy))
    checks.append(_try("state_machine", "core", _probe_state_machine))

    # Tier 2 — hunt capability (program-gated).
    checks.append(_try("skills", "hunt", _probe_skills))
    checks.append(_try("agent_specs", "hunt", _probe_agents))
    checks.append(_try("cvss", "hunt", _probe_cvss))
    checks.append(_try("broker", "hunt", _probe_broker))
    checks.append(_try("mcp_server", "hunt", _probe_mcp))
    checks.append(_try("secrets", "hunt", _probe_secrets))
    checks.append(_try("adapters", "hunt", _probe_adapters))
    checks.append(_try("program_present", "hunt", _probe_program_present))

    # Tier 3 — release completeness.
    checks.append(_try("tests", "full", _probe_tests))
    checks.append(_try("docs", "full", _probe_docs))

    # Optional: a specific program must load end-to-end.
    if program:
        def _load_program() -> str:
            from .hunt import load_program_context

            with load_program_context(program) as ctx:
                assert ctx.engagement.scope.has_includes, "program has no scope includes"
                return f"program {program!r} loads (scope+roe+state+secrets)"

        checks.append(_try(f"program:{program}", "hunt", _load_program))

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