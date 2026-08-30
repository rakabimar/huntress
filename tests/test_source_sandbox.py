from __future__ import annotations

import shutil
import subprocess
from types import SimpleNamespace

import pytest

from bughunt_harness.engagement.models import AccountsModel, Engagement, ProgramModel, ROEModel, ScopeModel, ScopeSet
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.scope.engine import ScopeEngine
from bughunt_harness.source import SourceService
from bughunt_harness.source_sandbox import SourceSandboxExecutor, detect_sandbox_backend
from bughunt_harness.state.db import HuntDB


def _git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.mark.external_tool
@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap unavailable")
def test_sandbox_blocks_host_home_and_network_and_is_policy_gated(tmp_path):
    workspace = tmp_path / "program"; workspace.mkdir()
    db = HuntDB(workspace / "state" / "hunt.db", "sandbox-test")
    scope = ScopeModel(include=ScopeSet(domains=["example.test"]))
    engagement = Engagement(program=ProgramModel(name="sandbox"), scope=scope,
                            roe=ROEModel(automation_allowed=True), accounts=AccountsModel())
    ctx = SimpleNamespace(workspace=workspace, db=db, slug="sandbox-test", engagement=engagement,
                          scope=ScopeEngine(scope), policy=PolicyEngine(scope, engagement.roe))
    repo = tmp_path / "malicious"; repo.mkdir(); _git(repo, "init")
    (repo / "reproduce.py").write_text(
        "import pathlib,socket\n"
        "secret=pathlib.Path('/home/rakabimar/.ssh/id_rsa').exists()\n"
        "s=socket.socket(); s.settimeout(.2)\n"
        "try: s.connect(('1.1.1.1',80)); network=True\n"
        "except OSError: network=False\n"
        "print(f'host_secret={secret} network={network}')\n", encoding="utf-8")
    (repo / "fuzz.py").write_text(
        "import argparse\np=argparse.ArgumentParser(); p.add_argument('--max-runs'); print(p.parse_args().max_runs)\n",
        encoding="utf-8",
    )
    _git(repo, "add", "."); _git(repo, "commit", "-m", "malicious fixture")
    try:
        registered = SourceService(ctx).add_repository(str(repo)); session = db.start_session("pytest", "whitebox-audit-specialist", "sandbox-test")
        fuzz_plan = SourceSandboxExecutor(ctx).plan(registered["id"], "fuzz", entrypoint="fuzz.py")
        assert fuzz_plan["decision"]["decision"] == "approval_required"
        assert fuzz_plan["command_template"][-2:] == ["--max-runs", "1000"]
        first = SourceSandboxExecutor(ctx).execute(registered["id"], "reproducer", session_id=session.id, entrypoint="reproduce.py")
        assert first["mode"] == "ASK" and not first["executed"]
        approval = db.get_approval(int(first["approval"].split("-")[1])); db.approve_approval(approval.id, "pytest-human")
        result = SourceSandboxExecutor(ctx).execute(registered["id"], "reproducer", session_id=session.id,
                                                    approval_id=approval.id, entrypoint="reproduce.py")
        assert result["returncode"] == 0, result
        assert "host_secret=False network=False" in result["stdout"]
        assert not result["network_enabled"] and not result["host_home_mounted"]
    finally:
        db.close()


def test_sandbox_readiness_is_truthful():
    status = detect_sandbox_backend()
    assert status["backend"] in {"bubblewrap", "podman", "docker", ""}
    assert status["host_docker_socket_mounted"] is False


def test_codeql_database_modes_are_semantic_and_build_is_ask_gated(tmp_path, monkeypatch):
    workspace = tmp_path / "program"; workspace.mkdir()
    db = HuntDB(workspace / "state" / "hunt.db", "codeql-test")
    scope = ScopeModel(include=ScopeSet(domains=["example.test"]))
    engagement = Engagement(
        program=ProgramModel(name="codeql"), scope=scope,
        roe=ROEModel(automation_allowed=True),
    )
    ctx = SimpleNamespace(
        workspace=workspace, db=db, slug="codeql-test", engagement=engagement,
        scope=ScopeEngine(scope), policy=PolicyEngine(scope, engagement.roe),
    )
    real_which = shutil.which
    monkeypatch.setattr(
        "bughunt_harness.source_sandbox.shutil.which",
        lambda name: "/usr/bin/codeql" if name == "codeql" else real_which(name),
    )
    try:
        python_repo = tmp_path / "python"; python_repo.mkdir(); _git(python_repo, "init")
        (python_repo / "app.py").write_text("print('fixture')\n", encoding="utf-8")
        _git(python_repo, "add", "."); _git(python_repo, "commit", "-m", "python")
        registered = SourceService(ctx).add_repository(str(python_repo))
        no_build = SourceSandboxExecutor(ctx).plan(registered["id"], "codeql_database")
        assert no_build["selection_reason"].startswith("NO_BUILD")
        assert no_build["decision"]["decision"] == "allow"
        assert "--build-mode=none" in no_build["command_template"]

        java_repo = tmp_path / "java"; java_repo.mkdir(); _git(java_repo, "init")
        (java_repo / "pom.xml").write_text("<project/>", encoding="utf-8")
        (java_repo / "Main.java").write_text("class Main {}\n", encoding="utf-8")
        _git(java_repo, "add", "."); _git(java_repo, "commit", "-m", "java")
        java = SourceService(ctx).add_repository(str(java_repo), repository_id="java")
        build = SourceSandboxExecutor(ctx).plan(java["id"], "codeql_database")
        assert build["selection_reason"].startswith("BUILD_REQUIRED")
        assert build["decision"]["decision"] == "approval_required"
        assert build["policy_action"] == "source_build"
    finally:
        db.close()


@pytest.mark.external_tool
@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap unavailable")
def test_sandbox_wall_clock_limit_stops_benign_infinite_loop(tmp_path):
    workspace = tmp_path / "program"; workspace.mkdir(); db = HuntDB(workspace / "state" / "hunt.db", "limit-test")
    scope = ScopeModel(include=ScopeSet(domains=["example.test"])); engagement = Engagement(
        program=ProgramModel(name="limit"), scope=scope, roe=ROEModel(automation_allowed=True))
    ctx = SimpleNamespace(workspace=workspace, db=db, slug="limit-test", engagement=engagement,
                          scope=ScopeEngine(scope), policy=PolicyEngine(scope, engagement.roe))
    repo = tmp_path / "loop"; repo.mkdir(); _git(repo, "init")
    (repo / "loop.py").write_text("while True: pass\n", encoding="utf-8")
    _git(repo, "add", "."); _git(repo, "commit", "-m", "bounded loop")
    try:
        registered = SourceService(ctx).add_repository(str(repo)); session = db.start_session("pytest", "whitebox-audit-specialist", "limit-test")
        executor = SourceSandboxExecutor(ctx)
        ask = executor.execute(registered["id"], "reproducer", session_id=session.id, entrypoint="loop.py")
        approval = db.get_approval(int(ask["approval"].split("-")[1])); db.approve_approval(approval.id, "pytest-human")
        from bughunt_harness.source_sandbox import SandboxLimits
        result = executor.execute(registered["id"], "reproducer", session_id=session.id,
                                  approval_id=approval.id, entrypoint="loop.py",
                                  limits=SandboxLimits(cpu_seconds=1, wall_seconds=3))
        assert result["returncode"] != 0 or result["timed_out"]
    finally:
        db.close()
