"""Activation validation and exact runtime-session binding regressions."""

import yaml

from bughunt_harness import config as config_module
from bughunt_harness.adapters import session as session_adapter
from bughunt_harness.cli import main
from bughunt_harness.engagement.workspace import create_workspace
from bughunt_harness.hunt import load_program_context
from bughunt_harness.registry import ProgramRegistry


def _register(config, *, fixture=False):
    registry = ProgramRegistry(config)
    try:
        record = registry.create(
            slug="local-test", name="Local",
            workspace_path=str(config.programs_dir / "local-test"),
        )
    finally:
        registry.close()
    create_workspace(record, fixture=fixture)
    return record


def test_invalid_empty_scope_cannot_activate(config, monkeypatch):
    monkeypatch.setattr(config_module, "_default_config", config)
    _register(config, fixture=False)
    assert main(["program", "activate", "--program", "local-test"]) == 1
    registry = ProgramRegistry(config)
    try:
        assert registry.get("local-test").status == "paused"
    finally:
        registry.close()


def test_force_activation_is_logged_but_not_hunt_ready(config, monkeypatch):
    monkeypatch.setattr(config_module, "_default_config", config)
    record = _register(config, fixture=False)
    assert main(["program", "activate", "--program", "local-test", "--force"]) == 0
    assert (record.workspace / ".force-activated").is_file()


def test_runtime_environment_binds_exact_session_id(config, monkeypatch):
    monkeypatch.setattr(config_module, "_default_config", config)
    record = _register(config, fixture=True)
    # Autonomous launch is opt-in and bounded.
    autonomy_path = record.workspace / "autonomy.yaml"
    autonomy = yaml.safe_load(autonomy_path.read_text(encoding="utf-8"))
    autonomy["enabled"] = True
    autonomy_path.write_text(yaml.safe_dump(autonomy, sort_keys=False), encoding="utf-8")
    registry = ProgramRegistry(config)
    try:
        registry.set_status("local-test", "active")
        active = registry.get("local-test")
    finally:
        registry.close()
    from bughunt_harness.engagement.workspace import write_program_status

    write_program_status(active)
    captured = {}
    monkeypatch.setattr(session_adapter, "_resolve_binary", lambda runtime: "/bin/true")
    monkeypatch.setattr(
        session_adapter.os, "execvpe",
        lambda program, argv, env: captured.update({"program": program, "argv": argv, "env": env}),
    )
    assert session_adapter.start_session("claude", "local-test", autonomous=True) == 0
    sid = int(captured["env"]["BUGHUNT_SESSION_ID"])
    assert captured["env"]["BUGHUNT_PROGRAM"] == "local-test"
    assert captured["env"]["BUGHUNT_AUTONOMOUS"] == "1"
    with load_program_context("local-test", config) as ctx:
        assert ctx.db.get_session(sid).program_slug == "local-test"
        assert ctx.db.active_autonomy_run(sid) is not None
