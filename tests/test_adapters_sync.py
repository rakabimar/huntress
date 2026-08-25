"""Runtime-adapter generation tests (Claude/Codex/OpenCode + session binding).

Rendering and session-binding are exercised against *temp* output dirs whenever
a function would otherwise write into the tracked repository.  No test here
performs real network or recon activity.
"""

import json

import pytest

from bughunt_harness.adapters import claude, sync
from bughunt_harness.adapters.base import RUNTIME_IDS, load_specs, read_core
from bughunt_harness.config import HarnessConfig


def test_claude_md_references_core():
    assert "@AGENT_CORE.md" in claude.claude_md()


def test_settings_json_shape():
    s = claude.settings_json()
    assert "permissions" in s
    assert "hooks" in s
    deny = "".join(s["permissions"]["deny"])
    # Secrets and credential surfaces must be denied.
    assert "~/.bughunt/secrets" in deny
    assert "~/.ssh" in deny
    # Harness CLI itself is explicitly allowed.
    assert s["permissions"]["allow"]
    assert "SessionStart" in s["hooks"]
    assert "Stop" in s["hooks"]
    assert "PreToolUse" in s["hooks"]


def test_settings_json_modern_hook_events():
    # P0.12: the full modern (Claude Code v2.x) hook event set is wired, each
    # matcher entry is `{hooks:[{type,command,timeout}]}` with a numeric timeout.
    s = claude.settings_json()
    expected = {
        "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
        "PostToolUseFailure", "Stop", "PreCompact", "SessionEnd",
    }
    assert set(s["hooks"]) == expected
    for event, matches in s["hooks"].items():
        assert isinstance(matches, list) and matches
        for m in matches:
            assert isinstance(m.get("hooks"), list) and m["hooks"]
            hook = m["hooks"][0]
            assert hook["type"] == "command"
            assert "hook" in hook["command"]
            assert isinstance(hook.get("timeout"), int) and hook["timeout"] > 0
    # PreToolUse is the Bash backstop -> must carry a matcher.
    assert s["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_settings_json_network_sandbox_boundary():
    # P0.11: default egress is restricted to loopback + reserved test TLDs via a
    # strict allowlist; real targets must go through the broker.
    s = claude.settings_json()
    net = s["sandbox"]["network"]
    assert net["strictAllowlist"] is True
    assert net["allowLocalBinding"] is True
    for host in ("localhost", "127.0.0.1", "*.test", "*.invalid", "*.example"):
        assert host in net["allowedDomains"]
    assert "evil.org" not in net["allowedDomains"]
    assert net["deniedDomains"] == []


def test_session_bind_writes_egress_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(claude, "CLAUDE_DIR", tmp_path / ".claude")
    workspace = tmp_path / "programs" / "acme-test"
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    path = claude.session_bind(
        workspace, [workspace], config=cfg, allowed_domains=["api.example.com", "*.example.com"]
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    allowed = doc["sandbox"]["network"]["allowedDomains"]
    assert "api.example.com" in allowed
    assert "*.example.com" in allowed
    assert "localhost" in allowed  # loopback fixtures always reachable
    assert doc["sandbox"]["network"]["strictAllowlist"] is True


def test_mcp_json_registers_bughunt():
    m = claude.mcp_json()
    assert "bughunt" in m["mcpServers"]
    assert m["mcpServers"]["bughunt"]["args"] == ["mcp", "serve"]


def test_agent_specs_load_and_render():
    specs = load_specs()
    assert len(specs) >= 8
    for s in specs:
        for runtime in RUNTIME_IDS:
            rendered = s.render(runtime)
            assert s.name in rendered
            assert len(rendered.strip()) > 0


def test_agents_md_inlines_core():
    md = sync.agents_md()
    assert "## 1. Prime directives" in md
    assert read_core().strip() in md


def test_sync_rejects_unknown_runtime():
    with pytest.raises(ValueError):
        sync.sync_all(["claude", "wat"])


def test_session_bind_isolates_workspaces(tmp_path, monkeypatch):
    # Point the Claude output dir + config at a temp tree so we don't touch the
    # repo or the real ~/.bughunt.
    monkeypatch.setattr(claude, "CLAUDE_DIR", tmp_path / ".claude")
    workspace = tmp_path / "programs" / "acme-test"
    sibling = tmp_path / "programs" / "other-test"
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    path = claude.session_bind(workspace, [workspace, sibling], config=cfg)
    assert path.is_file()
    doc = json.loads(path.read_text(encoding="utf-8"))
    deny = " ".join(doc["permissions"]["deny"])
    assert str(workspace) in doc["permissions"]["additionalDirectories"]
    assert "other-test" in deny  # sibling workspace denied
    assert str(workspace) not in deny  # active workspace itself not denied
    assert str(cfg.secrets_dir) in deny  # secrets always denied


def test_sync_skills_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(claude, "CLAUDE_DIR", tmp_path / ".claude")
    created = claude.sync_skills()
    assert len(created) >= 48
    out_dir = tmp_path / ".claude" / "skills"
    assert (out_dir / "report").exists() or (out_dir / "report").is_symlink()