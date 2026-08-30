from bughunt_harness.adapters.base import AgentSpec, load_specs
from bughunt_harness.adapters.tool_resolution import (
    is_native_runtime_tool,
    resolve_mcp_tool,
    validate_agent_tool_surfaces,
)


def test_every_agent_declared_tool_resolves_without_privilege_leak():
    assert validate_agent_tool_surfaces() == []


def test_grep_and_glob_are_explicit_native_tools():
    for runtime in ("claude", "codex", "opencode"):
        assert is_native_runtime_tool(runtime, "Grep")
        assert is_native_runtime_tool(runtime, "Glob")
        assert not is_native_runtime_tool(runtime, "grep")


def test_mcp_resolution_requires_registration_and_role_access():
    assert resolve_mcp_tool("whitebox-audit-specialist", "search_source") == "search_source"
    assert resolve_mcp_tool("researcher", "submit_validation_review") is None
    assert resolve_mcp_tool("researcher", "definitely_not_a_tool") is None


def test_unknown_agent_tool_fails_validation(tmp_path):
    path = tmp_path / "broken.md"
    path.write_text(
        "---\nname: broken\ntools: Read, unavailable_tool\n---\n\nBroken fixture.\n",
        encoding="utf-8",
    )
    problems = validate_agent_tool_surfaces([AgentSpec(path)], runtimes=("claude",))
    assert [(item.tool, item.kind) for item in problems] == [
        ("unavailable_tool", "unknown_tool"),
    ]
