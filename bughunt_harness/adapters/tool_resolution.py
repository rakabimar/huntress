"""Canonical agent-spec tool resolution and least-privilege validation."""

from __future__ import annotations

from dataclasses import dataclass

from .base import RUNTIME_IDS, AgentSpec, load_specs


# Canonical names accepted in runtime-neutral agent specs.  These are runtime
# facilities, not Harness MCP grants.  Keep the registry explicit so a typo can
# never be treated as an implicitly available native tool.
NATIVE_RUNTIME_TOOLS: dict[str, frozenset[str]] = {
    "claude": frozenset({"Read", "Write", "Edit", "Bash", "Grep", "Glob", "Agent"}),
    "codex": frozenset({"Read", "Write", "Edit", "Bash", "Grep", "Glob"}),
    "opencode": frozenset({"Read", "Write", "Edit", "Bash", "Grep", "Glob"}),
}

# Spec names that intentionally share a runtime role surface.
AGENT_ROLE_ALIASES = {
    "researcher": "researcher",
    "recon-observer": "recon-specialist",
}

VALIDATOR_ONLY = {
    "begin_finding_validation", "submit_validation_review",
    "finalize_validation_review", "run_independent_finding_validator",
}
REPORT_ONLY = {"prepare_finding_poc", "score_finding_cvss", "prepare_finding_report"}


@dataclass(frozen=True)
class AgentToolProblem:
    agent: str
    runtime: str
    tool: str
    kind: str
    detail: str


def role_for_agent(agent_name: str) -> str:
    from ..mcp.server import ROLE_TOOL_SURFACES

    if agent_name in ROLE_TOOL_SURFACES:
        return agent_name
    return AGENT_ROLE_ALIASES.get(agent_name, "researcher")


def is_native_runtime_tool(runtime: str, tool_name: str) -> bool:
    """Resolve an exact canonical native tool name for one runtime."""
    return tool_name in NATIVE_RUNTIME_TOOLS.get(runtime, frozenset())


def canonical_mcp_tool_name(tool_name: str) -> str:
    name = tool_name.strip()
    for prefix in ("mcp__bughunt__", "bughunt__", "bughunt."):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def resolve_mcp_tool(
    role: str, tool_name: str, *, registered: set[str] | None = None,
) -> str | None:
    """Resolve only when the tool both exists and is reachable by ``role``."""
    from ..mcp.server import registered_tool_names, tool_names_for_role

    canonical = canonical_mcp_tool_name(tool_name)
    actual = registered if registered is not None else registered_tool_names()
    if canonical not in actual:
        return None
    allowed = tool_names_for_role(role)
    if allowed is not None and canonical not in allowed:
        return None
    return canonical


def validate_agent_tool_surfaces(
    specs: list[AgentSpec] | None = None,
    runtimes: tuple[str, ...] = RUNTIME_IDS,
) -> list[AgentToolProblem]:
    """Validate every declaration against native and actual role MCP tools."""
    from ..mcp.server import registered_tool_names

    all_tools = registered_tool_names()
    problems: list[AgentToolProblem] = []
    for spec in specs or load_specs():
        role = role_for_agent(spec.name)
        for runtime in runtimes:
            for tool in spec.tools:
                if is_native_runtime_tool(runtime, tool):
                    continue
                canonical = canonical_mcp_tool_name(tool)
                if canonical not in all_tools:
                    problems.append(AgentToolProblem(
                        spec.name, runtime, tool, "unknown_tool",
                        "not a native runtime tool or registered Harness MCP tool",
                    ))
                elif resolve_mcp_tool(role, canonical, registered=all_tools) is None:
                    problems.append(AgentToolProblem(
                        spec.name, runtime, tool, "inaccessible_role_tool",
                        f"registered but not granted to role {role}",
                    ))
        protected = (VALIDATOR_ONLY | REPORT_ONLY) & {
            canonical_mcp_tool_name(tool) for tool in spec.tools
        }
        if protected and role not in {"finding-validator", "reporter"}:
            for tool in sorted(protected):
                problems.append(AgentToolProblem(
                    spec.name, "all", tool, "privilege_leak",
                    "validator/report-only capability declared by a research role",
                ))
    # De-duplicate cross-runtime MCP failures while retaining native-runtime
    # differences such as a tool supported by Claude but not another runtime.
    unique: dict[tuple[str, str, str, str], AgentToolProblem] = {}
    for problem in problems:
        key = (problem.agent, problem.runtime, problem.tool, problem.kind)
        unique[key] = problem
    return list(unique.values())


__all__ = [
    "AGENT_ROLE_ALIASES", "AgentToolProblem", "NATIVE_RUNTIME_TOOLS",
    "canonical_mcp_tool_name", "is_native_runtime_tool", "resolve_mcp_tool",
    "role_for_agent", "validate_agent_tool_surfaces",
]
