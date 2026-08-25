"""Runtime-config synchronization.

``harness sync`` derives every runtime's native config from the canonical
sources (``AGENT_CORE.md``, ``agent-specs/``, ``skills/``).  The shared
``AGENTS.md`` (used by Codex and OpenCode) inlines the canonical core so it
works even where ``@file`` imports are not supported.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import base, claude, codex, opencode


def agents_md() -> str:
    core = base.read_core()
    return (
        "# AGENTS — Bug Hunting Harness runtime\n\n"
        "You are operating the **Portable AI Bug Hunting Harness**. The full "
        "operating manual (prime directives, research loop, evidence contract, "
        "finding pipeline, prompt-injection defense, stop conditions) follows.\n\n"
        "---\n\n"
        f"{core}"
    )


def write_agents_md() -> Path:
    path = base.REPO_ROOT / "AGENTS.md"
    path.write_text(agents_md(), encoding="utf-8")
    return path


def sync_all(runtimes: list[str] | None = None) -> dict:
    runtimes = list(runtimes) if runtimes else list(base.RUNTIME_IDS)
    unknown = [r for r in runtimes if r not in base.RUNTIME_IDS]
    if unknown:
        raise ValueError(f"unknown runtime(s): {unknown}")

    summary: dict = {"generated": {"AGENTS.md": str(write_agents_md()), "AGENT_CORE.md": "canonical"}}

    if "claude" in runtimes:
        summary["claude"] = claude.sync()
    if "codex" in runtimes:
        summary["codex"] = codex.sync()
    if "opencode" in runtimes:
        summary["opencode"] = opencode.sync()

    return summary


def render_summary(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


__all__ = ["agents_md", "write_agents_md", "sync_all", "render_summary"]