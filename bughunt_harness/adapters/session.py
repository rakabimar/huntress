"""Session binding + runtime launch (``harness start``).

``harness start <runtime> --program <slug>``:

  1. validates the engagement (scope/ROE complete),
  2. records a new session row with the program slug (immutable),
  3. rewrites the runtime's per-program isolation binding (e.g. Claude's
     ``.claude/settings.local.json``) so the session is bound to ONE workspace,
  4. sets ``BUGHUNT_PROGRAM`` in the environment,
  5. execs the chosen runtime binary, handing it the terminal.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from ..config import get_config
from ..errors import HarnessError


def build_argv(
    runtime: str, workspace: Path, *, autonomous: bool = False,
    mcp_config: Path | None = None,
) -> list[str]:
    if runtime == "claude":
        argv = ["claude", "--add-dir", str(workspace)]
        if mcp_config is not None:
            argv.extend(["--mcp-config", str(mcp_config), "--strict-mcp-config"])
        if autonomous:
            argv.extend([
                "--append-system-prompt",
                "An autonomous hunt run is active. Follow AGENT_CORE's bounded research loop, "
                "refresh hunt status after each meaningful step, continue after rejected hypotheses, "
                "and stop only at a persisted legitimate stop condition. Never submit a report.",
            ])
        return argv
    if runtime == "codex":
        return ["codex"]
    if runtime == "opencode":
        return ["opencode"]
    raise HarnessError(f"unknown runtime: {runtime!r}")


def _resolve_binary(runtime: str) -> str:
    if runtime == "claude":
        name = "claude"
    elif runtime == "codex":
        name = "codex"
    else:
        name = "opencode"
    found = shutil.which(name)
    if not found:
        raise HarnessError(
            f"runtime binary {name!r} not found on PATH; install it before `harness start {runtime}`"
        )
    return found


def start_session(
    runtime: str, slug: str, *, autonomous: bool = False, goal: str | None = None,
) -> int:
    from ..hunt import load_program_context
    from ..registry import ProgramRegistry

    cfg = get_config()
    binary = _resolve_binary(runtime)

    from ..program_intake.service import ProgramIntakeService
    ProgramIntakeService(cfg).ensure_current_for_hunt(slug)

    # P0.4: launching a runtime is a live action; the program must be active.
    with load_program_context(slug, cfg, require_active=True) as ctx:
        # Immutable per-session program binding.
        session = ctx.db.start_session(runtime, "orchestrator", slug)
        if autonomous:
            from ..autonomy import start_autonomous_hunt

            run = start_autonomous_hunt(ctx, session.id, goal=goal)
        else:
            run = None

        reg = ProgramRegistry(cfg)
        try:
            reg.set_active(slug)
            siblings = [rec.workspace for rec in reg.list() if rec.slug != slug]
        finally:
            reg.close()

        # Per-program isolation binding (Claude; other runtimes differ in
        # mechanism but inherit the same BUGHUNT_PROGRAM env + state isolation).
        if runtime == "claude":
            from . import claude
            from ..integrations.playwright import playwright_command, write_program_mcp_config

            binding = claude.session_bind(
                ctx.workspace,
                [str(s) for s in siblings],
                cfg,
            )
            mcp_config = (
                write_program_mcp_config(ctx, autonomous=autonomous)
                if playwright_command() is not None else None
            )
        else:
            binding = None
            mcp_config = None

        argv = build_argv(
            runtime, ctx.workspace, autonomous=autonomous, mcp_config=mcp_config,
        )
        env = os.environ.copy()
        env["BUGHUNT_PROGRAM"] = slug
        env["BUGHUNT_SESSION_ID"] = str(session.id)
        env["BUGHUNT_AGENT_ROLE"] = "orchestrator"
        if run is not None:
            env["BUGHUNT_AUTONOMOUS"] = "1"
            env["BUGHUNT_AUTONOMY_RUN_ID"] = str(run.id)

    print(
        f"[harness] program = {slug}  runtime = {runtime}  session = {session.public_id}"
        + (f"  autonomous = {run.public_id} goal={run.goal}" if run else ""),
        file=sys.stderr,
    )
    if binding is not None:
        print(f"[harness] isolation binding -> {binding}", file=sys.stderr)
    if mcp_config is not None:
        print(f"[harness] program MCP config -> {mcp_config}", file=sys.stderr)

    if os.environ.get("BUGHUNT_DRY_RUN") == "1":
        print(f"[harness] DRY RUN: would exec {argv}", file=sys.stderr)
        return 0

    # Hand the terminal to the runtime.  The Stop hook will persist a checkpoint
    # and end the session when the runtime exits.
    os.execvpe(argv[0], argv, env)
    return 0  # pragma: no cover — unreachable after exec


__all__ = ["build_argv", "start_session"]
