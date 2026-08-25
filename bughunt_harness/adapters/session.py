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


def build_argv(runtime: str, workspace: Path) -> list[str]:
    if runtime == "claude":
        return ["claude", "--add-dir", str(workspace)]
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


def start_session(runtime: str, slug: str) -> int:
    from ..hunt import load_program_context
    from ..registry import ProgramRegistry

    cfg = get_config()
    binary = _resolve_binary(runtime)

    # P0.4: launching a runtime is a live action; the program must be active.
    with load_program_context(slug, cfg, require_active=True) as ctx:
        # Immutable per-session program binding.
        ctx.db.start_session(runtime, "orchestrator", slug)

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

            binding = claude.session_bind(
                ctx.workspace,
                [str(s) for s in siblings],
                cfg,
                allowed_domains=ctx.engagement.scope.include.included_hosts(),
            )
        else:
            binding = None

        argv = build_argv(runtime, ctx.workspace)
        env = os.environ.copy()
        env["BUGHUNT_PROGRAM"] = slug

    print(f"[harness] program = {slug}  runtime = {runtime}", file=sys.stderr)
    if binding is not None:
        print(f"[harness] isolation binding -> {binding}", file=sys.stderr)

    if os.environ.get("BUGHUNT_DRY_RUN") == "1":
        print(f"[harness] DRY RUN: would exec {argv}", file=sys.stderr)
        return 0

    # Hand the terminal to the runtime.  The Stop hook will persist a checkpoint
    # and end the session when the runtime exits.
    os.execvpe(argv[0], argv, env)
    return 0  # pragma: no cover — unreachable after exec


__all__ = ["build_argv", "start_session"]