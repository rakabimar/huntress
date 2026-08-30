"""Claude Code runtime adapter.

Generates Claude Code's native config from canonical sources:

  * ``CLAUDE.md``                     — wrapper referencing ``AGENT_CORE.md``
  * ``.claude/settings.json``         — project permissions + lifecycle hooks
  * ``.claude/agents/*.md``           — specialist agents (from ``agent-specs/``)
  * ``.claude/skills/*``              — symlinks into ``skills/``
  * ``.claude/settings.local.json``   — per-program (session) isolation binding
  * ``.mcp.json``                     — registers the harness MCP server

``settings.local.json`` is written only at ``harness start`` time and is never
committed; it binds the session to ONE program workspace and denies the others.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..config import HarnessConfig, get_config
from . import base

CLAUDE_DIR = base.REPO_ROOT / ".claude"


def _hook_cmd(event: str) -> str:
    return f"{base.REPO_ROOT / 'harness'} hook {event}"


def _hook(match: str | None, event: str, timeout: int) -> dict:
    """One modern (Claude Code v2.x) hook entry: ``{matcher?, hooks:[...]}`.

    ``command`` is the harness CLI invocation for `event`; ``timeout`` bounds
    the hook so a hung invocation cannot wedge the session; exit code 2 from the
    harness blocks the matched tool (PreToolUse backstop)."""
    cfg: dict = {"type": "command", "command": _hook_cmd(event), "timeout": timeout}
    entry: dict = {"hooks": [cfg]}
    if match is not None:
        entry["matcher"] = match
    return entry


# --------------------------------------------------------------------------- #
# settings.json (canonical project config — committed)
# --------------------------------------------------------------------------- #
def settings_json() -> dict:
    deny = [
        # Secrets never enter the model context (broker resolves them).
        "Read(~/.bughunt/secrets/**)",
        "Edit(~/.bughunt/secrets/**)",
        # Lateral-movement / credential theft surfaces.
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.gnupg/**)",
        "Read(~/.netrc)",
        "WebFetch",
        "WebSearch",
        # No raw database manipulation — state is mutated via the harness API.
        "Bash(sqlite3:*)",
        "Bash(* .db *)**",
        # No pushing/force-committing from inside a session.
        "Bash(git push:*)",
        # Heavy scanners are never justified in-session (use the broker).
        "Bash(nmap:*)",
        "Bash(masscan:*)",
        "Bash(sqlmap:*)",
        "Bash(nuclei:*)",
        "Bash(ffuf:*)",
        "Bash(wfuzz:*)",
        "Bash(nikto:*)",
    ]
    allow = [
        "Bash(./harness:*)",
        "Bash(harness:*)",
        "Bash(python -m bughunt_harness.cli:*)",
    ]
    # Full modern hook event set (Claude Code v2.x).  Events with no denier are
    # still wired so the harness can checkpoint/persist at the right moments.
    hooks = {
        "SessionStart": [_hook(None, "session-start", 30)],
        "UserPromptSubmit": [_hook(None, "user-prompt-submit", 10)],
        "PreToolUse": [
            _hook("Bash", "pre-tool-use", 10),
            _hook("mcp__playwright.*", "pre-tool-use", 10),
        ],
        "PostToolUse": [_hook(None, "post-tool-use", 10)],
        "PostToolUseFailure": [_hook(None, "post-tool-use", 10)],
        "Stop": [_hook(None, "stop", 30)],
        "PreCompact": [_hook(None, "pre-compact", 30)],
        "SessionEnd": [_hook(None, "session-end", 30)],
    }
    return {
        "permissions": {"allow": allow, "deny": deny},
        "hooks": hooks,
        # Broker-only egress boundary.  The model process may reach only local
        # integration planes; real targets are never copied from scope into
        # this allowlist.  The broker is a separate, policy-gated process.
        "sandbox": {
            "enabled": True,
            "filesystem": {
                "denyWrite": ["~/.bughunt/secrets/**", "~/.ssh/**"],
            },
            "network": {
                "allowLocalBinding": True,
                "strictAllowlist": True,
                "allowedDomains": [
                    "localhost",
                    "*.localhost",
                    "127.0.0.1",
                    "[::1]",
                ],
                "deniedDomains": [],
            },
        },
    }


# --------------------------------------------------------------------------- #
# .mcp.json
# --------------------------------------------------------------------------- #
def mcp_json() -> dict:
    return {
        "mcpServers": {
            "bughunt": {
                "command": str(base.REPO_ROOT / "harness"),
                "args": ["mcp", "serve"],
            }
        }
    }


# --------------------------------------------------------------------------- #
# CLAUDE.md (wrapper around the canonical core)
# --------------------------------------------------------------------------- #
def claude_md() -> str:
    return (
        "# Claude Code — Bug Hunting Harness runtime\n\n"
        "You are operating the **Portable AI Bug Hunting Harness** as a research "
        "runtime. The full operating manual is the canonical source below.\n\n"
        "@AGENT_CORE.md\n\n"
        "# Claude-specific wiring\n\n"
        "- Program state and gating live in the harness tools; use the **bughunt** "
        "MCP server tools (`scope_preflight`, `policy_preflight`, "
        "`send_authorized_http_request`, entity tools) and the `./harness` CLI.\n"
        "- Lifecycle hooks (`.claude/settings.json`) inject the active program brief "
        "on SessionStart and persist a checkpoint on Stop.\n"
        "- Specialist stances are available as subagents (see `.claude/agents/`); "
        "dispatch them rather than doing everything inline.\n"
        "- Per-program isolation is enforced by `.claude/settings.local.json`, which "
        "`harness start` rewrites for the active program.\n"
    )


# --------------------------------------------------------------------------- #
# mutation helpers
# --------------------------------------------------------------------------- #
def write_settings() -> Path:
    path = CLAUDE_DIR / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings_json(), indent=2) + "\n", encoding="utf-8")
    return path


def write_mcp() -> Path:
    path = base.REPO_ROOT / ".mcp.json"
    path.write_text(json.dumps(mcp_json(), indent=2) + "\n", encoding="utf-8")
    return path


def write_claude_md() -> Path:
    path = base.REPO_ROOT / "CLAUDE.md"
    path.write_text(claude_md(), encoding="utf-8")
    return path


def write_agents() -> list[Path]:
    out_dir = CLAUDE_DIR / "agents"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for spec in base.load_specs():
        path = out_dir / f"{spec.name}.md"
        path.write_text(spec.render("claude"), encoding="utf-8")
        written.append(path)
    return written


def sync_skills() -> list[Path]:
    out_dir = CLAUDE_DIR / "skills"
    out_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    for skill in base.list_skill_dirs():
        link = out_dir / skill.name
        if link.exists() or link.is_symlink():
            if link.is_symlink() or link.is_dir():
                continue
        try:
            os.symlink(skill, link)
        except OSError:
            import shutil

            shutil.rmtree(link, ignore_errors=True)
            shutil.copytree(skill, link)
        created.append(link)
    return created


def session_bind(
    workspace: Path,
    siblings: list[Path],
    config: HarnessConfig | None = None,
    *,
    allowed_domains: list[str] | None = None,
) -> Path:
    """Write the per-program isolation binding for the active session.

    Grants read/edit for `workspace` (via additionalDirectories), denies every
    *other* program workspace plus all secret locations.  ``allowed_domains``
    is retained only as a source-compatible argument and is intentionally
    ignored: target scope must never become direct model-process egress.
    """
    cfg = config or get_config()
    deny: list[str] = []
    for sib in siblings:
        sib = Path(sib)
        if sib.resolve() == Path(workspace).resolve():
            continue
        deny.append(f"Read({sib})")
        deny.append(f"Read({sib}/**)")
        deny.append(f"Edit({sib}/**)")
    deny += [
        f"Read({cfg.secrets_dir}/**)",
        f"Edit({cfg.secrets_dir}/**)",
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.gnupg/**)",
        "Read(~/.bughunt/registry.db)",
    ]
    # Only loopback integration endpoints.  In-scope public domains are still
    # blocked so curl/requests/fetch cannot bypass the Request Broker.
    egress = [
        "localhost",
        "*.localhost",
        "127.0.0.1",
        "[::1]",
    ]
    doc = {
        "permissions": {"additionalDirectories": [str(workspace)], "deny": deny},
        "sandbox": {
            "network": {
                "strictAllowlist": True,
                "allowedDomains": egress,
                "deniedDomains": [],
            }
        },
    }
    path = CLAUDE_DIR / "settings.local.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def sync() -> dict:
    """Regenerate all Claude-derived config; return a change summary."""
    changed = {
        "claude_md": str(write_claude_md()),
        "settings": str(write_settings()),
        "mcp": str(write_mcp()),
        "agents": [str(p) for p in write_agents()],
        "skills_symlinked": [str(p) for p in sync_skills()],
    }
    return changed


__all__ = ["CLAUDE_DIR", "settings_json", "mcp_json", "claude_md", "write_settings",
           "write_mcp", "write_claude_md", "write_agents", "sync_skills",
           "session_bind", "sync"]
