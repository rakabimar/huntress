"""Lifecycle hook entry points invoked by the runtime configs.

These run *inside* the AI runtime process (via its hook/subagent machinery) and
are the mechanism by which the harness (a) injects the current program brief at
session start, (b) persists a checkpoint + ends the session on stop, and (c)
applies a last-ditch safety guard on raw shell commands before they execute.

The *authoritative* scope/policy enforcement lives in the request broker; these
hooks provide context injection and a backstop, not the only line of defense.

Protocol
--------
Each hook reads a JSON payload on stdin (runtime-specific shape, see the runtime
adapter) and prints a JSON object on stdout.  Claude Code:
  * SessionStart stdout -> ``{"hookSpecificOutput":{"additionalContext": "..."}}``
  * PreToolUse  stdout -> ``{"hookSpecificOutput":{"permissionDecision":"deny", ...}}``
  * Stop        stdout -> (ignored; we persist state as a side effect)
"""

from __future__ import annotations

import json
import os
import re
import sys

from .errors import HarnessError
from .hunt import load_program_context, render_compact_context, resolve_program_slug

# Safe TLDs / loopback hosts permitted for *local fixture* network tooling.
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_TEST_TLD = re.compile(r"\.(test|invalid|localhost|example)$", re.IGNORECASE)

# Network CLI tools whose raw use is discouraged in favor of the broker.
_NETWORK_TOOLS = (
    "curl", "wget", "httpx", "xh", "httpie",
    "nmap", "masscan", "sqlmap", "nuclei", "ffuf", "wfuzz",
    "zap", "dirb", "gobuster", "nikto",
)

# Commands that are dangerous regardless of context (never exec in-session).
_DENYLIST_PATTERNS = [
    # `rm -rf /` , `rm -fr ~`, `rm -rf $HOME`, etc.
    re.compile(r"\brm\s+(-[^\s]*r[^\s]*f[^\s]*|-[^\s]*f[^\s]*r[^\s]*)\s+(/|~|\$HOME)"),
    # Filesystem / device destruction.
    re.compile(r"\b(mkfs|wipefs|fdisk|gdisk|sfdisk)\b"),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/(sd|hd|nvme|vd|md)"),
    # Overwriting critical files via shell redirection.
    re.compile(r">\s*>\s*(~?/\.ssh/|/etc/(passwd|shadow|sudoers)|/root/)"),
    re.compile(r">\s*(~?/\.ssh/|/etc/(passwd|shadow|sudoers)|/root/)"),
    # git push / force-commit inside a session (submission is human-gated).
    re.compile(r"\bgit\s+push\b"),
    # Fork bomb.
    re.compile(r":\{\s*:\|:&\s*\};\s*:"),
    # Piping a remote fetch into a shell interpreter.
    re.compile(r"\bcurl[^\n|]*\s*\|\s*(ba)?sh\b"),
]


def _read_payload() -> dict:
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _emit_deny(reason: str) -> None:
    _emit({"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": reason}})


def _active_slug() -> str | None:
    env = os.environ.get("BUGHUNT_PROGRAM")
    if env:
        return env
    try:
        return resolve_program_slug(None)
    except HarnessError:
        return None


# ------------------------------------------------------------------ #
# SessionStart -- inject the program brief
# ------------------------------------------------------------------ #
def _session_start(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0  # no active program -> no injection (harness CLI still works)
    try:
        with load_program_context(slug) as ctx:
            brief = render_compact_context(ctx)
    except HarnessError as exc:
        _emit({"hookSpecificOutput": {"additionalContext": f"[harness] active program error: {exc}"}})
        return 0
    _emit({"hookSpecificOutput": {"additionalContext": brief}})
    return 0


# ------------------------------------------------------------------ #
# Stop -- persist checkpoint + end session
# ------------------------------------------------------------------ #
def _stop(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0
    try:
        with load_program_context(slug) as ctx:
            _end_session(ctx)
    except HarnessError:
        pass
    return 0


# ------------------------------------------------------------------ #
# SessionEnd -- final checkpoint + session close (v2.x reliable stop)
# ------------------------------------------------------------------ #
def _session_end(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0
    try:
        with load_program_context(slug) as ctx:
            _end_session(ctx)
    except HarnessError:
        pass
    return 0


def _end_session(ctx) -> None:
    """Close the running session and persist a checkpoint (shared by Stop +
    SessionEnd so neither event can leave a session dangling)."""
    session = ctx.db.latest_session()
    if session and session.status == "running":
        ctx.db.end_session(session.id)
    ctx.db.save_checkpoint(next_action="(auto) session ended via lifecycle hook")


# ------------------------------------------------------------------ #
# PreCompact -- persist state before the runtime compacts its context
# ------------------------------------------------------------------ #
def _pre_compact(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0
    try:
        with load_program_context(slug) as ctx:
            ctx.db.save_checkpoint(next_action="(auto) checkpoint before context compaction")
    except HarnessError:
        pass
    return 0


# ------------------------------------------------------------------ #
# UserPromptSubmit / PostToolUse -- permissive hooks (no denier; kinetic state
# persistence is deliberately kept to Stop/SessionEnd/PreCompact).
# ------------------------------------------------------------------ #
def _noop(payload: dict) -> int:
    return 0


# ------------------------------------------------------------------ #
# PreToolUse -- backstop guard on raw Bash
# ------------------------------------------------------------------ #
def _pre_tool_use(payload: dict) -> int:
    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return 0

    command = ""
    inp = payload.get("tool_input") or {}
    if isinstance(inp, dict):
        command = inp.get("command", "") or ""
    if not command:
        return 0

    for pat in _DENYLIST_PATTERNS:
        if pat.search(command):
            _emit_deny("blocked by harness safety backstop: command matches a dangerous pattern")
            return 2

    # Raw network tooling must route through the broker, unless it only touches
    # local fixtures (loopback or reserved test TLDs).
    words = command.split()
    first = words[0].split("/")[-1] if words else ""
    if first in _NETWORK_TOOLS:
        hosts = re.findall(r"https?://([^/\s:\"]+)", command)
        safe = bool(hosts) and all(_host_is_fixture(h) for h in hosts)
        if not safe:
            _emit_deny(
                "raw network tools are blocked; use the controlled request broker "
                "(MCP `send_authorized_http_request`) so scope/policy/redaction are enforced"
            )
            return 2
    return 0


def _host_is_fixture(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if host in _LOOPBACK:
        return True
    return bool(_TEST_TLD.search(host)) or host.endswith(".localhost")


def run_hook(event: str) -> int:
    payload = _read_payload()
    handlers = {
        "session-start": _session_start,
        "user-prompt-submit": _noop,
        "pre-tool-use": _pre_tool_use,
        "post-tool-use": _noop,
        "stop": _stop,
        "session-end": _session_end,
        "pre-compact": _pre_compact,
    }
    handler = handlers.get(event)
    if handler is None:
        sys.stderr.write(f"unknown hook event: {event!r}\n")
        return 0
    return handler(payload)


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: python -m bughunt_harness.hooks <event>\n")
        return 2
    return run_hook(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())