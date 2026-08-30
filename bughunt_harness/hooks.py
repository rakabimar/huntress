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
import time

from .errors import HarnessError
from .hunt import load_program_context, render_compact_context, resolve_program_slug

# Only loopback hosts are permitted for direct local-fixture network tooling.
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_LOCALHOST_TLD = re.compile(r"\.localhost$", re.IGNORECASE)

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


def _bound_session_id() -> int | None:
    raw = os.environ.get("BUGHUNT_SESSION_ID", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
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
            sid = _bound_session_id()
            if sid is not None:
                ctx.db.require_session(sid, program_slug=slug)
            brief = render_compact_context(ctx)
            if sid is not None:
                brief += f"\nBound harness session: SES-{sid:03d}\n"
                run = ctx.db.active_autonomy_run(sid)
                if run:
                    brief += f"Autonomous run: {run.public_id} goal={run.goal} (bounded by autonomy.yaml)\n"
    except HarnessError as exc:
        _emit({"hookSpecificOutput": {"additionalContext": f"[harness] active program error: {exc}"}})
        return 0
    _emit({"hookSpecificOutput": {"additionalContext": brief}})
    return 0


# ------------------------------------------------------------------ #
# Stop -- persist state without ending the reusable runtime session
# ------------------------------------------------------------------ #
def _stop(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0
    try:
        with load_program_context(slug) as ctx:
            _checkpoint_session(ctx)
            sid = _bound_session_id()
            turn = ctx.db.active_agent_turn(sid) if sid is not None else None
            if turn:
                started = float(turn.get("metadata", {}).get("started_monotonic", time.monotonic()))
                ctx.db.complete_agent_turn(
                    turn["id"], latency_ms=max(0, int((time.monotonic() - started) * 1000)),
                    outcome="model_turn_completed",
                    metadata={"usage_availability": "UNAVAILABLE_PENDING_PROVIDER_RECONCILIATION"},
                )
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
    sid = _bound_session_id()
    if sid is None:
        return
    session = ctx.db.require_session(sid, program_slug=ctx.slug)
    _checkpoint_session(ctx)
    run = ctx.db.active_autonomy_run(sid)
    turn = ctx.db.active_agent_turn(sid)
    if turn:
        usage = {}
        raw_usage = os.environ.get("BUGHUNT_MODEL_USAGE", "")
        if raw_usage:
            try:
                usage = json.loads(raw_usage)
            except json.JSONDecodeError:
                usage = {}
        ctx.db.complete_agent_turn(
            turn["id"], input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            cached_tokens=int(usage.get("cached_tokens", 0)),
            estimated_cost=float(usage.get("cost", 0)), outcome="session_ended",
        )
    if run:
        ctx.db.stop_autonomy_run(run.id, "runtime session ended", "stopped")
    if session.status == "running":
        ctx.db.end_session(sid)


def _checkpoint_session(ctx) -> None:
    """Checkpoint only the explicitly bound session; leave it running."""
    from .autonomy import build_checkpoint_from_current_state

    sid = _bound_session_id()
    if sid is None:
        return
    ctx.db.require_session(sid, program_slug=ctx.slug)
    build_checkpoint_from_current_state(ctx, sid)


# ------------------------------------------------------------------ #
# PreCompact -- persist state before the runtime compacts its context
# ------------------------------------------------------------------ #
def _pre_compact(payload: dict) -> int:
    slug = _active_slug()
    if not slug:
        return 0
    try:
        with load_program_context(slug) as ctx:
            _checkpoint_session(ctx)
    except HarnessError:
        pass
    return 0


# ------------------------------------------------------------------ #
# UserPromptSubmit / PostToolUse -- permissive hooks (no denier; kinetic state
# persistence is deliberately kept to Stop/SessionEnd/PreCompact).
# ------------------------------------------------------------------ #
def _user_prompt_submit(payload: dict) -> int:
    slug, sid = _active_slug(), _bound_session_id()
    if not slug or sid is None:
        return 0
    try:
        with load_program_context(slug) as ctx:
            if ctx.db.active_agent_turn(sid) is not None:
                return 0
            role = os.environ.get("BUGHUNT_AGENT_ROLE", "orchestrator")
            from .mcp.server import tool_names_for_role
            from .skills.registry import load_skill
            surface = tool_names_for_role(role)
            requested = [item.strip() for item in os.environ.get("BUGHUNT_SKILLS", "").split(",") if item.strip()]
            skills = [name for name in requested if load_skill(name) is not None][:8]
            run = ctx.db.active_autonomy_run(sid)
            turn = ctx.db.start_agent_turn(
                session_id=sid, role=role, runtime=os.environ.get("BUGHUNT_RUNTIME", ""),
                model=os.environ.get("BUGHUNT_MODEL", ""), autonomy_run_id=run.id if run else None,
                specialist_task_id=int(os.environ["BUGHUNT_SPECIALIST_TASK_ID"])
                if os.environ.get("BUGHUNT_SPECIALIST_TASK_ID", "").isdigit() else None,
                skills_loaded=skills, tools_available_count=len(surface) if surface is not None else 0,
                metadata={"hook": "user-prompt-submit", "started_monotonic": time.monotonic(),
                          "interaction_kind": "model_turn"},
            )
            for skill in skills:
                ctx.db.record_skill_usage(
                    session_id=sid, role=role, skill=skill, autonomy_run_id=run.id if run else None,
                    specialist_task_id=turn.get("specialist_task_id"),
                    metadata={"activation": "runtime_context", "agent_turn_id": turn["id"]},
                )
    except HarnessError:
        pass
    return 0


def _post_tool_use(payload: dict) -> int:
    """Record only invocation metadata; never duplicate sensitive tool content."""
    slug, sid = _active_slug(), _bound_session_id()
    if not slug or sid is None:
        return 0
    try:
        with load_program_context(slug) as ctx:
            turn = ctx.db.active_agent_turn(sid)
            run = ctx.db.active_autonomy_run(sid)
            response = payload.get("tool_response") or payload.get("tool_result") or {}
            failed = bool(payload.get("is_error")) or (
                isinstance(response, dict) and bool(response.get("isError"))
            )
            invocation = str(payload.get("tool_use_id") or payload.get("invocation_id") or "")
            if invocation:
                try:
                    active = next(
                        item for item in ctx.db._conn.execute(
                            "SELECT started_at FROM tool_call WHERE invocation_id=?", (invocation,),
                        ).fetchall()
                    )
                    started = __import__("datetime").datetime.fromisoformat(active["started_at"].replace("Z", "+00:00"))
                    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    ctx.db.complete_tool_call(
                        invocation, success=not failed,
                        latency_ms=max(0, int((now - started).total_seconds() * 1000)),
                        error_class="tool_error" if failed else "",
                        result_summary="tool completed" if not failed else "tool failed",
                        metadata={"raw_content_stored": False},
                    )
                except (StopIteration, HarnessError):
                    invocation = ""
            if not invocation:
                ctx.db.record_tool_call(
                    session_id=sid, role=os.environ.get("BUGHUNT_AGENT_ROLE", "orchestrator"),
                    tool=str(payload.get("tool_name", "unknown"))[:200], success=not failed,
                    agent_turn_id=turn["id"] if turn else None,
                    autonomy_run_id=run.id if run else None,
                    error_class="tool_error" if failed else "",
                    metadata={"raw_content_stored": False, "correlation": "unavailable"},
                )
            if str(payload.get("tool_name", "")).lower() == "skill":
                tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
                skill = str(tool_input.get("skill") or tool_input.get("name") or "").strip()
                from .skills.registry import load_skill
                if skill and load_skill(skill) is not None:
                    ctx.db.record_skill_usage(
                        session_id=sid, role=os.environ.get("BUGHUNT_AGENT_ROLE", "orchestrator"),
                        skill=skill, autonomy_run_id=run.id if run else None,
                        metadata={"activation": "runtime_skill_tool", "agent_turn_id": turn["id"] if turn else None},
                    )
    except HarnessError:
        pass
    return 0


# ------------------------------------------------------------------ #
# PreToolUse -- backstop guard on raw Bash
# ------------------------------------------------------------------ #
def _pre_tool_use(payload: dict) -> int:
    _record_pre_tool_use(payload)
    tool_name = payload.get("tool_name", "")
    if tool_name.startswith("mcp__playwright"):
        return _pre_playwright(payload)
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
    # local fixtures on loopback.
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


def _record_pre_tool_use(payload: dict) -> None:
    slug, sid = _active_slug(), _bound_session_id()
    invocation = str(payload.get("tool_use_id") or payload.get("invocation_id") or "")
    if not slug or sid is None or not invocation:
        return
    try:
        with load_program_context(slug) as ctx:
            turn = ctx.db.active_agent_turn(sid)
            run = ctx.db.active_autonomy_run(sid)
            refs = {}
            for env_name, field in (
                ("BUGHUNT_ACTIVE_LEAD_ID", "lead_id"), ("BUGHUNT_ACTIVE_HYPOTHESIS_ID", "hypothesis_id"),
                ("BUGHUNT_ACTIVE_TEST_ID", "test_id"), ("BUGHUNT_SOURCE_ANALYSIS_RUN_ID", "source_analysis_run_id"),
                ("BUGHUNT_SPECIALIST_TASK_ID", "specialist_task_id"),
            ):
                raw = os.environ.get(env_name, "")
                refs[field] = int(raw) if raw.isdigit() else None
            ctx.db.start_tool_call(
                invocation_id=invocation, session_id=sid,
                role=os.environ.get("BUGHUNT_AGENT_ROLE", "orchestrator"),
                tool=str(payload.get("tool_name", "unknown"))[:200],
                agent_turn_id=turn["id"] if turn else None,
                autonomy_run_id=run.id if run else None,
                metadata={"raw_input_stored": False}, **refs,
            )
    except HarnessError:
        return


def _pre_playwright(payload: dict) -> int:
    """Defense-in-depth scope and high-impact browser-operation gate."""
    slug = _active_slug()
    sid = _bound_session_id()
    if not slug or sid is None:
        _emit_deny("Playwright requires an explicitly bound program and session")
        return 2
    data = payload.get("tool_input") or {}
    tool_name = str(payload.get("tool_name", ""))
    operation = tool_name.rsplit("__", 1)[-1]
    mutating_operations = {
        "browser_click", "browser_type", "browser_fill_form", "browser_select_option",
        "browser_press_key", "browser_drag", "browser_file_upload", "browser_handle_dialog",
        "browser_evaluate", "browser_run_code",
    }
    if os.environ.get("BUGHUNT_AUTONOMOUS") == "1" and operation in mutating_operations:
        _emit_deny(
            "raw Playwright mutation is unavailable in autonomous mode; use Harness "
            "browser_action with explicit action_semantics and expected_effect"
        )
        return 2
    serialized = json.dumps(data, default=str)
    urls = re.findall(r"https?://[^\s\"'<>]+", serialized)
    try:
        with load_program_context(slug, require_active=True) as ctx:
            ctx.db.require_session(sid, program_slug=slug, running=True)
            for url in urls:
                decision = ctx.scope.check(url)
                if not decision.allowed:
                    _emit_deny(f"Playwright target is out of scope: {decision.reason}")
                    return 2
            high_impact = re.search(
                r"(?i)\b(delete|close account|purchase|pay now|transfer|send (email|message)|withdraw)\b",
                serialized,
            )
            if high_impact:
                target = urls[0] if urls else None
                policy = ctx.policy.check("state_changing_request", target)
                if policy.decision != "allow":
                    _emit_deny(
                        "high-impact browser action is not AUTO; request a bounded approval "
                        f"through the harness ({policy.reason})"
                    )
                    return 2
    except HarnessError as exc:
        _emit_deny(f"Playwright preflight failed: {exc}")
        return 2
    return 0


def _host_is_fixture(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if host in _LOOPBACK:
        return True
    return bool(_LOCALHOST_TLD.search(host))


def run_hook(event: str) -> int:
    payload = _read_payload()
    handlers = {
        "session-start": _session_start,
        "user-prompt-submit": _user_prompt_submit,
        "pre-tool-use": _pre_tool_use,
        "post-tool-use": _post_tool_use,
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
