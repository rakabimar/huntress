"""Per-program, per-account Playwright MCP configuration and health checks."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from ..adapters import base
from ..requests.broker import detected_burp_proxy


BROWSER_SEMANTIC_ACTIONS = {
    "test_account_mutation": "browser_test_account_mutation",
    "third_party_communication": "browser_third_party_communication",
    "financial_operation": "browser_financial_operation",
    "credential_change": "browser_credential_change",
    "role_change": "browser_role_change",
    "irreversible_action": "browser_irreversible_action",
    "non_test_account_action": "browser_irreversible_action",
    "persistence": "browser_irreversible_action",
}

_BROWSER_RISK = {
    "browser_observe": 0, "browser_test_account_mutation": 1,
    "browser_suspicious_navigation": 2, "browser_third_party_communication": 2,
    "browser_financial_operation": 2, "browser_credential_change": 2,
    "browser_role_change": 2, "browser_irreversible_action": 3,
}
_IRREVERSIBLE = re.compile(r"(?i)(?:^|[-_/])(delete|destroy|erase|remove-account|close-account|terminate)\b")
_FINANCIAL = re.compile(r"(?i)(?:^|[-_/])(redeem|purchase|checkout|pay|refund|transfer|withdraw)\b")
_CREDENTIAL = re.compile(r"(?i)\b(password|passkey|mfa|2fa|recovery|credential|rotate.?key)\b")
_ROLE = re.compile(r"(?i)\b(role|privilege|permission|invite|membership|make.?admin)\b")
_THIRD_PARTY = re.compile(r"(?i)\b(send|email|message|publish|webhook|notify)\b")
_SUSPICIOUS_GET = re.compile(
    r"(?i)(?:^|[-_/])(logout|delete|remove|unsubscribe|approve|confirm|redeem|"
    r"cancel|disable|revoke|reset|callback|action)(?:$|[-_/?#])"
)


@dataclass
class BrowserActionResult:
    ok: bool
    decision: str
    reason: str
    operation: str = ""
    target_url: str = ""
    account: str = ""
    action_semantics: str = ""
    output: str = ""
    approval_id: str | None = None
    artifacts: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "decision": self.decision,
            "mode": {"allow": "AUTO", "approval_required": "ASK", "deny": "DENY"}.get(
                self.decision, self.decision.upper(),
            ),
            "reason": self.reason, "operation": self.operation,
            "target_url": self.target_url, "account": self.account,
            "action_semantics": self.action_semantics,
            "output": self.output, "approval_id": self.approval_id,
            "artifacts": self.artifacts,
        }


def playwright_command() -> list[str] | None:
    local = base.REPO_ROOT / "node_modules" / ".bin" / "playwright-mcp"
    if local.is_file():
        return [str(local)]
    if shutil.which("playwright-mcp"):
        return [shutil.which("playwright-mcp") or "playwright-mcp"]
    return None


def chromium_executable() -> str | None:
    return (
        shutil.which("chromium") or shutil.which("chromium-browser")
        or shutil.which("google-chrome") or shutil.which("google-chrome-stable")
    )


def _allowed_origins(engagement) -> list[str]:
    origins: set[str] = set()
    inc = engagement.scope.include
    for url in inc.urls + inc.path_urls:
        parsed = urlparse(url)
        origins.add(f"{parsed.scheme}://{parsed.netloc}")
    for host in inc.domains + inc.subdomains:
        origins.update({f"https://{host}", f"http://{host}"})
    for wildcard in inc.wildcards:
        origins.update({f"https://{wildcard}", f"http://{wildcard}"})
    for ip in inc.ipv4:
        origins.update({f"https://{ip}", f"http://{ip}"})
    # Local fixture/control plane is always available to the research browser.
    origins.update({"http://127.0.0.1:*", "https://127.0.0.1:*", "http://localhost:*"})
    return sorted(origins)


def write_program_mcp_config(ctx, *, headed: bool = True, autonomous: bool = False) -> Path:
    """Generate disposable MCP config with isolated account browser profiles."""
    command = playwright_command()
    if command is None:
        raise RuntimeError("@playwright/mcp is not installed; run `npm install`")
    browser_root = ctx.workspace / "browser"
    browser_root.mkdir(parents=True, exist_ok=True)
    accounts = [a for a in ctx.engagement.accounts.accounts if a.enabled] or [None]
    servers: dict[str, dict] = {
        "bughunt": {
            "command": str(base.REPO_ROOT / "harness"),
            "args": ["mcp", "serve"],
        },
    }
    proxy = ctx.engagement.integrations.burp.proxy_url or detected_burp_proxy()
    origins = ";".join(_allowed_origins(ctx.engagement))
    # Autonomous runtimes receive browser observation/mutation only through
    # the Harness MCP. Official Playwright exposes both kinds in one server,
    # so registering it raw here would recreate the policy bypass.
    if autonomous:
        path = browser_root / "mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n", encoding="utf-8")
        return path
    for account in accounts:
        account_id = account.id if account else "default"
        profile = browser_root / account_id / "profile"
        output = browser_root / account_id / "artifacts"
        profile.mkdir(parents=True, exist_ok=True)
        output.mkdir(parents=True, exist_ok=True)
        args = [
            *command[1:],
            "--user-data-dir", str(profile), "--output-dir", str(output),
            "--allowed-origins", origins,
        ]
        executable = chromium_executable()
        if executable:
            args.extend(["--executable-path", executable])
        if not headed:
            args.append("--headless")
        if proxy:
            args.extend(["--proxy-server", proxy])
        servers[f"playwright_{account_id}"] = {"command": command[0], "args": args}
    path = browser_root / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n", encoding="utf-8")
    return path


def classify_browser_action(
    *, target_url: str, declared_semantics: str, expected_effect: str = "",
    operation: str = "",
) -> dict:
    """Independently derive a risk floor; model labels can only increase risk."""
    declared = BROWSER_SEMANTIC_ACTIONS.get(declared_semantics)
    if declared is None:
        return {
            "action": "state_changing_request", "declared_action": "",
            "derived_action": "state_changing_request",
            "reason": "unknown browser mutation requires bounded human approval",
            "classification_confirmed": False, "unknown_mutation": True,
        }
    signal = " ".join((target_url, expected_effect, operation))
    derived, reason = "browser_test_account_mutation", "generic mutation"
    for pattern, action, why in (
        (_IRREVERSIBLE, "browser_irreversible_action", "delete/irreversible signal"),
        (_FINANCIAL, "browser_financial_operation", "financial signal"),
        (_CREDENTIAL, "browser_credential_change", "credential lifecycle signal"),
        (_ROLE, "browser_role_change", "role/membership signal"),
        (_THIRD_PARTY, "browser_third_party_communication", "third-party communication signal"),
    ):
        if pattern.search(signal):
            derived, reason = action, why
            break
    effective = max((declared, derived), key=lambda item: _BROWSER_RISK[item])
    return {"action": effective, "declared_action": declared, "derived_action": derived,
            "reason": reason, "classification_confirmed": effective == declared}


def browser_policy_preflight(
    ctx, *, target_url: str, action_semantics: str, account: str,
    expected_effect: str = "", operation: str = "",
) -> dict:
    """Apply policy to the independently confirmed semantic risk floor."""
    classification = classify_browser_action(
        target_url=target_url, declared_semantics=action_semantics,
        expected_effect=expected_effect, operation=operation,
    )
    action = classification["action"]
    if not action:
        return {
            "action": "", "decision": "deny", "mode": "DENY",
            "reason": classification["reason"], "scope": ctx.scope.check(target_url).as_dict(),
        }
    if action_semantics == "test_account_mutation":
        configured = ctx.engagement.accounts.by_id().get(account)
        if configured is None or not configured.enabled:
            return {
                "action": action, "decision": "deny", "mode": "DENY",
                "reason": "test-account mutation requires an enabled configured account",
                "scope": ctx.scope.check(target_url).as_dict(),
            }
    decision = ctx.policy.check(action, target_url).as_dict()
    if classification.get("unknown_mutation") and decision["decision"] != "deny":
        decision.update({
            "decision": "approval_required", "mode": "ASK",
            "reason": "unknown browser mutation is ASK by default",
        })
    decision["classification"] = classification
    return decision


def _program_browser_args(ctx, account: str, *, headed: bool) -> tuple[list[str], Path]:
    command = playwright_command()
    if command is None:
        raise RuntimeError("@playwright/mcp is not installed")
    if account not in {a.id for a in ctx.engagement.accounts.accounts if a.enabled}:
        raise RuntimeError("browser account is not configured and enabled")
    root = ctx.workspace / "browser" / account
    profile, output = root / "profile", root / "artifacts"
    profile.mkdir(parents=True, exist_ok=True); output.mkdir(parents=True, exist_ok=True)
    args = [
        *command[1:], "--user-data-dir", str(profile), "--output-dir", str(output),
        "--allowed-origins", ";".join(_allowed_origins(ctx.engagement)),
    ]
    executable = chromium_executable()
    if executable:
        args.extend(["--executable-path", executable])
    if not headed:
        args.append("--headless")
    proxy = ctx.engagement.integrations.burp.proxy_url or detected_burp_proxy()
    if proxy:
        args.extend(["--proxy-server", proxy])
    return [command[0], *args], output


async def _call_program_browser(ctx, account: str, calls: list[tuple[str, dict]], timeout: float) -> list[object]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    command, _output = _program_browser_args(
        ctx, account, headed=ctx.engagement.integrations.playwright.headed,
    )
    params = StdioServerParameters(command=command[0], args=command[1:], cwd=str(base.REPO_ROOT))
    results = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=timeout)) as session:
            await session.initialize()
            names = {tool.name for tool in (await session.list_tools()).tools}
            for name, arguments in calls:
                if name not in names:
                    raise RuntimeError(f"Playwright tool {name!r} is unavailable")
                result = await session.call_tool(name, arguments)
                if result.isError:
                    raise RuntimeError(f"Playwright tool {name!r} failed")
                results.append(result)
    return results


def _text_result(result: object, limit: int = 6000) -> str:
    text = "\n".join(
        getattr(item, "text", "") for item in getattr(result, "content", [])
        if getattr(item, "type", "") == "text"
    )
    return "UNTRUSTED TARGET DATA\n" + text[:limit]


def browser_observe(ctx, *, account: str, target_url: str, operation: str = "snapshot", timeout: int = 30) -> BrowserActionResult:
    """Execute a strictly read-only browser observation through Harness policy."""
    if operation not in {"snapshot", "screenshot"}:
        return BrowserActionResult(False, "deny", "unsupported read-only browser operation", operation, target_url, account)
    parsed = urlparse(target_url)
    navigation_action = (
        "browser_suspicious_navigation"
        if _SUSPICIOUS_GET.search(parsed.path + ("?" + parsed.query if parsed.query else ""))
        else "browser_observe"
    )
    decision = ctx.policy.check(navigation_action, target_url)
    if decision.decision != "allow":
        return BrowserActionResult(False, decision.decision, decision.reason, operation, target_url, account)
    tool = "browser_snapshot" if operation == "snapshot" else "browser_take_screenshot"
    try:
        results = asyncio.run(_call_program_browser(
            ctx, account, [("browser_navigate", {"url": target_url}), (tool, {})], timeout,
        ))
        return BrowserActionResult(True, "allow", "allowed", operation, target_url, account, "observation", _text_result(results[-1]))
    except Exception as exc:
        return BrowserActionResult(False, "allow", f"browser execution error: {type(exc).__name__}", operation, target_url, account)


def browser_action(
    ctx, *, session_id: int, account: str, target_url: str, operation: str,
    target: str, action_semantics: str, expected_effect: str,
    element_ref: str = "", value: str = "", timeout: int = 30,
) -> BrowserActionResult:
    """Policy-mediate one explicitly semantic state-changing browser action."""
    from ..requests.broker import request_params_hash

    if operation not in {"click", "fill", "select_option", "press_key"}:
        return BrowserActionResult(False, "deny", "unsupported browser mutation operation", operation, target_url, account, action_semantics)
    if not target.strip() or not expected_effect.strip() or not element_ref.strip():
        return BrowserActionResult(False, "deny", "target, element_ref, and expected_effect are required", operation, target_url, account, action_semantics)
    decision = browser_policy_preflight(
        ctx, target_url=target_url, action_semantics=action_semantics, account=account,
        expected_effect=expected_effect, operation=operation,
    )
    if decision["decision"] == "deny":
        return BrowserActionResult(False, "deny", decision["reason"], operation, target_url, account, action_semantics)
    action = decision["action"]
    approval = None
    approval_id = None
    payload = {"operation": operation, "target": target, "expected_effect": expected_effect, "element_ref": element_ref}
    params_hash = request_params_hash("BROWSER", target_url, None, payload, None)
    if decision["decision"] == "approval_required":
        approval = ctx.db.find_valid_approval(
            action, target=target_url, program=ctx.slug, method="BROWSER",
            params_hash=params_hash, auth_context=account,
        )
        if approval is None:
            approval = ctx.db.request_approval(
                action, target_url, requested_by="orchestrator", note=expected_effect,
                program=ctx.slug, method="BROWSER", params_hash=params_hash,
                session_id=session_id, auth_context=account,
                constraints={"max_requests": 1, "max_concurrency": 1, "duration_seconds": timeout},
            )
            return BrowserActionResult(False, "approval_required", decision["reason"], operation, target_url, account, action_semantics, approval_id=approval.public_id)
        approval_id = approval.public_id
        try:
            ctx.db.record_approval_use(approval.id)
        except Exception as exc:
            return BrowserActionResult(False, "deny", str(exc), operation, target_url, account, action_semantics, approval_id=approval_id)
    arguments = {"element": target, "ref": element_ref}
    if operation == "fill":
        arguments["text"] = value
    elif operation == "select_option":
        arguments["values"] = [value]
    elif operation == "press_key":
        arguments = {"key": value}
    try:
        results = asyncio.run(_call_program_browser(
            ctx, account,
            [("browser_navigate", {"url": target_url}), (f"browser_{operation}", arguments), ("browser_snapshot", {})],
            timeout,
        ))
        return BrowserActionResult(True, "allow", "allowed", operation, target_url, account, action_semantics, _text_result(results[-1]), approval_id)
    except Exception as exc:
        return BrowserActionResult(False, "allow", f"browser execution error: {type(exc).__name__}", operation, target_url, account, action_semantics, approval_id=approval_id)


def playwright_health(timeout: float = 8.0) -> dict:
    command = playwright_command()
    if command is None:
        return {"ok": False, "installed": False, "error": "@playwright/mcp is not installed"}
    try:
        proc = subprocess.run(
            [*command, "--version"], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        text = (proc.stdout or proc.stderr).strip()
        return {
            "ok": proc.returncode == 0, "installed": True,
            "command": command[0], "version": text,
            "chromium": chromium_executable(),
            "error": "" if proc.returncode == 0 else text,
        }
    except Exception as exc:
        return {
            "ok": False, "installed": True, "command": command[0],
            "error": f"{type(exc).__name__}: {exc}",
        }


async def _browser_probe_async(target: str, timeout: float) -> dict:
    """Handshake, list tools, and navigate one caller-supplied localhost URL."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    command = playwright_command()
    executable = chromium_executable()
    if command is None or executable is None:
        return {"ok": False, "error": "Playwright MCP or Chromium is unavailable"}
    parsed = urlparse(target)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return {"ok": False, "error": "browser health probe accepts loopback URLs only"}
    origin = f"{parsed.scheme}://{parsed.netloc}"
    with tempfile.TemporaryDirectory(prefix="bughunt-playwright-doctor-") as td:
        args = [
            *command[1:], "--headless", "--isolated", "--output-dir", td,
            "--allowed-origins", origin, "--executable-path", executable,
        ]
        params = StdioServerParameters(command=command[0], args=args, cwd=str(base.REPO_ROOT))
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=timeout),
                ) as session:
                    initialized = await session.initialize()
                    listing = await session.list_tools()
                    names = {tool.name for tool in listing.tools}
                    if "browser_navigate" not in names or "browser_snapshot" not in names:
                        return {"ok": False, "error": "required browser tools are absent"}
                    navigated = await session.call_tool("browser_navigate", {"url": target})
                    if navigated.isError:
                        return {"ok": False, "error": "browser_navigate returned an MCP error"}
                    snapshot = await session.call_tool("browser_snapshot", {})
                    if snapshot.isError:
                        return {"ok": False, "error": "browser_snapshot returned an MCP error"}
                    text = "\n".join(
                        getattr(item, "text", "") for item in snapshot.content
                        if getattr(item, "type", "") == "text"
                    )
                    return {
                        "ok": True, "server": initialized.serverInfo.name,
                        "version": initialized.serverInfo.version,
                        "tool_count": len(names), "snapshot": text[:500],
                    }
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def playwright_browser_probe(target: str, timeout: float = 20.0) -> dict:
    return asyncio.run(_browser_probe_async(target, timeout))


__all__ = [
    "playwright_command", "chromium_executable", "write_program_mcp_config",
    "playwright_health", "playwright_browser_probe",
    "classify_browser_action", "browser_policy_preflight", "browser_observe", "browser_action",
    "BrowserActionResult", "BROWSER_SEMANTIC_ACTIONS",
]
