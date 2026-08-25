"""Runtime tooling detection (Burp proxy + browser/Playwright), deterministic.

Detection is genuine: it reports what is actually importable, on PATH, or
configured via environment — never a hardcoded "detected".  Output is metadata
only (paths/booleans), no secret values.
"""

from __future__ import annotations

import importlib.util
import os
import shutil


def detect_burp(env: dict[str, str] | None = None, which=shutil.which) -> dict:
    """Report whether Burp is usable: a binary on PATH and/or a proxy env.

    The request broker routes through ``BUGHUNT_BURP_PROXY`` when set, so either
    signal is enough to say "Burp is wired in".
    """
    env = os.environ if env is None else env
    proxy = env.get("BUGHUNT_BURP_PROXY")
    binary = which("burpsuite") or which("BurpSuitePro") or which("burp")
    return {
        "binary": binary,
        "proxy_env_set": bool(proxy),
        "detected": bool(binary or proxy),
    }


def detect_browser(which=shutil.which) -> dict:
    """Report whether a browser/Playwright surface is available.

    The browser surface is the Playwright MCP plugin; detect its Python binding,
    a node/npx runtime (for the headless plugin), or a standalone playwright CLI.
    """
    py_mod = importlib.util.find_spec("playwright") is not None
    node = which("node") is not None
    npx = which("npx") is not None
    playwright_cli = which("playwright") is not None
    return {
        "python_module": py_mod,
        "node": node,
        "npx": npx,
        "playwright_cli": playwright_cli,
        "detected": bool(py_mod or (node and npx) or playwright_cli),
    }


__all__ = ["detect_burp", "detect_browser"]