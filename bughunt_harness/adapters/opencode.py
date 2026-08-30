"""OpenCode runtime adapter.

OpenCode reads ``AGENTS.md`` (generated shared manual) plus optional
``opencode.json`` project config for MCP registration.  Specialist stances are
emitted as markdown agents under ``.opencode/agent/``.
"""

from __future__ import annotations

from pathlib import Path

import json

from . import base

OPENCODE_DIR = base.REPO_ROOT / ".opencode"


def opencode_json() -> dict:
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "bughunt": {
                "type": "local",
                "command": [str(base.REPO_ROOT / "harness"), "mcp", "serve"],
                "enabled": True,
            }
        },
        "permission": {
            "webfetch": "deny",
            "bash": {
                "*": "deny",
                "./harness *": "allow",
                "harness *": "allow",
                "python -m bughunt_harness.cli *": "allow",
            },
            "external_directory": "deny",
        },
    }


def write_config() -> Path:
    path = base.REPO_ROOT / "opencode.json"
    path.write_text(json.dumps(opencode_json(), indent=2) + "\n", encoding="utf-8")
    return path


def write_agents() -> list[Path]:
    out_dir = OPENCODE_DIR / "agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for spec in base.load_specs():
        path = out_dir / f"{spec.name}.md"
        path.write_text(spec.render("opencode"), encoding="utf-8")
        written.append(path)
    return written


def sync() -> dict:
    return {
        "config": str(write_config()),
        "agents": [str(p) for p in write_agents()],
    }


__all__ = ["OPENCODE_DIR", "opencode_json", "write_config", "write_agents", "sync"]
