"""Shared runtime-adapter helpers.

Adapters translate the *canonical* sources (``AGENT_CORE.md``, ``agent-specs/``,
``skills/``, ``vendor/``) into each runtime's native config.  This module holds
the pieces that are runtime-agnostic: repo-root discovery, canonical file
reading, and agent-spec / skill enumeration.
"""

from __future__ import annotations

import re
from pathlib import Path

# Repo root is two levels up from this file (bughunt_harness/adapters/base.py).
REPO_ROOT = Path(__file__).resolve().parents[2]

RUNTIME_IDS = ("claude", "codex", "opencode")

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


def repo_root() -> Path:
    return REPO_ROOT


def canonical_core_path() -> Path:
    return REPO_ROOT / "AGENT_CORE.md"


def read_core() -> str:
    return canonical_core_path().read_text(encoding="utf-8")


def agent_specs_dir() -> Path:
    return REPO_ROOT / "agent-specs"


def skills_dir() -> Path:
    return REPO_ROOT / "skills"


def list_agent_specs() -> list[Path]:
    d = agent_specs_dir()
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.md"))


def list_skill_dirs() -> list[Path]:
    d = skills_dir()
    if not d.is_dir():
        return []
    out = []
    for child in sorted(d.iterdir()):
        if child.is_dir() and (child / "SKILL.md").is_file():
            out.append(child)
    return out


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split a YAML-frontmatter document into (meta-dict, body)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text.strip()
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, m.group(2).strip()


def render_agent_doc(name: str, description: str, body: str, tools: list[str] | None = None,
                     model: str | None = None) -> str:
    """Render a runtime agent document (Claude/Codex markdown-agent format)."""
    head = [
        "---",
        f"name: {name}",
        f"description: {description}",
    ]
    if tools:
        head.append(f"tools: {', '.join(tools)}")
    if model:
        head.append(f"model: {model}")
    head.append("---")
    return "\n".join(head) + "\n\n" + body.strip() + "\n"


class AgentSpec:
    """Parsed agent-spec file (canonical, runtime-agnostic)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.name = path.stem
        text = path.read_text(encoding="utf-8")
        self.meta, self.body = parse_frontmatter(text)
        self.description = self.meta.get("description", self.name)
        self.tools = [t.strip() for t in self.meta.get("tools", "").split(",") if t.strip()]
        self.model = self.meta.get("model") or None

    def render(self, runtime: str) -> str:
        return render_agent_doc(self.name, self.description, self.body, self.tools or None, self.model)


def load_specs() -> list[AgentSpec]:
    return [AgentSpec(p) for p in list_agent_specs()]


__all__ = [
    "REPO_ROOT",
    "RUNTIME_IDS",
    "repo_root",
    "canonical_core_path",
    "read_core",
    "agent_specs_dir",
    "skills_dir",
    "list_agent_specs",
    "list_skill_dirs",
    "parse_frontmatter",
    "render_agent_doc",
    "AgentSpec",
    "load_specs",
]