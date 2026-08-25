"""Skill library registry + structural validation.

Reads the canonical ``skills/*/SKILL.md`` tree and derives a uniform skill
index.  Validation is deterministic and structural: it checks the frontmatter
schema, the required body sections, and that every example stays on
``example.test`` / ``localhost`` (spec §81).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = REPO_ROOT / "skills"
MANIFEST = SKILLS_DIR / "manifest.yaml"

VALID_MATURITY = {"draft", "stable", "verified"}
VALID_RISK = {"R0", "R1", "R2", "R3", "R4"}
REQUIRED_SECTIONS = [
    "Purpose",
    "When to use",
    "Process",
    "Evidence",
    "False positives",
    "Stop conditions",
]

_FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    m = _FM_RE.match(text)
    if not m:
        return {}, text
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    return meta, m.group(2)


def load_manifest() -> dict:
    if not MANIFEST.is_file():
        return {}
    try:
        return yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}


def skill_dirs() -> list[Path]:
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(d for d in SKILLS_DIR.iterdir() if d.is_dir() and (d / "SKILL.md").is_file())


def load_skill(slug: str) -> dict | None:
    path = SKILLS_DIR / slug / "SKILL.md"
    if not path.is_file():
        return None
    meta, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
    meta.setdefault("name", slug)
    return {
        "name": meta.get("name", slug),
        "slug": slug,
        "description": meta.get("description", ""),
        "maturity": meta.get("maturity", "draft"),
        "risk_class": meta.get("risk_class", "R0"),
        "category": meta.get("category", "technical"),
        "cwe": meta.get("cwe", []),
        "path": str(path),
        "body": body,
    }


def list_skills() -> list[dict]:
    out = []
    for d in skill_dirs():
        skill = load_skill(d.name)
        if skill:
            # Strip body from the listing to keep it light.
            out.append({k: v for k, v in skill.items() if k != "body"})
    return out


def _sections_of(body: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"(?m)^##\s+(.+)$", body)]


_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_URL_HOST_RE = re.compile(r"https?://([^\s/\"')\]`]+)")


def iter_hosts(body: str) -> list[str]:
    """Extract raw host candidate tokens from example URLs in a body."""
    return _URL_HOST_RE.findall(body)


def is_fixture_host(raw_host: str) -> bool:
    """True if a host token is loopback or a reserved test/invalid TLD.

    Tolerates the surrounding punctuation and ``:port`` / ``:<port>`` suffixes
    that naturally appear inside prose and code spans.
    """
    h = raw_host.strip().lower().rstrip(".")
    h = h.replace("`", "").strip()
    if h in _LOOPBACK:
        return True
    # Strip a numeric or placeholder port (e.g. 127.0.0.1:8080 / :<port>).
    h = re.sub(r":\d+$", "", h)
    h = re.sub(r":<port>$", "", h)
    h = h.rstrip(":")
    if h in _LOOPBACK:
        return True
    return h.endswith((".test", ".invalid", ".localhost", ".example"))


def validate_all() -> list[dict]:
    """Return a list of problems; empty list == the library is structurally valid."""
    problems: list[dict] = []
    seen = set()
    for d in skill_dirs():
        slug = d.name
        seen.add(slug)
        skill = load_skill(slug)
        if skill is None:
            problems.append({"level": "fail", "skill": slug, "message": "SKILL.md unreadable"})
            continue
        if skill["maturity"] not in VALID_MATURITY:
            problems.append({"level": "fail", "skill": slug, "message": f"bad maturity {skill['maturity']!r}"})
        if skill["risk_class"] not in VALID_RISK:
            problems.append({"level": "fail", "skill": slug, "message": f"bad risk_class {skill['risk_class']!r}"})
        if not skill["description"]:
            problems.append({"level": "warn", "skill": slug, "message": "missing description"})
        sections = _sections_of(skill["body"])
        for sec in REQUIRED_SECTIONS:
            if sec not in sections:
                problems.append({"level": "fail", "skill": slug, "message": f"missing required section '## {sec}'"})
        body = skill["body"]
        for host in iter_hosts(body):
            if not is_fixture_host(host):
                problems.append({"level": "warn", "skill": slug, "message": f"example uses non-fixture host {host!r}"})

    # Manifest must reference every skill (and vice versa).
    manifest = load_manifest()
    referenced = set()
    for groups in manifest.get("categories", {}).values():
        for name in groups.get("skills", []):
            referenced.add(name)
    for slug in seen - referenced:
        problems.append({"level": "warn", "skill": slug, "message": "not listed in manifest.yaml router"})
    for slug in referenced - seen:
        problems.append({"level": "fail", "skill": slug, "message": "listed in manifest.yaml but no SKILL.md exists"})

    return problems


__all__ = [
    "REPO_ROOT", "SKILLS_DIR", "MANIFEST",
    "load_manifest", "skill_dirs", "load_skill", "list_skills", "validate_all",
    "iter_hosts", "is_fixture_host",
]