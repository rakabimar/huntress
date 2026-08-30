"""Skill library registry + structural validation.

Reads the canonical ``skills/*/SKILL.md`` tree and derives a uniform skill
index.  Validation is deterministic and structural: it checks the frontmatter
schema, the required body sections, and that every example stays on
``example.test`` / ``localhost`` (spec §81).
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = REPO_ROOT / "skills"
MANIFEST = SKILLS_DIR / "manifest.yaml"

VALID_MATURITY = {"draft", "stable", "verified"}
VALID_RISK = {"R0", "R1", "R2", "R3", "R4"}
REQUIRED_MATURE_EVAL_GROUPS = {
    "routing", "positive", "negative", "false-positive", "evidence",
    "tool-selection", "safety", "complex-scenario",
}
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
        "status": meta.get("status", "stable"),
        "canonical_skill": meta.get("canonical_skill"),
        "canonical": bool(meta.get("canonical", meta.get("status", "stable") != "deprecated")),
        "primary_specialist": meta.get("primary_specialist", ""),
        "related_skills": meta.get("related_skills", []),
        "primary_triggers": meta.get("primary_triggers", []),
        "secondary_triggers": meta.get("secondary_triggers", []),
        "negative_triggers": meta.get("negative_triggers", []),
        "capability_pack": meta.get("capability_pack", "default"),
        "whitebox": bool(meta.get("whitebox", False)),
        "blackbox": bool(meta.get("blackbox", True)),
        "requires_tools": meta.get("requires_tools", []),
        "behavioral_eval_status": meta.get("behavioral_eval_status", "missing"),
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


def resolve_skill_slug(slug: str) -> str:
    """Resolve a deprecated alias to one stable canonical skill."""
    skill = load_skill(slug)
    if skill and skill.get("status") == "deprecated" and skill.get("canonical_skill"):
        return str(skill["canonical_skill"])
    return slug


def route_skills(
    lead_text: str,
    *,
    whitebox: bool = False,
    capability_packs: set[str] | None = None,
    limit: int = 3,
) -> list[dict]:
    """Select one primary and at most two supporting canonical skills.

    This is deliberately a small lexical pre-router, not a vulnerability
    classifier.  The model still owns the hypothesis; this function only keeps
    irrelevant skill context out of a turn.
    """
    text = re.sub(r"[^a-z0-9]+", " ", lead_text.lower()).strip()
    enabled = capability_packs or {"default", "whitebox"}
    text_tokens = set(text.split())

    def trigger_score(value: object, weight: int) -> int:
        phrase = re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()
        if not phrase:
            return 0
        if phrase in text:
            return weight * 2
        tokens = set(phrase.split())
        overlap = len(tokens & text_tokens)
        return weight * overlap if overlap else 0

    ranked: list[tuple[int, str, dict]] = []
    for skill in (load_skill(path.name) for path in skill_dirs()):
        if not skill or not skill["canonical"] or skill["status"] == "deprecated":
            continue
        if skill["category"] == "core" or skill["maturity"] not in {"stable", "verified"}:
            continue
        if whitebox and not skill["whitebox"] and not skill["blackbox"]:
            continue
        if not whitebox and not skill["blackbox"]:
            continue
        pack = str(skill.get("capability_pack") or "default")
        if pack not in enabled and pack != "default":
            continue
        negatives = [str(value).lower() for value in skill["negative_triggers"]]
        if any(trigger and trigger in text for trigger in negatives):
            continue
        primary = sum(trigger_score(value, 4) for value in skill["primary_triggers"])
        secondary = sum(trigger_score(value, 2) for value in skill["secondary_triggers"])
        name_hint = 1 if skill["slug"].replace("-", " ") in text else 0
        score = primary + secondary + name_hint
        if score:
            ranked.append((score, skill["slug"], skill))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [
        {k: value for k, value in skill.items() if k != "body"}
        for _, _, skill in ranked[: max(1, min(limit, 3))]
    ]


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

        # Stable technical skills must carry decision-making depth, routing
        # boundaries, and deterministic behavioral fixtures. Core stance skills
        # are intentionally compact and are evaluated by the research pipeline.
        if skill["maturity"] == "stable" and skill["category"] != "core" and skill["status"] != "deprecated":
            for field in ("primary_specialist", "primary_triggers", "negative_triggers", "related_skills"):
                if not skill.get(field):
                    problems.append({"level": "fail", "skill": slug, "message": f"stable skill missing routing metadata {field}"})
            refs = list((d / "references").glob("*.md")) if (d / "references").is_dir() else []
            ref_text = "\n".join(path.read_text(encoding="utf-8") for path in refs).lower()
            semantic_files = {path.name for path in refs}
            semantic_checks = {
                "mental model": "mental-model.md" in semantic_files or "expert-guide.md" in semantic_files,
                "attack surface": "attack-surface.md" in semantic_files or "expert-guide.md" in semantic_files,
                "false positive": "false positive" in ref_text,
                "evidence": "evidence" in ref_text,
                "remediation": "remediation" in ref_text,
                "implementation": "implementation" in ref_text,
            }
            for concept, present in semantic_checks.items():
                if not present:
                    problems.append({"level": "fail", "skill": slug, "message": f"stable references missing {concept!r} guidance"})
            eval_root = d / "evals"
            present_groups = {p.name for p in eval_root.iterdir() if p.is_dir() and list(p.glob("*.yaml"))} if eval_root.is_dir() else set()
            missing_groups = REQUIRED_MATURE_EVAL_GROUPS - present_groups
            if missing_groups:
                problems.append({"level": "fail", "skill": slug, "message": f"stable skill missing eval groups: {', '.join(sorted(missing_groups))}"})
            if skill.get("behavioral_eval_status") == "missing":
                problems.append({"level": "fail", "skill": slug, "message": "stable skill missing behavioral_eval_status"})

    # Manifest must reference every skill (and vice versa).
    manifest = load_manifest()
    referenced = set()
    for groups in manifest.get("categories", {}).values():
        for name in groups.get("skills", []):
            referenced.add(name)
    deprecated = {
        slug for slug in seen
        if (load_skill(slug) or {}).get("status") == "deprecated"
    }
    for slug in (seen - referenced) - deprecated:
        problems.append({"level": "warn", "skill": slug, "message": "not listed in manifest.yaml router"})
    for slug in referenced - seen:
        problems.append({"level": "fail", "skill": slug, "message": "listed in manifest.yaml but no SKILL.md exists"})

    # Detect near-identical methodology/expert references across unrelated
    # stable technical skills. Shared safety phrases are too short to trigger.
    comparable = []
    for slug in sorted(seen):
        skill = load_skill(slug) or {}
        if skill.get("maturity") != "stable" or skill.get("category") == "core" or skill.get("status") == "deprecated":
            continue
        directory = SKILLS_DIR / slug / "references"
        candidates = [directory / "methodology.md", directory / "expert-guide.md", directory / "mental-model.md"]
        text = "\n".join(p.read_text(encoding="utf-8") for p in candidates if p.is_file())
        normalized = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9\s]", " ", text.lower())).strip()
        if len(normalized.split()) >= 80:
            comparable.append((slug, skill.get("category"), normalized))
    for index, (left, left_category, left_text) in enumerate(comparable):
        for right, right_category, right_text in comparable[index + 1:]:
            if left_category == right_category:
                continue
            ratio = SequenceMatcher(None, left_text, right_text, autojunk=True).ratio()
            if ratio >= 0.9:
                problems.append({"level": "warn", "skill": left, "message": f"high reference similarity {ratio:.2f} with unrelated skill {right}"})

    return problems


def quality_audit() -> dict:
    """Heuristic depth/duplication audit; warnings never gate runtime readiness."""
    warnings: list[dict] = []
    for directory in skill_dirs():
        skill = load_skill(directory.name) or {}
        if skill.get("status") == "deprecated":
            continue
        refs = sorted((directory / "references").glob("*.md")) if (directory / "references").is_dir() else []
        metadata_text = yaml.safe_dump(
            {key: value for key, value in skill.items() if key != "body"},
            sort_keys=True,
        )
        text = (metadata_text + "\n" + skill.get("body", "") + "\n" +
                "\n".join(path.read_text(encoding="utf-8") for path in refs)).lower()
        concepts = {
            "false-positive guidance": r"false positive|false-positive|intended behavior",
            "evidence contract": r"evidence contract|durable evidence|request.response|reproduc|evidence_required|evidence ref|minimal evidence",
            "negative triggers": r"negative.trigger|do not use|when not to use|do not promote|never promote|not a finding|insufficient|reject",
            "stop condition": r"stop condition|stop when|reject when|abort when|deprioritize|stop generaliz",
            "decision tree": r"decision tree|decision path|decision checklist|if .* then|escalat|workflow|trace .*→",
            "tool selection": r"tool selection|ripgrep|semgrep|codeql|broker|playwright|burp|sandbox",
        }
        for concept, pattern in concepts.items():
            if not re.search(pattern, text, re.S):
                warnings.append({"skill": directory.name, "kind": "missing_depth", "message": f"no clear {concept}"})
        technical_terms = set(re.findall(r"[a-z][a-z0-9_-]{3,}", directory.name.replace("-", " ")))
        technical_terms.update(re.findall(
            r"[a-z][a-z0-9_-]{4,}", str(skill.get("description", "")).lower(),
        ))
        generic = {"security", "analysis", "testing", "research", "workflow", "source", "skill", "when", "with", "from", "that", "this", "using"}
        specific = {term for term in technical_terms if term not in generic}
        if specific and sum(1 for term in specific if text.count(term) >= 2) < min(2, len(specific)):
            warnings.append({"skill": directory.name, "kind": "technical_specificity",
                             "message": "limited domain-specific vocabulary beyond metadata"})
        evals = sorted((directory / "evals").glob("*/*.yaml")) if (directory / "evals").is_dir() else []
        if not evals:
            warnings.append({"skill": directory.name, "kind": "fixtures", "message": "no behavioral fixtures"})
        else:
            inputs = []
            for path in evals:
                try:
                    case = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                    inputs.append(re.sub(r"\s+", " ", str(case.get("input", "")).strip().lower()))
                except yaml.YAMLError:
                    continue
            unique = len(set(inputs)); total = len(inputs)
            if total >= 4 and unique / total < 0.6:
                warnings.append({"skill": directory.name, "kind": "fixture_duplication",
                                 "message": f"only {unique}/{total} unique fixture inputs"})
    structural_similarity = [item for item in validate_all() if "similarity" in item.get("message", "")]
    warnings.extend(structural_similarity)
    return {"skill_count": len(skill_dirs()), "warning_count": len(warnings), "warnings": warnings,
            "runtime_gate": False}


__all__ = [
    "REPO_ROOT", "SKILLS_DIR", "MANIFEST",
    "load_manifest", "skill_dirs", "load_skill", "list_skills", "validate_all",
    "iter_hosts", "is_fixture_host",
    "resolve_skill_slug",
    "route_skills", "quality_audit",
    "REQUIRED_MATURE_EVAL_GROUPS",
]
