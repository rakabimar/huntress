"""Deterministic skill evaluation (spec §17 eval fixtures).

A lightweight, structural eval: does the skill parse, carry all required
sections, reference a valid risk class, and confine examples to fixture hosts?
This is not a quality LLM-judge; it is the reproducible floor every skill must
clear before being marked ``stable`` / ``verified``.
"""

from __future__ import annotations

from .registry import (
    REQUIRED_SECTIONS,
    VALID_RISK,
    is_fixture_host,
    iter_hosts,
    load_skill,
    skill_dirs,
)


def evaluate_skill(slug: str) -> dict:
    skill = load_skill(slug)
    if skill is None:
        return {"slug": slug, "present": False, "checks": [], "passed": False}
    checks = [
        {"name": "parse", "ok": True, "detail": "frontmatter parsed"},
        {"name": "description", "ok": bool(skill["description"]), "detail": skill["description"][:80]},
        {"name": "risk_class", "ok": skill["risk_class"] in VALID_RISK, "detail": skill["risk_class"]},
        {"name": "sections", "ok": all(f"## {s}" in skill["body"] for s in REQUIRED_SECTIONS), "detail": ", ".join(REQUIRED_SECTIONS)},
        {
            "name": "fixture_hosts",
            "ok": all(is_fixture_host(h) for h in iter_hosts(skill["body"])),
            "detail": "examples use example.test/localhost only",
        },
    ]
    passed = all(c["ok"] for c in checks)
    return {"slug": slug, "present": True, "checks": checks, "passed": passed}


def run_eval(name: str | None = None) -> dict:
    slugs = [name] if name else [d.name for d in skill_dirs()]
    results = [evaluate_skill(s) for s in slugs]
    passed = sum(1 for r in results if r["passed"])
    return {
        "skill_count": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }


__all__ = ["evaluate_skill", "run_eval"]