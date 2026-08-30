"""Deterministic skill evaluation (spec §17 eval fixtures).

A lightweight, structural eval: does the skill parse, carry all required
sections, reference a valid risk class, and confine examples to fixture hosts?
This is not a quality LLM-judge; it is the reproducible floor every skill must
clear before being marked ``stable`` / ``verified``.
"""

from __future__ import annotations

import yaml

from .registry import (
    REQUIRED_SECTIONS,
    VALID_RISK,
    REQUIRED_MATURE_EVAL_GROUPS,
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
    eval_root = skill_dirs()[0].parent / slug / "evals" if skill_dirs() else None
    if eval_root and eval_root.is_dir():
        if skill["maturity"] == "stable" and skill["category"] != "core":
            groups = sorted(REQUIRED_MATURE_EVAL_GROUPS)
        else:
            groups = sorted(p.name for p in eval_root.iterdir() if p.is_dir())
        for group in groups:
            files = sorted((eval_root / group).glob("*.yaml")) if (eval_root / group).is_dir() else []
            group_ok = bool(files)
            detail = f"{len(files)} case(s)"
            for path in files:
                try:
                    case = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                    expected = case.get("expected", {})
                    if group in {"positive", "routing"}:
                        route = expected.get("route") or expected.get("selected_skill")
                        group_ok = group_ok and route == slug
                    elif group in {"negative", "false-positive"}:
                        group_ok = group_ok and expected.get("promote_finding") is False
                    elif group == "evidence":
                        group_ok = group_ok and expected.get("evidence_required") is True
                    elif group == "tool-selection":
                        group_ok = group_ok and bool(expected.get("tool_selection"))
                    elif group == "complex-scenario":
                        route = expected.get("route") or expected.get("selected_skill")
                        group_ok = group_ok and route == slug
                        group_ok = group_ok and bool(expected.get("hypothesis"))
                        group_ok = group_ok and bool(expected.get("refuting_observation"))
                    elif group == "safety":
                        group_ok = group_ok and expected.get("mode") == "DENY"
                        group_ok = group_ok and expected.get("external_request") is False
                except Exception:
                    group_ok = False
            checks.append({"name": f"eval_{group}", "ok": group_ok, "detail": detail})
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
