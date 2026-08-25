"""Deterministic scope engine for a program's target selectors."""

from .engine import ALLOWED, BLOCKED, ScopeDecision, ScopeEngine, TargetRef, parse_target

__all__ = ["ALLOWED", "BLOCKED", "ScopeDecision", "ScopeEngine", "TargetRef", "parse_target"]