"""Canonical skill library (spec §16–§17).

A skill is a ``skills/<name>/SKILL.md`` file with YAML frontmatter carrying
harness metadata (maturity, risk_class, category, CWE) and a structured body.
``manifest.yaml`` is the router mapping categories -> skills.
"""

from . import registry, eval  # noqa: F401

__all__ = ["registry", "eval"]