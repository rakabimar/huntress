"""CVSS scoring engine (v4.0 + v3.1)."""

from .engine import CVSSResult, severity_from_score, score_vector, validate_vector

__all__ = ["CVSSResult", "severity_from_score", "score_vector", "validate_vector"]