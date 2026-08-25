"""Secret and sensitive-data redaction.

The harness must never leak secrets (tokens, passwords, cookies, Authorization
headers, required custom secret headers) into logs, checkpoints, evidence
previews, or model-visible metadata.  This module implements a small,
deterministic redaction layer used by the request broker, evidence store,
and logging.
"""

from __future__ import annotations

import re

# Headers whose values should never be persisted to logs/checkpoints/previews.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-bughunt-auth",
    "api-key",
    "x-api-secret",
    "x-access-token",
    "x-refresh-token",
}

# Generic high-entropy token heuristics (kept conservative to avoid over-hiding).
_BEARER_RE = re.compile(r"(bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
_GENERIC_SECRET_RE = re.compile(
    r"(?i)(secret|token|password|passwd|api[-_]?key|apikey|access[-_]?key)"
    r"[\"'=:\s]+([A-Za-z0-9\-._~+/]{12,})"
)

_REDACTED = "[REDACTED]"


def redact_header(name: str, value: str) -> str:
    """Redact a single header value if the header is sensitive."""
    if name.lower() in SENSITIVE_HEADERS:
        return _REDACTED
    return value


def redact_text(text: str) -> str:
    """Best-effort redaction of secrets embedded in free text."""
    if not text:
        return text
    out = _JWT_RE.sub(_REDACTED, text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}", out)
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values redacted by key."""
    return {k: redact_header(k, v) for k, v in headers.items()}


def redact_secret_values(mapping: dict[str, str], secret_marker_keys: set[str]) -> dict[str, str]:
    """Redact any key matching known secret header names (case-insensitive)."""
    lower = {k.lower() for k in secret_marker_keys}
    return {
        k: (_REDACTED if isinstance(v, str) and (k.lower() in lower or k.lower() in SENSITIVE_HEADERS) else v)
        for k, v in mapping.items()
    }


__all__ = [
    "SENSITIVE_HEADERS",
    "redact_header",
    "redact_text",
    "redact_headers",
    "redact_secret_values",
]