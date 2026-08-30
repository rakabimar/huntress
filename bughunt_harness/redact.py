"""Secret and sensitive-data redaction.

The harness must never leak secrets (tokens, passwords, cookies, Authorization
headers, required custom secret headers) into logs, checkpoints, evidence
previews, or model-visible metadata.  This module implements a small,
deterministic redaction layer used by the request broker, evidence store,
and logging.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
_SENSITIVE_QUERY_NAMES = {
    "access_token", "refresh_token", "token", "id_token", "api_key", "apikey",
    "key", "secret", "password", "passwd", "code", "session", "session_id",
}


def redact_header(name: str, value: str, sensitive_names: set[str] | None = None) -> str:
    """Redact a single header value if the header is sensitive."""
    dynamic = {n.lower() for n in (sensitive_names or set())}
    if name.lower() in SENSITIVE_HEADERS or name.lower() in dynamic:
        return _REDACTED
    return value


def redact_text(
    text: str, *, secret_values: list[str] | None = None,
    secret_patterns: list[str] | None = None,
) -> str:
    """Best-effort redaction of secrets embedded in free text."""
    if not text:
        return text
    out = _JWT_RE.sub(_REDACTED, text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}", out)
    out = _GENERIC_SECRET_RE.sub(lambda m: m.group(0).replace(m.group(2), _REDACTED), out)
    for value in sorted((v for v in (secret_values or []) if v), key=len, reverse=True):
        out = out.replace(value, _REDACTED)
    for pattern in secret_patterns or []:
        try:
            out = re.sub(pattern, _REDACTED, out)
        except re.error:
            continue
    return out


def redact_headers(
    headers: dict[str, str], sensitive_names: set[str] | None = None,
) -> dict[str, str]:
    """Return a copy of headers with sensitive values redacted by key."""
    return {k: redact_header(k, v, sensitive_names) for k, v in headers.items()}


def redact_url(url: str, *, secret_values: list[str] | None = None) -> str:
    """Redact secret-bearing query values while retaining request shape."""
    try:
        parts = urlsplit(url)
        query = []
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            normalized = name.lower().replace("-", "_")
            if normalized in _SENSITIVE_QUERY_NAMES or any(
                marker in normalized for marker in ("token", "secret", "password", "credential")
            ):
                value = _REDACTED
            else:
                value = redact_text(value, secret_values=secret_values)
            query.append((name, value))
        safe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    except ValueError:
        safe = url
    return redact_text(safe, secret_values=secret_values)


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
    "redact_url",
    "redact_secret_values",
]
