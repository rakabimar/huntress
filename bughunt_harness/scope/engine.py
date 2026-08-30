"""Deterministic scope engine.

Resolves an arbitrary target string (URL, bare host, IP, or CIDR) against a
program's include/exclude ScopeSets and returns a structured decision.

Invariants enforced here:
  * exclusion ALWAYS wins over inclusion;
  * ``*.example.com`` matches descendants ``a.example.com`` / ``a.b.example.com``
    but NOT ``example.com`` itself and NOT ``evil-example.com``;
  * an exact domain matches only itself (subdomains need a wildcard or explicit
    entry);
  * URL rules match scheme+host(+port) and a path prefix at segment boundaries.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlparse, urlunparse

from ..engagement.models import ScopeModel, ScopeSet

ALLOWED = "ALLOWED"
BLOCKED = "BLOCKED"


@dataclass
class TargetRef:
    """Normalized view of a requested target."""

    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str = "/"
    is_ip: bool = False
    query: str = ""

    @property
    def netloc(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def normalized(self) -> str:
        if self.scheme is None:
            return self.netloc
        host = f"[{self.host}]" if ":" in self.host and self.is_ip else self.host
        default = (self.scheme == "https" and self.port in (None, 443)) or (
            self.scheme == "http" and self.port in (None, 80)
        )
        netloc = host if default else f"{host}:{self.port}"
        return urlunparse((self.scheme, netloc, self.path, "", self.query, ""))


@dataclass
class ScopeDecision:
    decision: str
    reason: str
    matched_rule: str | None = None
    matched_category: str | None = None
    constraints: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOWED

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "matched_category": self.matched_category,
            "constraints": self.constraints,
        }


def _normalize_host(host: str) -> str:
    raw = (host or "").strip().rstrip(".").lower()
    if not raw:
        return raw
    try:
        return raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized host: {host!r}") from exc


_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_ENCODED_SLASH = re.compile(r"%(2f|5c|00)", re.IGNORECASE)


def _normalize_path(path: str) -> str:
    raw = path or "/"
    if _BAD_PERCENT.search(raw):
        raise ValueError("path contains invalid percent encoding")
    if _ENCODED_SLASH.search(raw):
        raise ValueError("encoded slash/backslash/NUL in path is ambiguous")
    decoded = unquote(raw)
    if re.search(r"%[0-9a-fA-F]{2}", decoded):
        raise ValueError("multiply encoded path is ambiguous")
    if "\\" in decoded or any(ord(ch) < 32 for ch in decoded):
        raise ValueError("path contains an ambiguous separator/control character")
    if "//" in decoded:
        raise ValueError("repeated path separators are ambiguous")
    trailing = decoded.endswith("/")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if trailing and normalized != "/":
        normalized += "/"
    # Preserve ordinary URL escaping while ensuring dot-segment comparison is
    # performed on the decoded semantic path.
    return quote(normalized, safe="/:@!$&'()*+,;=-._~")


def parse_target(target: str) -> TargetRef:
    """Parse a target into a normalized TargetRef, tolerating URLs and hosts."""
    raw = target.strip()
    if not raw:
        raise ValueError("empty target")

    if "://" in raw:
        p = urlparse(raw)
        scheme = (p.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError("only absolute http(s) targets are supported")
        if p.username is not None or p.password is not None or "@" in p.netloc.rsplit("]", 1)[-1]:
            raise ValueError("URL userinfo is forbidden")
        host = _normalize_host(p.hostname or "")
        try:
            port = p.port
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        if port == (443 if scheme == "https" else 80):
            port = None
        elif port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid URL port")
        path = _normalize_path(p.path or "/")
        query = p.query
    else:
        scheme = None
        # Bare host, possible ":port" suffix, no path.
        host_port = raw
        port = None
        if host_port.count(":") == 1:
            maybe_host, maybe_port = host_port.rsplit(":", 1)
            if maybe_port.isdigit():
                host_port, port = maybe_host, int(maybe_port)
                if not 1 <= port <= 65535:
                    raise ValueError("invalid target port")
        host = _normalize_host(host_port)
        path = "/"
        query = ""
        if any(ch in raw for ch in ("/", "?", "#", "@")):
            raise ValueError("bare targets may contain only a host and optional port")

    if not host:
        raise ValueError(f"could not extract a host from target: {target!r}")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    return TargetRef(
        raw=raw, scheme=scheme, host=host, port=port, path=path,
        is_ip=is_ip, query=query,
    )


def _host_matches_wildcard(host: str, wildcard: str) -> bool:
    """``*.example.com`` matches sub.dom.example.com but not example.com."""
    w = _normalize_host(wildcard)
    if not w.startswith("*."):
        return False
    suffix = w[2:]
    if not suffix:
        return False
    # host must equal-a-subdomain-of suffix: endswith ".suffix".
    return host.endswith("." + suffix) and host != suffix


def _path_prefix_match(target_path: str, rule_path: str) -> bool:
    """True if target_path is rule_path or a descendant path (segment boundary)."""
    tp = target_path.rstrip("/") or "/"
    rp = rule_path.rstrip("/") or "/"
    if rp == "/":
        return True
    if tp == rp:
        return True
    return tp.startswith(rp + "/")


class ScopeEngine:
    def __init__(self, scope: ScopeModel) -> None:
        self.scope = scope

    # -- helpers ----------------------------------------------------------
    def _host_in_ruleset(self, host: str, ruleset: ScopeSet) -> str | None:
        """Return the matching selector string, or None."""
        for d in ruleset.domains:
            if _normalize_host(d) == host:
                return d
        for d in ruleset.subdomains:
            if _normalize_host(d) == host:
                return d
        for w in ruleset.wildcards:
            if _host_matches_wildcard(host, w):
                return w
        return None

    def _url_in_ruleset(self, ref: TargetRef, ruleset: ScopeSet) -> str | None:
        if ref.scheme is None:
            return None
        entries = list(ruleset.urls) + list(ruleset.path_urls)
        for entry in entries:
            try:
                rule = parse_target(entry)
            except ValueError:
                continue
            if rule.scheme != ref.scheme:
                continue
            if rule.host != ref.host:
                continue
            # Compare effective ports, treating missing as default.
            ref_port = ref.port if ref.port else (443 if ref.scheme == "https" else 80)
            rule_port = rule.port if rule.port else (443 if ref.scheme == "https" else 80)
            if ref_port != rule_port:
                continue
            rule_path = rule.path or "/"
            if _path_prefix_match(ref.path, rule_path):
                return entry
        return None

    def _ip_in_ruleset(self, ref: TargetRef, ruleset: ScopeSet) -> str | None:
        try:
            ip = ipaddress.ip_address(ref.host)
        except ValueError:
            return None
        for e in ruleset.ipv4:
            try:
                if ipaddress.ip_address(e.strip()) == ip:
                    return e
            except ValueError:
                continue
        for c in ruleset.cidr:
            try:
                if ip in ipaddress.ip_network(c.strip(), strict=False):
                    return c
            except ValueError:
                continue
        return None

    def _matches(self, ref: TargetRef, ruleset: ScopeSet) -> tuple[str | None, str | None]:
        """Return (selector, category) if ref matches ruleset, else (None, None)."""
        if ref.is_ip:
            hit = self._ip_in_ruleset(ref, ruleset)
            if hit is not None:
                return hit, "ip"
            return None, None

        # Host-based rules (domain/wildcard/subdomain).
        hit = self._host_in_ruleset(ref.host, ruleset)
        if hit is not None:
            return hit, "host"

        # URL-based rules (only meaningful when a scheme is present).
        hit = self._url_in_ruleset(ref, ruleset)
        if hit is not None:
            return hit, "url"

        return None, None

    # -- public API -------------------------------------------------------
    def check(self, target: str) -> ScopeDecision:
        try:
            ref = parse_target(target)
        except ValueError as exc:
            return ScopeDecision(
                decision=BLOCKED,
                reason=f"ambiguous_or_invalid_target: {exc}",
            )

        # 1. Exclusion always wins.
        ex_sel, ex_cat = self._matches(ref, self.scope.exclude)
        if ex_sel is not None:
            return ScopeDecision(
                decision=BLOCKED,
                reason=f"explicit_out_of_scope (matched exclude rule {ex_sel!r})",
                matched_rule=ex_sel,
                matched_category=ex_cat,
            )

        # 2. Inclusion.
        in_sel, in_cat = self._matches(ref, self.scope.include)
        if in_sel is not None:
            return ScopeDecision(
                decision=ALLOWED,
                reason=f"matched include rule {in_sel!r} ({in_cat})",
                matched_rule=in_sel,
                matched_category=in_cat,
            )

        return ScopeDecision(
            decision=BLOCKED,
            reason="target not in scope (no include rule matched)",
            matched_rule=None,
            matched_category=None,
        )


def normalize_target(target: str) -> str:
    """Canonical target identity for approvals, evidence, and redirect checks."""
    return parse_target(target).normalized


__all__ = [
    "ALLOWED", "BLOCKED", "TargetRef", "ScopeDecision", "ScopeEngine",
    "parse_target", "normalize_target",
]
