"""Controlled request broker — the ONLY sanctioned external HTTP path.

Every request flows through: scope check -> policy gate -> rate-limit ->
header/secret resolution -> (optional) Burp proxy -> execution -> redaction ->
evidence persistence -> agent-action log.  Arbitrary unrestricted target
execution is never exposed through this module.
"""

from __future__ import annotations

import hashlib
import json as _json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from ..config import get_config
from ..engagement.models import Engagement
from ..errors import NetworkSafetyError
from ..policy.engine import ALLOW, APPROVAL_REQUIRED, DENY, PolicyEngine
from ..redact import redact_headers, redact_text
from ..scope.engine import ScopeEngine
from ..secrets.manager import SecretManager
from ..state.db import HuntDB
from .ratelimit import SharedRateLimiter

DEFAULT_TIMEOUT = 30
MAX_PREVIEW = 800


def request_params_hash(method: str, target: str, body: str | None, json_body: Any | None, params: dict[str, str] | None) -> str:
    """Stable SHA-256 of the request identity (not secrets) used to scope an
    approval to the exact request it was granted for."""
    payload = _json.dumps(
        {"method": method, "target": target, "body": body, "json": json_body, "params": params},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class HostRateLimiter:
    """Process-local per-host minimum-spacing limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def throttle(self, host: str, max_rps: float) -> None:
        if max_rps <= 0:
            raise NetworkSafetyError("max_rps must be > 0")
        interval = 1.0 / max_rps
        with self._lock:
            now = time.time()
            last = self._last.get(host)
            if last is not None:
                wait = interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
            self._last[host] = time.time()


@dataclass
class BrokerResult:
    ok: bool
    decision: str
    reason: str
    method: str = ""
    url: str = ""
    status_code: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    body_length: int = 0
    evidence_id: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "decision": self.decision,
            "reason": self.reason,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "body_preview": self.body_preview,
            "body_length": self.body_length,
            "evidence_id": self.evidence_id,
            "error": self.error,
        }


class RequestBroker:
    def __init__(
        self,
        engagement: Engagement,
        *,
        program_slug: str,
        workspace: Path,
        hunt_db: HuntDB | None = None,
        secrets: SecretManager | None = None,
        program_status: str = "active",
    ) -> None:
        self.engagement = engagement
        self.program_slug = program_slug
        self.program_status = program_status
        self.workspace = Path(workspace)
        self.scope = ScopeEngine(engagement.scope)
        self.policy = PolicyEngine(engagement.scope, engagement.roe)
        self.secrets = secrets or SecretManager(program_slug)
        self.db = hunt_db or HuntDB(self.workspace / "state" / "hunt.db", program_slug=program_slug)
        # Cross-process limiter over the shared hunt.db (P0.6: max_rps + max_concurrency).
        self.limiter = SharedRateLimiter(self.db.db_path, program_slug)
        self.config = get_config()

    @property
    def active(self) -> bool:
        return self.program_status == "active"

    # -- secret-safe header resolution ------------------------------------
    def _resolve_headers(self, user_headers: dict[str, str] | None) -> dict[str, str]:
        """Resolve required + secret headers.  Header matching is
        case-insensitive per the HTTP spec and the harness contract (P0.10)."""
        headers: dict[str, str] = dict(user_headers or {})
        lower = {k.lower(): v for k, v in headers.items()}
        by_name = self.engagement.headers.by_name()  # lowercased name -> HeaderModel

        # Required headers (from ROE) must be present & resolvable.
        for name in self.engagement.roe.required_headers:
            hdr = by_name.get(name.lower())
            if hdr is None:
                raise NetworkSafetyError(f"required header {name!r} has no metadata entry in headers.yaml")
            if hdr.value_ref and name.lower() not in lower:
                resolved = self.secrets.resolve(hdr.value_ref) or ""
                headers[hdr.name] = resolved
                lower[hdr.name.lower()] = resolved
            if hdr.mandatory and name.lower() not in lower:
                raise NetworkSafetyError(f"mandatory header {name!r} is missing and has no reference")

        # Resolve any header explicitly marked secret.
        for name, hdr in by_name.items():
            if hdr.secret and hdr.value_ref and name not in lower:
                resolved = self.secrets.resolve(hdr.value_ref) or ""
                headers[hdr.name] = resolved
                lower[name] = resolved
        return headers

    # -- persisting evidence ----------------------------------------------
    def _persist_evidence(
        self,
        method: str,
        url: str,
        req_headers: dict[str, str],
        resp_status: int | None,
        resp_headers: dict[str, str],
        body: str,
    ) -> str | None:
        try:
            rec = self.db.add_evidence(
                kind="request_response",
                ref=f"{method} {url}",
                description=f"broker {method} request to {url}",
                preview=body[:MAX_PREVIEW],
            )
            ev_dir = self.workspace / "evidence"
            ev_dir.mkdir(parents=True, exist_ok=True)
            # Redacted copies only — never persist raw secret headers.
            raw = (
                f"{method} {url}\n\n"
                + "".join(f"{k}: {v}\n" for k, v in redact_headers(req_headers).items())
                + "\n--- RESPONSE ---\n"
                + f"status: {resp_status}\n"
                + "".join(f"{k}: {v}\n" for k, v in redact_headers(resp_headers).items())
                + "\n" + redact_text(body[:20000])
            )
            (ev_dir / f"{rec.public_id}.txt").write_text(raw, encoding="utf-8")
            return rec.public_id
        except Exception:
            return None

    # -- main entry -------------------------------------------------------
    def execute(
        self,
        *,
        target: str,
        method: str = "GET",
        action: str = "read_http",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        json_body: Any | None = None,
        params: dict[str, str] | None = None,
        agent_role: str = "orchestrator",
        session_id: int | None = None,
        auth_context: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        allow_redirects: bool = False,
        verify: bool = True,
    ) -> BrokerResult:
        method = method.upper()

        # 0. Program lifecycle gate (P0.4): live actions require status=active.
        if not self.active:
            self._log(agent_role, action, target, DENY, f"program_status={self.program_status}", session_id)
            return BrokerResult(
                ok=False, decision=DENY,
                reason=f"program is {self.program_status!r}; live actions require 'active'",
                method=method, url=target,
            )

        # 1. Scope.
        scope = self.scope.check(target)
        if not scope.allowed:
            self._log(agent_role, action, target, DENY, "out_of_scope", session_id)
            return BrokerResult(ok=False, decision=DENY, reason=f"out_of_scope: {scope.reason}", method=method, url=target)

        # 2. Policy.
        pol = self.policy.check(action, target)
        if pol.decision == DENY:
            self._log(agent_role, action, target, DENY, pol.reason, session_id)
            return BrokerResult(ok=False, decision=DENY, reason=pol.reason, method=method, url=target)
        if pol.decision == APPROVAL_REQUIRED:
            # A valid (unexpired, unconsumed) human approval authorizes exactly one
            # request; anything else records a pending approval for the human.
            ph = request_params_hash(method, target, body, json_body, params)
            existing = self.db.find_valid_approval(
                action, target=target, program=self.program_slug, method=method, params_hash=ph,
            )
            if existing is not None:
                self.db.consume_approval(existing.id)
                # fall through to execution (drop the approval_required short-circuit)
            else:
                self.db.request_approval(
                    action, target, requested_by=agent_role, note=pol.reason,
                    program=self.program_slug, method=method, params_hash=ph, session_id=session_id,
                )
                self._log(agent_role, action, target, APPROVAL_REQUIRED, pol.reason, session_id)
                return BrokerResult(ok=False, decision=APPROVAL_REQUIRED, reason=pol.reason, method=method, url=target)

        # 3. Headers + secrets.
        try:
            req_headers = self._resolve_headers(headers)
        except NetworkSafetyError as exc:
            self._log(agent_role, action, target, DENY, str(exc), session_id)
            return BrokerResult(ok=False, decision=DENY, reason=str(exc), method=method, url=target)

        # 4. Rate limit (keyed by host) — cross-process max_rps + max_concurrency.
        host = scope_target_host(target)
        try:
            self.limiter.acquire(host, self.engagement.roe.max_rps, self.engagement.roe.max_concurrency)
        except NetworkSafetyError as exc:
            self._log(agent_role, action, target, DENY, str(exc), session_id)
            return BrokerResult(ok=False, decision=DENY, reason=str(exc), method=method, url=target)

        try:
            # 5. Burp proxy routing.
            proxies = None
            if self.config.burp_proxy:
                proxies = {"http": self.config.burp_proxy, "https": self.config.burp_proxy}

            # 6. Execute.
            try:
                resp = requests.request(
                    method,
                    target,
                    headers=req_headers,
                    data=body,
                    json=json_body,
                    params=params,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    verify=verify,
                    proxies=proxies,
                )
            except Exception as exc:  # noqa: BLE001 - report network errors safely
                self._log(agent_role, action, target, ALLOW, f"error: {type(exc).__name__}", session_id)
                return BrokerResult(
                    ok=False, decision=ALLOW, reason="request_error", method=method, url=target,
                    error=f"{type(exc).__name__}: {exc}", request_headers=redact_headers(req_headers),
                )

            # 7. Redact + capture.
            r_headers = redact_headers(dict(resp.headers))
            try:
                text_body = resp.text
            except Exception:
                text_body = ""
            body_preview = redact_text(text_body[:MAX_PREVIEW])
            body_length = len(resp.content)

            # 8. Persist evidence.
            evidence_id = self._persist_evidence(method, target, req_headers, resp.status_code, dict(resp.headers), text_body)

            # 9. Log action (no secrets).
            summary = f"HTTP {resp.status_code} len={body_length}"
            self._log(agent_role, action, target, ALLOW, summary, session_id)

            # 10. Structured request record (metadata only — no raw bodies/secrets).
            try:
                self.db.record_request(
                    program=self.program_slug, method=method, url=target,
                    session_id=session_id, auth_context=auth_context or "",
                    request_metadata={"headers_count": len(req_headers), "host": host},
                    response_metadata={"status": resp.status_code, "length": body_length},
                    evidence_ref=evidence_id or "",
                    body_hash=hashlib.sha256((body or "").encode("utf-8")).hexdigest() if body else "",
                )
            except Exception:
                pass

            return BrokerResult(
                ok=True,
                decision=ALLOW,
                reason="allowed",
                method=method,
                url=target,
                status_code=resp.status_code,
                request_headers=redact_headers(req_headers),
                response_headers=r_headers,
                body_preview=body_preview,
                body_length=body_length,
                evidence_id=evidence_id,
            )
        finally:
            # Always release the reserved concurrency slot, even on error.
            self.limiter.release(host)

    def _log(self, agent_role: str, action: str, target: str, decision: str, summary: str, session_id: int | None) -> None:
        try:
            self.db.record_action(
                agent_role=agent_role,
                action=action,
                program=self.program_slug,
                target=target,
                decision=decision,
                result_summary=summary,
                session_id=session_id,
            )
        except Exception:
            pass


def scope_target_host(target: str) -> str:
    """Extract a rate-limit key (host) from a target without importing scope parser."""
    host = target.split("://")[-1].split("/")[0]
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host.lower()


__all__ = ["BrokerResult", "RequestBroker", "HostRateLimiter", "scope_target_host", "request_params_hash"]