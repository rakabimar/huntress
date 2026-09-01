"""Controlled active HTTP execution plane.

Every hop is independently gated by program status, normalized scope, action
policy, autonomy budget, bounded approval, shared rate/concurrency leases,
auth-context injection, redirect safety, and secret-safe evidence capture.
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from ..config import get_config
from ..engagement.models import AccountModel, Engagement
from ..errors import NetworkSafetyError, SecretError, StateError
from ..policy.engine import ALLOW, APPROVAL_REQUIRED, DENY, PolicyEngine
from ..redact import redact_headers, redact_text, redact_url
from ..scope.engine import ScopeEngine, normalize_target, parse_target
from ..secrets.manager import SecretManager
from ..state.db import HuntDB
from ..timeutil import utcnow
from .ratelimit import SharedRateLimiter

DEFAULT_TIMEOUT = 30
MAX_PREVIEW = 1200
MAX_EVIDENCE_BODY = 20000
REDIRECT_CODES = {301, 302, 303, 307, 308}


def request_params_hash(
    method: str, target: str, body: str | None, json_body: Any | None,
    params: dict[str, str] | None, controlled_mutation: dict | None = None,
) -> str:
    payload = json.dumps(
        {
            "method": method.upper(), "target": normalize_target(target),
            "body_hash": hashlib.sha256((body or "").encode()).hexdigest(),
            "json_hash": hashlib.sha256(
                json.dumps(json_body, sort_keys=True, default=str).encode()
            ).hexdigest() if json_body is not None else "",
            "params": params or {}, "mutation": controlled_mutation or {},
        },
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class HostRateLimiter:
    """Legacy process-local helper retained for API compatibility."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def throttle(self, host: str, max_rps: float) -> None:
        if max_rps <= 0:
            raise NetworkSafetyError("max_rps must be > 0")
        with self._lock:
            interval = 1.0 / max_rps
            wait = interval - (time.time() - self._last.get(host, 0.0))
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.time()


@dataclass
class AuthResolution:
    context_id: str = ""
    account_id: str = ""
    role: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    sensitive_names: set[str] = field(default_factory=set)
    secret_values: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


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
    request_id: str | None = None
    auth_context: str = ""
    account_role: str = ""
    redirect_chain: list[dict] = field(default_factory=list)
    proxy: str | None = None
    error: str | None = None
    session_secret_refs: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "decision": self.decision, "reason": self.reason,
            "mode": {ALLOW: "AUTO", APPROVAL_REQUIRED: "ASK", DENY: "DENY"}.get(
                self.decision, self.decision.upper(),
            ),
            "method": self.method, "url": self.url, "status_code": self.status_code,
            "request_headers": self.request_headers, "response_headers": self.response_headers,
            "body_preview": self.body_preview, "body_length": self.body_length,
            "evidence_id": self.evidence_id, "request_id": self.request_id,
            "auth_context": self.auth_context, "account_role": self.account_role,
            "redirect_chain": self.redirect_chain, "proxy": self.proxy, "error": self.error,
            "session_secret_refs": self.session_secret_refs,
        }


def _tcp_open(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detected_burp_proxy(config=None) -> str | None:
    """Return only an explicitly configured Burp proxy.

    A listening conventional port is useful diagnostic evidence, but cannot
    identify the process and therefore must never enable interception.
    """
    cfg = config or get_config()
    if cfg.burp_proxy in {"disabled", "off", "none"}:
        return None
    return cfg.burp_proxy or None


def burp_proxy_status(config=None, *, proxy_url: str | None = None) -> dict:
    """Report configured/reachable/verified separately from an 8080 candidate."""
    cfg = config or get_config()
    configured_url = proxy_url if proxy_url is not None else detected_burp_proxy(cfg)
    candidate = _tcp_open("127.0.0.1", 8080)
    result = {
        "configured": bool(configured_url), "proxy_url": configured_url,
        "reachable": False, "verified": False,
        "candidate_8080": candidate, "source": "explicit" if configured_url else "disabled",
        "error": "",
    }
    if not configured_url:
        return result
    parsed = urlparse(configured_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.port:
        result["error"] = "proxy URL must be http(s)://host:port"
        return result
    result["reachable"] = _tcp_open(parsed.hostname, parsed.port, timeout=1.0)
    # Explicit configuration is the identity assertion. Reachability proves
    # only that the configured endpoint can be contacted; a random open 8080
    # never reaches this state.
    result["verified"] = bool(result["reachable"])
    return result


def validate_ca_bundle(value: str | Path | None) -> tuple[str | None, str]:
    """Resolve and minimally validate a PEM CA bundle without changing trust stores."""
    if not value:
        return None, "not_configured"
    path = Path(value).expanduser()
    if not path.exists():
        return None, "file_missing"
    if not path.is_file():
        return None, "not_a_file"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, "not_readable"
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    if begin not in text or end not in text:
        return None, "invalid_pem"
    try:
        first = text[text.index(begin): text.index(end) + len(end)]
        ssl.PEM_cert_to_DER_cert(first)
    except (ValueError, ssl.SSLError):
        return None, "invalid_certificate"
    return str(path.resolve()), "valid"


class RequestBroker:
    def __init__(
        self, engagement: Engagement, *, program_slug: str, workspace: Path,
        hunt_db: HuntDB | None = None, secrets: SecretManager | None = None,
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
        self.limiter = SharedRateLimiter(self.db.db_path, program_slug)
        self.config = get_config()

    def _burp_settings(self) -> tuple[str | None, str | None, bool]:
        program = self.engagement.integrations.burp
        proxy = program.proxy_url or detected_burp_proxy(self.config)
        ca = program.ca_bundle or self.config.burp_ca
        return proxy, ca, bool(program.https_interception)

    @property
    def active(self) -> bool:
        return self.program_status == "active"

    def _account(self, account_id: str) -> AccountModel | None:
        return self.engagement.accounts.by_id().get(account_id)

    def _resolve_auth_context(self, requested: str) -> AuthResolution:
        if not requested:
            return AuthResolution()
        record = None
        if requested.upper().startswith("AUTH-"):
            try:
                record = self.db.get_auth_context(int(requested.split("-", 1)[1]))
            except (ValueError, StateError) as exc:
                raise NetworkSafetyError(f"unknown auth context {requested!r}") from exc
        else:
            record = self.db.get_auth_context_by_account(requested)
        account_id = record.account_id if record else requested
        account = self._account(account_id)
        if account is None or not account.enabled:
            raise NetworkSafetyError(f"auth context account {account_id!r} is missing or disabled")
        if record and not record.enabled:
            raise NetworkSafetyError(f"auth context {record.public_id} is disabled")

        configured_refs = set(account.auth.secret_refs() if account.auth else [])
        if account.secret_ref:
            configured_refs.add(account.secret_ref)
        if record:
            if account.auth and record.type != account.auth.type:
                raise NetworkSafetyError(
                    f"auth context {record.public_id} type differs from trusted account configuration"
                )
            if not set(record.secret_refs).issubset(configured_refs):
                raise NetworkSafetyError(
                    f"auth context {record.public_id} contains an unconfigured secret reference"
                )

        auth_type = record.type if record else (account.auth.type if account.auth else "")
        refs = list(record.secret_refs) if record else []
        metadata = dict(record.metadata) if record else {}
        if account.auth:
            metadata = {**account.auth.metadata, **metadata}
            if not refs:
                refs = account.auth.secret_refs()
        if not refs and account.secret_ref:
            refs = [account.secret_ref]
        if not auth_type:
            raise NetworkSafetyError(
                f"account {account_id!r} has no auth type; configure account.auth or an AuthContext"
            )

        out = AuthResolution(
            context_id=record.public_id if record else account_id,
            account_id=account_id, role=record.role if record and record.role else account.role,
            metadata=metadata,
        )

        def resolve(ref: str | None) -> str:
            if not ref:
                raise NetworkSafetyError(f"auth context {out.context_id!r} is missing a secret reference")
            try:
                value = self.secrets.resolve(ref)
            except SecretError as exc:
                raise NetworkSafetyError(f"auth context {out.context_id!r} is not resolvable: {exc}") from exc
            if not value:
                raise NetworkSafetyError(f"auth context {out.context_id!r} resolved an empty credential")
            out.secret_values.append(value)
            return value

        if auth_type == "bearer":
            ref = account.auth.bearer_ref if account.auth and account.auth.bearer_ref else (refs[0] if refs else None)
            out.headers["Authorization"] = "Bearer " + resolve(str(ref) if ref else None)
            out.sensitive_names.add("authorization")
        elif auth_type == "cookie":
            ref = account.auth.cookie_ref if account.auth and account.auth.cookie_ref else (refs[0] if refs else None)
            out.headers["Cookie"] = resolve(str(ref) if ref else None)
            out.sensitive_names.add("cookie")
        elif auth_type == "header_bundle":
            configured = dict(account.auth.headers) if account.auth and account.auth.headers else {}
            configured.update(metadata.get("headers", {}))
            if not configured and refs and metadata.get("header_names"):
                configured = dict(zip(metadata["header_names"], refs))
            if not configured:
                raise NetworkSafetyError("header_bundle requires metadata.headers or account.auth.headers")
            for name, ref in configured.items():
                out.headers[str(name)] = resolve(str(ref))
                out.sensitive_names.add(str(name).lower())
        elif auth_type == "browser_session":
            cookie_ref = metadata.get("cookie_ref")
            if not cookie_ref and account.auth:
                cookie_ref = account.auth.cookie_ref
            if not cookie_ref:
                raise NetworkSafetyError(
                    "browser_session has no broker cookie_ref; use its isolated Playwright context"
                )
            out.headers["Cookie"] = resolve(str(cookie_ref))
            out.sensitive_names.add("cookie")
        else:
            raise NetworkSafetyError(f"unsupported auth context type {auth_type!r}")
        return out

    def _resolve_headers(
        self, user_headers: dict[str, str] | None, auth: AuthResolution,
    ) -> tuple[dict[str, str], set[str], list[str]]:
        headers = dict(user_headers or {})
        # AuthContext is authoritative for credential headers.
        for name, value in auth.headers.items():
            for existing in list(headers):
                if existing.lower() == name.lower():
                    del headers[existing]
            headers[name] = value
        lower = {k.lower(): v for k, v in headers.items()}
        by_name = self.engagement.headers.by_name()
        sensitive = set(auth.sensitive_names)
        values = list(auth.secret_values)
        for name, model in by_name.items():
            if model.secret:
                sensitive.add(name)
            if model.value is not None and name not in lower:
                headers[model.name] = model.value
                lower[name] = model.value
            if model.value_ref and name not in lower:
                try:
                    value = self.secrets.resolve(model.value_ref) or ""
                except SecretError as exc:
                    if model.mandatory or model.name in self.engagement.roe.required_headers:
                        raise NetworkSafetyError(f"required header {model.name!r} is not resolvable: {exc}") from exc
                    continue
                headers[model.name] = value
                lower[name] = value
                if model.secret:
                    values.append(value)
        for required in self.engagement.roe.required_headers:
            model = by_name.get(required.lower())
            if model is None:
                raise NetworkSafetyError(f"required header {required!r} has no headers.yaml metadata")
            if required.lower() not in {k.lower() for k in headers}:
                raise NetworkSafetyError(f"mandatory header {required!r} is missing")
        for header_name, header_value in headers.items():
            if header_name.lower() in sensitive and header_value not in values:
                values.append(header_value)
        return headers, sensitive, values

    def _budget_gate(self, session_id: int | None, hypothesis_id: int | None) -> str | None:
        run = self.db.active_autonomy_run(session_id) if session_id is not None else None
        if run is None:
            return None
        records = self.db.list_request_records(session_id)
        if len(records) >= int(run.budget.get("max_total_requests", 1000)):
            return "autonomy budget exhausted: max_total_requests"
        if hypothesis_id is not None:
            used = sum(1 for r in records if r.hypothesis_id == hypothesis_id)
            if used >= int(run.budget.get("max_requests_per_hypothesis", 30)):
                return "autonomy budget exhausted: max_requests_per_hypothesis"
        return None

    def _persist_evidence(
        self, *, method: str, url: str, request_headers: dict[str, str],
        request_body: Any, response_status: int, response_headers: dict[str, str],
        response_body: str, auth: AuthResolution, sensitive_names: set[str],
        secret_values: list[str], secret_patterns: list[str], controlled_mutation: dict | None,
        baseline_evidence_id: str, redirect_chain: list[dict], burp_ref: str,
    ) -> str:
        url = redact_url(url, secret_values=secret_values)
        redirect_chain = [
            {
                **hop,
                **{
                    key: redact_url(str(hop[key]), secret_values=secret_values)
                    for key in ("from", "to") if hop.get(key)
                },
            }
            for hop in redirect_chain
        ]
        safe_req_headers = redact_headers(request_headers, sensitive_names)
        safe_resp_headers = redact_headers(response_headers, sensitive_names)
        if isinstance(request_body, (dict, list)):
            req_text = json.dumps(request_body, sort_keys=True, default=str)
        else:
            req_text = str(request_body or "")
        req_text = redact_text(req_text, secret_values=secret_values, secret_patterns=secret_patterns)
        resp_text = redact_text(
            response_body[:MAX_EVIDENCE_BODY], secret_values=secret_values,
            secret_patterns=secret_patterns,
        )
        rec = self.db.add_evidence(
            kind="request_response", ref=f"{method} {url}",
            description=f"broker-captured {method} request/response",
            preview="UNTRUSTED TARGET DATA\n" + resp_text[:MAX_PREVIEW],
        )
        artifact = self.workspace / "evidence" / f"{rec.public_id}.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "bughunt.request_response.v1", "timestamp": utcnow(),
            "program": self.program_slug,
            "request": {
                "method": method, "url": url,
                "query_parameters": dict(parse_qsl(urlparse(url).query, keep_blank_values=True)),
                "headers": safe_req_headers, "body": req_text,
                "auth_context": auth.context_id, "account_id": auth.account_id,
                "account_role": auth.role, "controlled_mutation": controlled_mutation or {},
                "baseline_evidence_id": baseline_evidence_id or None,
            },
            "response": {
                "status": response_status, "headers": safe_resp_headers,
                "body": resp_text, "body_length": len(response_body.encode("utf-8", errors="replace")),
            },
            "redirect_chain": redirect_chain, "burp_reference": burp_ref or None,
        }
        artifact.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.db.set_evidence_ref(rec.id, str(artifact))
        return rec.public_id

    def execute(
        self, *, target: str, method: str = "GET", action: str = "read_http",
        headers: dict[str, str] | None = None, body: str | None = None,
        json_body: Any | None = None, params: dict[str, str] | None = None,
        agent_role: str = "orchestrator", session_id: int | None = None,
        auth_context: str = "", timeout: int = DEFAULT_TIMEOUT,
        allow_redirects: bool = False, verify: bool | str = True,
        max_redirects: int | None = None, approval_constraints: dict | None = None,
        research_test_id: int | None = None, hypothesis_id: int | None = None,
        controlled_mutation: dict | None = None, baseline_evidence_id: str = "",
        burp_ref: str = "",
        parent_request_id: int | None = None, root_request_id: int | None = None,
        replay_depth: int = 0, mutation_summary: str = "",
        secret_extract: dict[str, str] | None = None,
        secret_store_names: dict[str, str] | None = None,
        extra_secret_values: list[str] | None = None,
    ) -> BrokerResult:
        method = method.upper()
        if not self.active:
            return self._blocked(action, target, method, "program is not active", agent_role, session_id)
        try:
            current_url = normalize_target(target)
        except (ValueError, NetworkSafetyError) as exc:
            return self._blocked(action, target, method, str(exc), agent_role, session_id)
        # Out-of-scope remains the first target gate and never requires an
        # execution session merely to refuse it. Every request that could reach
        # the network, however, must carry the exact running session binding.
        initial_scope = self.scope.check(current_url)
        if not initial_scope.allowed:
            return self._blocked(
                action, current_url, method, f"out_of_scope: {initial_scope.reason}",
                agent_role, session_id,
            )
        if session_id is None:
            return self._blocked(
                action, current_url, method, "explicit bound session_id is required",
                agent_role, session_id,
            )
        try:
            self.db.require_session(
                session_id, program_slug=self.program_slug, running=True,
            )
        except StateError as exc:
            return self._blocked(action, current_url, method, str(exc), agent_role, session_id)
        if research_test_id is not None:
            try:
                test = self.db.get_test(research_test_id)
                if hypothesis_id is None:
                    hypothesis_id = test.hypothesis_id
                elif test.hypothesis_id != hypothesis_id:
                    raise StateError("research test does not belong to supplied hypothesis")
            except StateError as exc:
                return self._blocked(action, target, method, str(exc), agent_role, session_id)
        try:
            auth = self._resolve_auth_context(auth_context)
            req_headers, sensitive_names, secret_values = self._resolve_headers(headers, auth)
            secret_values.extend(extra_secret_values or [])
        except (ValueError, NetworkSafetyError) as exc:
            return self._blocked(action, target, method, str(exc), agent_role, session_id)

        redirect_limit = max_redirects or self.engagement.autonomy.max_redirects
        redirect_chain: list[dict] = []
        proxy, configured_ca, https_interception = self._burp_settings()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        if proxy and verify is True and configured_ca:
            verified_ca, ca_status = validate_ca_bundle(configured_ca)
            if verified_ca is None:
                return self._blocked(
                    action, current_url, method, f"invalid Burp CA bundle: {ca_status}",
                    agent_role, session_id, auth=auth, proxy=proxy,
                )
            verify = verified_ca
        elif proxy and verify is True and https_interception:
            return self._blocked(
                action, current_url, method,
                "Burp HTTPS interception is configured but no CA bundle is available",
                agent_role, session_id, auth=auth, proxy=proxy,
            )
        current_method, current_body, current_json, current_params = method, body, json_body, params
        approval = None

        for hop in range(redirect_limit + 1):
            scope = self.scope.check(current_url)
            if not scope.allowed:
                return self._blocked(
                    action, current_url, current_method, f"out_of_scope: {scope.reason}",
                    agent_role, session_id, redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                )
            pol = self.policy.check(action, current_url)
            if pol.decision == DENY:
                return self._blocked(
                    action, current_url, current_method, pol.reason, agent_role, session_id,
                    redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                )
            budget_reason = self._budget_gate(session_id, hypothesis_id)
            if budget_reason:
                return self._blocked(
                    action, current_url, current_method, budget_reason, agent_role, session_id,
                    redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                )
            if pol.decision == APPROVAL_REQUIRED and approval is None:
                constraints = dict(approval_constraints or {"max_requests": 1})
                constraints.setdefault("max_requests", 1 + (redirect_limit if allow_redirects else 0))
                constraints.setdefault("max_concurrency", self.engagement.roe.max_concurrency)
                constraints.setdefault("duration_seconds", timeout)
                if int(constraints["max_concurrency"]) > self.engagement.roe.max_concurrency:
                    return self._blocked(
                        action, current_url, current_method,
                        "approval plan exceeds ROE max_concurrency", agent_role, session_id,
                        redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                    )
                if int(constraints["duration_seconds"]) > max(timeout, 300):
                    return self._blocked(
                        action, current_url, current_method,
                        "approval plan duration is not bounded", agent_role, session_id,
                        redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                    )
                ph = request_params_hash(
                    current_method, current_url, current_body, current_json,
                    current_params, controlled_mutation,
                )
                approval = self.db.find_valid_approval(
                    action, target=current_url, program=self.program_slug,
                    method=current_method, params_hash=ph,
                    auth_context=auth.context_id,
                )
                if approval is None:
                    self.db.request_approval(
                        action, current_url, requested_by=agent_role, note=pol.reason,
                        program=self.program_slug, method=current_method, params_hash=ph,
                        session_id=session_id, auth_context=auth.context_id,
                        constraints=constraints,
                    )
                    self._log(agent_role, action, current_url, APPROVAL_REQUIRED, pol.reason, session_id)
                    return BrokerResult(
                        ok=False, decision=APPROVAL_REQUIRED, reason=pol.reason,
                        method=current_method, url=current_url, auth_context=auth.context_id,
                        account_role=auth.role, redirect_chain=redirect_chain, proxy=proxy,
                    )
            if approval is not None:
                approval = self.db.get_approval(approval.id)
                allowed_targets = approval.constraints.get("targets") or [approval.target]
                if (
                    approval.status != "approved"
                    or approval.action != action
                    or approval.program != self.program_slug
                    or approval.auth_context != auth.context_id
                    or current_url not in allowed_targets
                    or (approval.method and approval.method != current_method)
                ):
                    return self._blocked(
                        action, current_url, current_method,
                        "bounded approval does not authorize this execution",
                        agent_role, session_id, redirect_chain=redirect_chain,
                        auth=auth, proxy=proxy,
                    )

            effective_concurrency = self.engagement.roe.max_concurrency
            if approval is not None:
                effective_concurrency = min(
                    effective_concurrency,
                    int(approval.constraints.get("max_concurrency", effective_concurrency)),
                )
                try:
                    # Reserve before reaching the network. This makes the
                    # request bound atomic under concurrent broker processes.
                    approval = self.db.record_approval_use(approval.id)
                except StateError as exc:
                    return self._blocked(
                        action, current_url, current_method, str(exc), agent_role,
                        session_id, redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                    )

            host = scope_target_host(current_url)
            try:
                lease = self.limiter.acquire(
                    host, self.engagement.roe.max_rps, effective_concurrency,
                    session_id=session_id, lease_ttl=max(float(timeout) + 15.0, 30.0),
                )
            except NetworkSafetyError as exc:
                return self._blocked(
                    action, current_url, current_method, str(exc), agent_role, session_id,
                    redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                )
            try:
                request_started = time.perf_counter()
                resp = requests.request(
                    current_method, current_url, headers=req_headers,
                    data=current_body, json=current_json, params=current_params,
                    timeout=timeout, allow_redirects=False, verify=verify, proxies=proxies,
                )
            except Exception as exc:  # noqa: BLE001
                self._log(agent_role, action, current_url, ALLOW, f"request_error:{type(exc).__name__}", session_id)
                return BrokerResult(
                    ok=False, decision=ALLOW, reason="request_error", method=current_method,
                    url=current_url, request_headers=redact_headers(req_headers, sensitive_names),
                    auth_context=auth.context_id, account_role=auth.role,
                    redirect_chain=redirect_chain, proxy=proxy,
                    error=f"{type(exc).__name__}: {redact_text(str(exc), secret_values=secret_values, secret_patterns=self.engagement.headers.secret_patterns)}",
                )
            finally:
                self.limiter.release(host, lease)

            try:
                text_body = resp.text
            except Exception:
                text_body = ""
            exact_url = normalize_target(resp.url or current_url)
            session_refs: dict[str, str] = {}
            if secret_extract:
                try:
                    session_refs = self._extract_session_secrets(
                        resp, secret_extract, secret_store_names or {},
                    )
                    secret_values.extend(
                        value for value in (self.secrets.resolve(ref) for ref in session_refs.values())
                        if value
                    )
                except (ValueError, KeyError, SecretError, json.JSONDecodeError) as exc:
                    return self._blocked(
                        action, exact_url, current_method,
                        f"session credential extraction failed: {type(exc).__name__}",
                        agent_role, session_id, redirect_chain=redirect_chain,
                        auth=auth, proxy=proxy, status_code=resp.status_code,
                    )
            safe_exact_url = redact_url(exact_url, secret_values=secret_values)
            evidence_id = self._persist_evidence(
                method=current_method, url=exact_url, request_headers=req_headers,
                request_body=current_json if current_json is not None else current_body,
                response_status=resp.status_code, response_headers=dict(resp.headers),
                response_body=text_body, auth=auth, sensitive_names=sensitive_names,
                secret_values=secret_values,
                secret_patterns=self.engagement.headers.secret_patterns,
                controlled_mutation=controlled_mutation,
                baseline_evidence_id=baseline_evidence_id,
                redirect_chain=redirect_chain, burp_ref=burp_ref,
            )
            request_record = self.db.record_request(
                program=self.program_slug, method=current_method, url=safe_exact_url,
                session_id=session_id, auth_context=auth.context_id,
                request_metadata={
                    "headers": redact_headers(req_headers, sensitive_names),
                    "query_parameters": dict(parse_qsl(urlparse(safe_exact_url).query, keep_blank_values=True)),
                    "account_id": auth.account_id, "account_role": auth.role,
                    "action": action,
                },
                response_metadata={
                    "status": resp.status_code, "headers": redact_headers(dict(resp.headers), sensitive_names),
                    "length": len(resp.content),
                    "timing_ms": round((time.perf_counter() - request_started) * 1000, 3),
                },
                burp_ref=burp_ref,
                body_hash=hashlib.sha256(
                    (
                        json.dumps(current_json, sort_keys=True, default=str)
                        if current_json is not None
                        else (current_body or "")
                    ).encode()
                ).hexdigest(),
                evidence_ref=evidence_id, research_test_id=research_test_id,
                hypothesis_id=hypothesis_id, controlled_mutation=controlled_mutation,
                parent_request_id=parent_request_id, root_request_id=root_request_id,
                replay_depth=replay_depth, mutation_summary=mutation_summary,
            )
            self._log(
                agent_role, action, safe_exact_url, ALLOW,
                f"HTTP {resp.status_code} len={len(resp.content)} evidence={evidence_id}", session_id,
            )

            location = resp.headers.get("Location")
            if not (allow_redirects and resp.status_code in REDIRECT_CODES and location):
                return BrokerResult(
                    ok=True, decision=ALLOW, reason="allowed", method=current_method,
                    url=safe_exact_url, status_code=resp.status_code,
                    request_headers=redact_headers(req_headers, sensitive_names),
                    response_headers=redact_headers(dict(resp.headers), sensitive_names),
                    body_preview="UNTRUSTED TARGET DATA\n" + redact_text(
                        text_body[:MAX_PREVIEW], secret_values=secret_values,
                        secret_patterns=self.engagement.headers.secret_patterns,
                    ),
                    body_length=len(resp.content), evidence_id=evidence_id,
                    request_id=request_record.public_id, auth_context=auth.context_id,
                    account_role=auth.role,
                    redirect_chain=[
                        {
                            **entry,
                            **{
                                key: redact_url(str(entry[key]), secret_values=secret_values)
                                for key in ("from", "to") if entry.get(key)
                            },
                        }
                        for entry in redirect_chain
                    ],
                    proxy=proxy,
                    session_secret_refs=session_refs,
                )
            if hop >= redirect_limit:
                return self._blocked(
                    action, exact_url, current_method, "redirect_limit_exceeded",
                    agent_role, session_id, redirect_chain=redirect_chain,
                    auth=auth, proxy=proxy, status_code=resp.status_code,
                    evidence_id=evidence_id,
                )
            try:
                next_url = normalize_target(urljoin(exact_url, location))
            except ValueError as exc:
                return self._blocked(
                    action, exact_url, current_method, f"unsafe_redirect: {exc}",
                    agent_role, session_id, redirect_chain=redirect_chain,
                    auth=auth, proxy=proxy, status_code=resp.status_code,
                    evidence_id=evidence_id,
                )
            next_scope = self.scope.check(next_url)
            if not next_scope.allowed:
                redirect_chain.append({"from": exact_url, "status": resp.status_code, "to": next_url, "followed": False})
                return self._blocked(
                    action, next_url, current_method,
                    f"out_of_scope_redirect: {next_scope.reason}", agent_role, session_id,
                    redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                    status_code=resp.status_code, evidence_id=evidence_id,
                )
            old_host, new_host = parse_target(exact_url).host, parse_target(next_url).host
            if auth.context_id and old_host != new_host:
                allowed_hosts = {str(h).lower().rstrip(".") for h in auth.metadata.get("allowed_hosts", [])}
                if new_host not in allowed_hosts:
                    redirect_chain.append({"from": exact_url, "status": resp.status_code, "to": next_url, "followed": False})
                    return self._blocked(
                        action, next_url, current_method,
                        "auth_context_cross_host_redirect_not_authorized", agent_role, session_id,
                        redirect_chain=redirect_chain, auth=auth, proxy=proxy,
                        status_code=resp.status_code, evidence_id=evidence_id,
                    )
            redirect_chain.append({"from": exact_url, "status": resp.status_code, "to": next_url, "followed": True})
            current_url, current_params = next_url, None
            if resp.status_code == 303 or (resp.status_code in {301, 302} and current_method == "POST"):
                current_method, current_body, current_json = "GET", None, None

        raise AssertionError("redirect loop exhausted unexpectedly")

    def _extract_session_secrets(
        self, response, selectors: dict[str, str], store_names: dict[str, str],
    ) -> dict[str, str]:
        """Extract credentials inside the broker and persist only secret refs."""
        output: dict[str, str] = {}
        parsed_json = None
        for key, selector in selectors.items():
            if selector.startswith("json:"):
                if parsed_json is None:
                    parsed_json = response.json()
                current: Any = parsed_json
                for segment in selector[5:].removeprefix("$.").split("."):
                    current = current[segment]
                value = str(current)
            elif selector.startswith("cookie:"):
                value = str(response.cookies.get(selector[7:]) or "")
            else:
                raise ValueError("session selector must use json: or cookie:")
            if not value:
                raise ValueError(f"empty extracted credential {key}")
            output[key] = self.secrets.store_file_secret(store_names.get(key, f"session-{key}"), value)
        return output

    def _blocked(
        self, action: str, target: str, method: str, reason: str,
        agent_role: str, session_id: int | None, *, redirect_chain: list[dict] | None = None,
        auth: AuthResolution | None = None, proxy: str | None = None,
        status_code: int | None = None, evidence_id: str | None = None,
    ) -> BrokerResult:
        self._log(agent_role, action, target, DENY, reason, session_id)
        secret_values = auth.secret_values if auth else []
        safe_chain = [
            {
                **hop,
                **{
                    key: redact_url(str(hop[key]), secret_values=secret_values)
                    for key in ("from", "to") if hop.get(key)
                },
            }
            for hop in (redirect_chain or [])
        ]
        return BrokerResult(
            ok=False, decision=DENY, reason=reason, method=method,
            url=redact_url(target, secret_values=secret_values),
            status_code=status_code, evidence_id=evidence_id,
            auth_context=auth.context_id if auth else "",
            account_role=auth.role if auth else "",
            redirect_chain=safe_chain, proxy=proxy,
        )

    def _log(
        self, agent_role: str, action: str, target: str, decision: str,
        summary: str, session_id: int | None,
    ) -> None:
        try:
            self.db.record_action(
                agent_role=agent_role, action=action, program=self.program_slug,
                target=redact_url(target), decision=decision,
                result_summary=redact_text(
                    summary, secret_patterns=self.engagement.headers.secret_patterns,
                ),
                session_id=session_id,
            )
        except Exception:
            pass


def scope_target_host(target: str) -> str:
    try:
        return parse_target(target).host
    except ValueError:
        return "invalid"


__all__ = [
    "BrokerResult", "RequestBroker", "HostRateLimiter", "scope_target_host",
    "request_params_hash", "detected_burp_proxy",
    "burp_proxy_status", "validate_ca_bundle",
]
