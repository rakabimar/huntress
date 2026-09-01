"""Deterministic localhost acceptance for the capability-completion loop.

Unlike the optional real-provider/model smokes, this workflow is safe for
pytest: it binds only to loopback and uses an in-memory OAST provider.
"""

from __future__ import annotations

import base64
import json
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from .auth import AuthSessionManager
from .config import HarnessConfig
from .coverage import CoverageTracker
from .engagement.models import (
    AccountAuthModel,
    AccountModel,
    AccountsModel,
    AuthLoginModel,
    Engagement,
    ProgramModel,
    ROEModel,
    ScopeModel,
    ScopeSet,
)
from .javascript import JavaScriptAnalyzer
from .oast import OASTInteractionData, OASTService, SyntheticOASTProvider
from .policy.engine import PolicyEngine
from .requests.broker import RequestBroker
from .requests.replay import ReplayService
from .scope.engine import ScopeEngine
from .secrets.manager import SecretManager
from .state.db import HuntDB
from .watch import ReconWatchService


@dataclass
class CapabilityAcceptanceResult:
    ok: bool
    workspace: str
    request_count: int
    auth_differential_statuses: list[int | None]
    response_diff_observation_only: bool
    auth_refresh_count: int
    oast_interaction_count: int
    oast_evidence_id: str
    js_artifact_count: int
    recon_change_count: int
    watch_lead_count: int
    coverage_tested: int
    duplicate_classification: str
    external_network_used: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


def _jwt(exp: int, marker: str) -> str:
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{encode({'alg': 'none'})}.{encode({'exp': exp, 'marker': marker})}.sig"


def run_capability_completion_smoke(work_root: Path | None = None) -> CapabilityAcceptanceResult:
    """Exercise the completed research loop against one synthetic local app."""
    root = Path(work_root) if work_root else Path(tempfile.mkdtemp(prefix="bughunt-capability-smoke-"))
    workspace = root / "program"
    workspace.mkdir(parents=True, exist_ok=True)
    provider = SyntheticOASTProvider()
    runtime: dict = {"token": "", "js_version": 1, "oast_ref": ""}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                body = {}
            if self.path == "/login" and body == {"email": "local-user", "password": "local-password"}:
                runtime["token"] = _jwt(int(time.time()) + 1, "initial")
                self._json(200, {"access_token": runtime["token"], "refresh_token": "local-refresh"})
                return
            if self.path == "/refresh" and body.get("refresh_token") == "local-refresh":
                runtime["token"] = _jwt(int(time.time()) + 3600, "refreshed")
                self._json(200, {"access_token": runtime["token"], "refresh_token": "local-refresh"})
                return
            self._json(401, {"error": "bad_credentials"})

        def do_GET(self):  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path == "/objects/1":
                account = self.headers.get("X-Account", "")
                if account == "account-a":
                    self._json(200, {"id": 1, "owner": "account-a", "private": "owner-view"})
                else:
                    self._json(403, {"error": "not_owner"})
                return
            if parsed.path == "/protected":
                if self.headers.get("Authorization") == "Bearer " + runtime["token"]:
                    self._json(200, {"ok": True})
                else:
                    self._json(401, {"error": "expired"})
                return
            if parsed.path == "/app.js":
                routes = '["/api/v1/orders"]' if runtime["js_version"] == 1 else '["/api/v1/orders","/api/v2/admin-preview"]'
                raw = (f"const routes={routes}; query GetOrder {{ order {{ id }} }}; "
                       "const apiKey='ABCDEFGHIJKLMNOP'; //# sourceMappingURL=app.js.map").encode()
                self.send_response(200); self.send_header("Content-Type", "application/javascript")
                self.end_headers(); self.wfile.write(raw)
                return
            if parsed.path == "/app.js.map":
                self._json(200, {"version": 3, "sources": ["src/app.ts"], "sourcesContent": ["fetch('/api/v1/orders')"], "names": ["fetch"]})
                return
            if parsed.path == "/blind":
                callback = parse_qs(parsed.query).get("callback", [""])[0]
                hostname = (urlsplit(callback).hostname or "").lower()
                if runtime["oast_ref"] and hostname:
                    provider.inject(runtime["oast_ref"], OASTInteractionData(
                        "local-callback-1", "HTTP", datetime.now(timezone.utc).isoformat(),
                        hostname, request_method="GET", path="/",
                    ))
                self._json(202, {"queued": True})
                return
            self._json(404, {"error": "missing"})

        def _json(self, status: int, document: dict) -> None:
            raw = json.dumps(document).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    cfg = HarnessConfig(home=root / "home", burp_proxy="disabled")
    cfg.ensure_dirs()
    secrets = SecretManager("capability-smoke", cfg)
    for name, value in {
        "account-a": "account-a", "account-b": "account-b",
        "username": "local-user", "password": "local-password",
    }.items():
        secrets.store_file_secret(name, value)
    lifecycle = AccountAuthModel(
        type="bearer", bearer_ref="file:session-access", strategy="HTTP_LOGIN",
        login=AuthLoginModel(
            url=base + "/login", username_field="email", username_ref="file:username",
            password_ref="file:password", bearer_json_path="$.access_token",
            refresh_json_path="$.refresh_token", refresh_url=base + "/refresh",
        ),
    )
    scope_model = ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"], urls=[base]))
    engagement = Engagement(
        program=ProgramModel(name="Capability completion smoke", status="active"),
        scope=scope_model,
        roe=ROEModel(
            automation_allowed=True, authentication_testing=True,
            authorization_testing=True, state_changing_actions=True,
            out_of_band_testing=True, max_rps=50.0, max_concurrency=2,
        ),
        accounts=AccountsModel(accounts=[
            AccountModel(id="account_a", role="owner", auth=AccountAuthModel(type="header_bundle", headers={"X-Account": "file:account-a"})),
            AccountModel(id="account_b", role="other", auth=AccountAuthModel(type="header_bundle", headers={"X-Account": "file:account-b"})),
            AccountModel(id="session_account", role="user", auth=lifecycle),
        ]),
    )
    db = HuntDB(workspace / "state" / "hunt.db", "capability-smoke")
    broker = RequestBroker(
        engagement, program_slug="capability-smoke", workspace=workspace,
        hunt_db=db, secrets=secrets,
    )
    broker.config = cfg
    ctx = SimpleNamespace(
        slug="capability-smoke", workspace=workspace, db=db, broker=broker,
        engagement=engagement, scope=ScopeEngine(scope_model),
        policy=PolicyEngine(scope_model, engagement.roe),
    )
    try:
        session = db.start_session("acceptance", "researcher", "capability-smoke")
        asset, _ = db.upsert_asset(
            type="host", value="127.0.0.1", normalized_value="127.0.0.1",
            scope_status="in_scope", confidence=1.0,
        )
        db.upsert_endpoint(
            host_asset_id=asset["id"], scheme="http", method="GET",
            # Recon deliberately shapes only high-confidence identifiers; the
            # short fixture integer therefore remains literal.
            normalized_path="/objects/1", metadata={"source": "acceptance"},
        )
        auth_hypothesis = db.create_hypothesis("The same object is handled differently across two explicit accounts")
        auth_test = db.add_test(auth_hypothesis.id, "owner versus other exact request differential")
        baseline = broker.execute(
            target=base + "/objects/1", action="authorization_test",
            auth_context="account_a", session_id=session.id,
            research_test_id=auth_test.id, hypothesis_id=auth_hypothesis.id,
            agent_role="api-authz-specialist",
        )
        if not baseline.ok or not baseline.request_id:
            raise RuntimeError(f"auth baseline failed: {baseline.decision}: {baseline.reason}")
        differential = ReplayService(ctx).compare_across_auth(
            int(baseline.request_id.rsplit("-", 1)[1]), contexts=["account_a", "account_b"],
            session_id=session.id, mode="OWNER_VS_OTHER", baseline_context="account_a",
            expected_owner_context="account_a", research_test_id=auth_test.id,
            hypothesis_id=auth_hypothesis.id,
        )

        manager = AuthSessionManager(ctx)
        login = manager.login("session_account", session_id=session.id)
        if login["state"] != "VALID":
            raise RuntimeError("local session login did not become valid")
        protected = manager.execute_with_session(
            "session_account", session_id=session.id, target=base + "/protected",
            action="read_http", agent_role="auth-identity-specialist",
        )
        if not protected.ok:
            raise RuntimeError("refreshed local session did not authorize protected request")

        watch = ReconWatchService(ctx)
        watch.configure("passive", 60)
        watch_calls = {"count": 0}

        def recon_runner(_profile: str) -> dict:
            watch_calls["count"] += 1
            runtime["js_version"] = watch_calls["count"]
            recon_run = db.start_recon_run(profile="passive", stage="javascript")
            analysis = JavaScriptAnalyzer(ctx).analyze_url(
                base + "/app.js", session_id=session.id, recon_run_id=recon_run["id"],
            )
            db.finish_recon_run(recon_run["id"], status="completed")
            return {"artifact_id": analysis.get("id"), "changed": analysis.get("changed", False)}

        watch.run_once("passive", recon_runner)
        watch_second = watch.run_once("passive", recon_runner)

        oast = OASTService(ctx, {"synthetic": provider})
        oast_session = oast.create_session("synthetic", session_id=session.id, expires_in=300)
        runtime["oast_ref"] = oast_session["provider_session_reference"]
        blind_hypothesis = db.create_hypothesis("A callback is exactly correlated to one blind local test")
        blind_test = db.add_test(blind_hypothesis.id, "minimal local synthetic OAST callback")
        probe = oast.create_probe(
            oast_session["id"], hypothesis_id=blind_hypothesis.id,
            research_test_id=blind_test.id, expected_protocols=["HTTP"],
        )
        callback = probe["callback_urls"]["HTTP"]
        oob_kwargs = {
            "target": base + "/blind", "params": {"callback": callback},
            "action": "oob_test", "session_id": session.id,
            "research_test_id": blind_test.id, "hypothesis_id": blind_hypothesis.id,
            "agent_role": "researcher",
        }
        first_oob = broker.execute(**oob_kwargs)
        if first_oob.decision != "approval_required":
            raise RuntimeError("OAST target request did not enforce its R3 approval gate")
        approval = db.list_pending_approvals(session_id=session.id)[0]
        db.approve_approval(approval.id, approved_by="local-acceptance-human")
        sent_oob = broker.execute(**oob_kwargs)
        if not sent_oob.ok or not sent_oob.request_id:
            raise RuntimeError(f"approved OAST request failed: {sent_oob.reason}")
        oast.link_request(probe["id"], int(sent_oob.request_id.rsplit("-", 1)[1]))
        polled = oast.poll_probe(probe["id"])
        if len(polled["interactions"]) != 1 or not polled["new_interactions"]:
            raise RuntimeError("exact local OAST correlation was not persisted")

        first_finding = db.create_finding(
            "Duplicate fixture A", affected_target=base + "/objects/1",
            category="CWE-639", impact_summary="cross-account object read",
        )
        second_finding = db.create_finding(
            "Duplicate fixture B", affected_target=base + "/objects/2",
            category="CWE-639", impact_summary="cross-account object read",
        )
        second_finding = db.get_finding(second_finding.id)
        coverage = CoverageTracker(ctx).summary()
        auth_status = manager.status("session_account")[0]
        result = CapabilityAcceptanceResult(
            ok=(
                differential.statuses == [200, 403]
                and differential.observation_only
                and auth_status["refresh_count"] == 1
                and second_finding.dedup_classification == "EXACT_DUPLICATE"
                and coverage["tested"] >= 1
                and bool(watch_second["leads"])
            ),
            workspace=str(workspace), request_count=len(db.list_request_records()),
            auth_differential_statuses=differential.statuses,
            response_diff_observation_only=differential.observation_only,
            auth_refresh_count=auth_status["refresh_count"],
            oast_interaction_count=len(polled["interactions"]),
            oast_evidence_id=polled["new_interactions"][0]["evidence_id"],
            js_artifact_count=db._conn.execute("SELECT COUNT(*) FROM js_artifact").fetchone()[0],
            recon_change_count=db._conn.execute("SELECT COUNT(*) FROM recon_change").fetchone()[0],
            watch_lead_count=len(watch_second["leads"]), coverage_tested=coverage["tested"],
            duplicate_classification=second_finding.dedup_classification,
        )
        if not result.ok:
            raise RuntimeError(f"capability acceptance predicate failed: {result.as_dict()}")
        # The first fixture is intentionally retained so the duplicate relation
        # remains inspectable in the acceptance database.
        assert first_finding.id == second_finding.potential_duplicate_of
        return result
    finally:
        broker.limiter.close()
        db.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)


__all__ = ["CapabilityAcceptanceResult", "run_capability_completion_smoke"]
