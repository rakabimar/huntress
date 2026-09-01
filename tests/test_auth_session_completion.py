from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

from bughunt_harness.auth import AuthSessionManager
from bughunt_harness.config import HarnessConfig
from bughunt_harness.engagement.models import (
    AccountAuthModel, AccountModel, AccountsModel, AuthLoginModel, Engagement,
    ProgramModel, ROEModel, ScopeModel, ScopeSet,
)
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.requests.broker import RequestBroker
from bughunt_harness.scope.engine import ScopeEngine
from bughunt_harness.secrets.manager import SecretManager
from bughunt_harness.state.db import HuntDB


def _jwt(exp: int, marker: str) -> str:
    enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{enc({'alg':'none'})}.{enc({'exp':exp,'marker':marker})}.sig"


class _AuthHandler(BaseHTTPRequestHandler):
    current = ""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0")); body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/login" and body == {"email": "user", "password": "password"}:
            token = _jwt(int(time.time()) + 1, "initial"); self.__class__.current = token
            self._json(200, {"access_token": token, "refresh_token": "refresh-secret"}); return
        if self.path == "/refresh" and body.get("refresh_token") == "refresh-secret":
            token = _jwt(int(time.time()) + 3600, "refreshed"); self.__class__.current = token
            self._json(200, {"access_token": token, "refresh_token": "refresh-secret"}); return
        self._json(401, {"error": "bad_credentials"})

    def do_GET(self):  # noqa: N802
        if self.path == "/protected" and self.headers.get("Authorization") == "Bearer " + self.__class__.current:
            self._json(200, {"ok": True}); return
        self._json(401, {"error": "expired"})

    def _json(self, status, body):
        raw = json.dumps(body).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(raw)

    def log_message(self, *_args): pass


def test_short_lived_session_refreshes_once_without_db_secret_leak(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), _AuthHandler); threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    cfg = HarnessConfig(home=tmp_path / "home", burp_proxy="disabled"); cfg.ensure_dirs()
    secrets = SecretManager("auth-test", cfg); secrets.store_file_secret("username", "user"); secrets.store_file_secret("password", "password")
    auth = AccountAuthModel(
        type="bearer", bearer_ref="file:access", strategy="HTTP_LOGIN",
        login=AuthLoginModel(
            url=base + "/login", username_field="email", username_ref="file:username",
            password_ref="file:password", bearer_json_path="$.access_token",
            refresh_json_path="$.refresh_token", refresh_url=base + "/refresh",
        ),
    )
    scope_model = ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"]))
    engagement = Engagement(program=ProgramModel(name="auth", status="active"), scope=scope_model, roe=ROEModel(automation_allowed=True, state_changing_actions=True, authentication_testing=True), accounts=AccountsModel(accounts=[AccountModel(id="account_a", auth=auth)]))
    db = HuntDB(tmp_path / "state" / "hunt.db", "auth-test"); session = db.start_session("pytest", "auth-identity-specialist", "auth-test")
    broker = RequestBroker(engagement, program_slug="auth-test", workspace=tmp_path, hunt_db=db, secrets=secrets); broker.config = cfg
    ctx = SimpleNamespace(slug="auth-test", workspace=tmp_path, db=db, broker=broker, engagement=engagement, scope=ScopeEngine(scope_model), policy=PolicyEngine(scope_model, engagement.roe))
    manager = AuthSessionManager(ctx)
    try:
        logged_in = manager.login("account_a", session_id=session.id)
        assert logged_in["state"] == "VALID"
        result = manager.execute_with_session("account_a", session_id=session.id, target=base + "/protected", action="read_http")
        assert result.ok and result.status_code == 200
        assert manager.status("account_a")[0]["refresh_count"] == 1
        db_text = " ".join(str(tuple(row)) for table in ("auth_session", "auth_session_event", "request_record", "evidence") for row in db._conn.execute(f"SELECT * FROM {table}"))
        assert "password" not in db_text and "refresh-secret" not in db_text and _AuthHandler.current not in db_text
        assert (secrets.secret_dir / "access").stat().st_mode & 0o777 == 0o600
    finally:
        broker.limiter.close(); db.close(); server.shutdown(); server.server_close()


def test_manual_browser_session_waits_for_human(tmp_path):
    # Static output ref metadata is allowed to be unavailable until the human completes login.
    auth = AccountAuthModel(type="bearer", bearer_ref="file:manual-access", strategy="MANUAL_BROWSER")
    scope_model = ScopeModel(include=ScopeSet(domains=["example.test"]))
    engagement = Engagement(program=ProgramModel(name="manual", status="active"), scope=scope_model, accounts=AccountsModel(accounts=[AccountModel(id="manual", auth=auth)]))
    db = HuntDB(tmp_path / "state" / "hunt.db", "manual"); cfg = HarnessConfig(home=tmp_path / "home", burp_proxy="disabled")
    broker = RequestBroker(engagement, program_slug="manual", workspace=tmp_path, hunt_db=db, secrets=SecretManager("manual", cfg)); broker.config = cfg
    ctx = SimpleNamespace(slug="manual", workspace=tmp_path, db=db, broker=broker, engagement=engagement)
    result = AuthSessionManager(ctx).login("manual", session_id=db.start_session("pytest", "researcher", "manual").id)
    assert result["state"] == "WAITING_HUMAN"
    broker.limiter.close(); db.close()
