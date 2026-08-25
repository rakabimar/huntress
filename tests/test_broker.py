"""Request-broker tests — scope/policy gates and a *localhost* happy path.

The ALLOW path is exercised against a loopback HTTP fixture only (spec §95).
Out-of-scope, forbidden, and approval-gated requests are asserted to
short-circuit *before* any network I/O.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from bughunt_harness.requests.broker import RequestBroker, scope_target_host
from bughunt_harness.state.db import HuntDB
from bughunt_harness.secrets.manager import SecretManager


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"fixture-ok")

    def log_message(self, *args):  # noqa: D102
        pass


def _serve():
    server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _broker(engagement, tmp_path):
    db = HuntDB(tmp_path / "state" / "hunt.db", program_slug="acme-test")
    return RequestBroker(
        engagement,
        program_slug="acme-test",
        workspace=tmp_path,
        hunt_db=db,
        secrets=SecretManager("acme-test"),
    )


def test_out_of_scope_short_circuits(engagement, tmp_path):
    b = _broker(engagement, tmp_path)
    r = b.execute(target="https://evil.org", action="read_http")
    assert r.ok is False
    assert r.decision == "deny"
    assert "out_of_scope" in r.reason


def test_forbidden_action_denied(engagement, tmp_path):
    b = _broker(engagement, tmp_path)
    r = b.execute(target="https://example.test", action="dos")
    assert r.ok is False
    assert r.decision == "deny"


def test_approval_required_when_automation_off(engagement, tmp_path):
    b = _broker(engagement, tmp_path)  # default ROE: automation off
    r = b.execute(target="https://example.test", action="read_http")
    assert r.ok is False
    assert r.decision == "approval_required"


def test_allowed_localhost_roundtrip(allowed_engagement, tmp_path):
    server = _serve()
    try:
        port = server.server_address[1]
        b = _broker(allowed_engagement, tmp_path)
        r = b.execute(target=f"http://127.0.0.1:{port}/ok", action="read_http")
        assert r.ok is True
        assert r.decision == "allow"
        assert r.status_code == 200
        assert "fixture-ok" in r.body_preview
        assert r.evidence_id is not None  # evidence persisted
    finally:
        server.shutdown()
        server.server_close()


def test_scope_target_host_extraction():
    assert scope_target_host("https://api.example.test:8443/x") == "api.example.test"
    assert scope_target_host("http://127.0.0.1:8080") == "127.0.0.1"
    assert scope_target_host("https://example.test") == "example.test"


def test_required_header_matching_is_case_insensitive(tmp_path):
    # P0.10: a mandatory header supplied with different casing must still satisfy
    # the requirement (HTTP header names are case-insensitive).
    from bughunt_harness.engagement.models import (
        AccountsModel,
        Engagement,
        HeaderModel,
        HeadersModel,
        ProgramModel,
        ReportingModel,
        ROEModel,
        ScopeModel,
        ScopeSet,
    )

    eng = Engagement(
        program=ProgramModel(name="h", platform="custom", status="active"),
        scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"])),
        roe=ROEModel(automation_allowed=True, required_headers=["X-Bug-Bounty"]),
        headers=HeadersModel(headers=[HeaderModel(name="X-Bug-Bounty", mandatory=True)]),
        accounts=AccountsModel(),
        reporting=ReportingModel(),
    )
    b = _broker(eng, tmp_path)
    server = _serve()
    try:
        port = server.server_address[1]
        # Metadata name "X-Bug-Bounty", supplied as "X-BUG-BOUNTY".
        r = b.execute(
            target=f"http://127.0.0.1:{port}/ok", action="read_http",
            headers={"X-BUG-BOUNTY": "MARKER"},
        )
    finally:
        server.shutdown()
        server.server_close()
    assert r.ok is True
    assert r.decision == "allow"