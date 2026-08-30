"""End-to-end synthetic hunt loop (P1).  Local-only; no external network.

Runs the complete research pipeline against a loopback HTTP fixture and a
``--fixture``-style program: registry → scope → broker roundtrip → evidence →
lead → hypothesis → research test → finding → validation review → validated →
PoC → CVSS scoring → report → QA.  The CLI ``cvss``/``poc`` entry points are
smoke-tested in-process; the loop itself drives the internal APIs so it stays
deterministic and never touches the real ``~/.bughunt``.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from bughunt_harness.cvss.engine import score_vector
from bughunt_harness.cvss.reasoning import score_with_reasoning
from bughunt_harness.engagement.models import (
    AccountsModel,
    Engagement,
    HeadersModel,
    ProgramModel,
    ReportingModel,
    ROEModel,
    ScopeModel,
    ScopeSet,
)
from bughunt_harness.engagement.workspace import create_workspace, save_engagement
from bughunt_harness.hunt import load_program_context
from bughunt_harness.registry import ProgramRegistry
from bughunt_harness.reporting.poc import PoC, run_poc_qa
from bughunt_harness.reporting.qa import run_qa
from bughunt_harness.reporting.report import ReportData

SLUG = "acme-test"


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"e2e-ok")

    def log_message(self, *args):  # noqa: D102
        pass


def _serve():
    server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _make_program(config) -> str:
    reg = ProgramRegistry(config)
    try:
        record = reg.create(
            slug=SLUG, name="Acme", workspace_path=str(config.programs_dir / SLUG), status="active"
        )
    finally:
        reg.close()
    create_workspace(record, fixture=True)
    # Overwrite the fixture scope with loopback + automation so the broker can
    # roundtrip a *local* mock server (no DNS, no external target).
    save_engagement(
        Path(record.workspace_path),
        Engagement(
            program=ProgramModel(name="Acme", platform="custom", status="active"),
            scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"])),
            roe=ROEModel(automation_allowed=True),
            headers=HeadersModel(),
            accounts=AccountsModel(),
            reporting=ReportingModel(),
        ),
    )
    return record.workspace_path


def test_end_to_end_pipeline(config):
    ws = _make_program(config)

    with load_program_context(SLUG, config) as ctx:
        db = ctx.db
        assert ctx.record.status == "active"
        researcher = db.start_session("pytest", "researcher", SLUG)
        validator = db.start_session("pytest", "finding-validator", SLUG)

        # 1. Broker: in-scope local roundtrip produces durable evidence.
        server = _serve()
        try:
            port = server.server_address[1]
            r = ctx.broker().execute(
                target=f"http://127.0.0.1:{port}/ok", action="read_http",
                session_id=researcher.id,
            )
        finally:
            server.shutdown()
            server.server_close()
        assert r.ok and r.decision == "allow" and r.status_code == 200
        assert "e2e-ok" in r.body_preview
        assert r.evidence_id is not None

        # 2. Lead → hypothesis → controlled test → supports.
        lead = db.add_lead("Loopback endpoint reflects user input", entity="mock", source="recon")
        hyp = db.create_hypothesis(
            "GET /ok returns attacker-controlled header echo", lead_id=lead.id, confidence=0.6
        )
        db.set_hypothesis_status(hyp.id, "testing")
        test = db.add_test(
            hyp.id, "confirm echo", method="broker GET", expected_if_true="reflected", expected_if_false="sanitized"
        )
        executed = db.complete_test(test.id, "body echoes e2e-ok", "supports", evidence_refs=[r.evidence_id])
        assert executed.result == "supports"
        db.set_hypothesis_status(hyp.id, "supported")

        # 3. Finding (candidate) with full provenance linkage (P0.8).
        f = db.create_finding(
            "Reflected input on loopback endpoint",
            affected_target=f"127.0.0.1:{port}",
            category="reflected-output",
            impact_summary="attacker-controlled text is reflected verbatim",
            evidence_refs=[r.evidence_id],
            lead_id=lead.id,
            hypothesis_id=hyp.id,
            test_ids=[test.id],
            creator_session_id=researcher.id,
        )
        assert f.lead_id == lead.id and f.hypothesis_id == hyp.id and f.test_ids == [test.id]

        # 4. Validation-review workflow → validated (P0.7: no direct jump).
        db.transition_finding(f.id, "validation")
        review = db.begin_validation(f.id, requested_by="e2e", reviewer_type="finding-validator")
        checks = {
            "scope_eligible": {"passed": True}, "reproducible": {"passed": True},
            "prerequisites": {"value": "synthetic fixture access"},
            "security_boundary": {"value": "fixture output boundary"},
            "attacker_control": {"value": "request path marker"},
            "demonstrated_impact": {"value": f.impact_summary},
            "intended_behavior": {"passed": True},
            "false_positive_analysis": {"passed": True},
            "evidence_quality": {"passed": True}, "minimal_impact": {"passed": True},
            "program_exclusions": {"passed": True},
        }
        db.submit_validation_review(
            review.id, "supported", reasoning_summary="reproducible from linked evidence",
            check_results=checks, evidence_refs=f.evidence_refs,
            reviewer_role="finding-validator", reviewer_session_id=validator.id,
        )
        validated = db.finalize_validation(
            f.id, scope_engine=ctx.scope, program_active=True,
        )
        assert validated.status == "validated"

        # 5. PoC documentation + validated -> poc_ready.
        poc = PoC(
            prerequisites=["a browser or the harness broker"],
            account_setup="unauthenticated local fixture",
            baseline_behavior="plain 200 response",
            controlled_change="inject marker into target path",
            reproduction_steps=["send GET http://127.0.0.1:<port>/<marker> via broker"],
            observed_result="marker is reflected in the response body",
            impact_verification="reflection demonstrates unescaped output",
        )
        poc_qa = run_poc_qa(poc, evidence_refs=f.evidence_refs, finding_status=validated.status)
        assert poc_qa.passed, poc_qa.issues
        poc_dir = ctx.workspace / "poc"
        poc_dir.mkdir(parents=True, exist_ok=True)
        poc_path = poc_dir / f"{f.public_id}.md"
        poc_path.write_text(poc.render(), encoding="utf-8")
        db.set_finding_poc_path(f.id, str(poc_path))
        poc_ready = db.transition_finding(f.id, "poc_ready")
        assert poc_ready.status == "poc_ready"

        # 6. CVSS scoring + poc_ready -> scored (calculator, not hand arithmetic).
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
        reasoning = {
            metric: {
                "value": value,
                "rationale": f"Fixture evidence supports {metric}={value} without class-based scoring.",
                "evidence_refs": [r.evidence_id],
                "uncertainty": "none",
            }
            for metric, value in (part.split(":", 1) for part in vector.split("/")[1:])
        }
        scored_data = score_with_reasoning(vector, reasoning, finding_evidence=f.evidence_refs)
        db.set_finding_cvss(f.id, scored_data)
        scored = db.transition_finding(f.id, "scored")
        assert scored.status == "scored"

        # 7. Report + deterministic QA passes.
        report = ReportData(
            title="Reflected input on loopback endpoint",
            summary="A loopback endpoint reflects attacker-controlled text without encoding.",
            affected_asset=f"127.0.0.1:{port}",
            weakness="Improper Output Neutralization",
            severity="Low",
            cvss_vector=scored_data["vector"],
            prerequisites=["local synthetic fixture"],
            steps=["Send GET /<marker> to the endpoint via the broker"],
            poc=poc.render(),
            expected_result="marker is encoded or stripped",
            actual_result="marker is reflected verbatim",
            impact="Reflected text may be leveraged for UI redress / injection.",
            evidence=[r.evidence_id],
            remediation="HTML-encode reflected output.",
        )
        qa = run_qa(report, finding_status=scored.status)
        assert qa.passed, [i.code for i in qa.failures]
        rep_dir = ctx.workspace / "reports"
        rep_dir.mkdir(parents=True, exist_ok=True)
        out = rep_dir / f"{scored.public_id}.md"
        out.write_text(report.render(), encoding="utf-8")
        assert out.is_file() and "## Evidence" in out.read_text(encoding="utf-8")
        db.set_finding_report_path(f.id, str(out))
        report_ready = db.transition_finding(f.id, "report_ready")
        qa_passed = db.transition_finding(f.id, "qa_passed")
        assert report_ready.status == "report_ready" and qa_passed.status == "qa_passed"


def test_cli_cvss_smoke(capsys):
    from bughunt_harness.cli import main

    rc = main(["cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
    assert rc == 0
    assert '"severity"' in capsys.readouterr().out


def test_cli_poc_parser_wiring():
    from bughunt_harness.cli import build_parser

    args = build_parser().parse_args(["poc", "--finding", "FIND-001", "-p", SLUG, "--steps", "1. step one"])
    assert args.command == "poc"
    assert args.finding == "FIND-001"
    assert args.program == SLUG
    assert args.steps == "1. step one"
