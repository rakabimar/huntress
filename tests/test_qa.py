"""Report QA tests (deterministic report gate)."""

from bughunt_harness.reporting import ReportData, run_qa


def _complete_report(**overrides):
    base = dict(
        title="Open redirect on https://example.test/logout",
        summary="The logout endpoint reflects the next parameter into Location without validation.",
        affected_asset="https://example.test/logout",
        weakness="URL Redirection to Untrusted Site",
        cwe="CWE-601",
        severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        prerequisites=["No account required"],
        steps=["1. Request /logout?next=https://evil.example"],
        poc="GET /logout?next=https://evil.example -> 302 Location: https://evil.example",
        expected_result="Redirect restricted to same-origin destinations",
        actual_result="302 redirect to arbitrary third-party URL",
        impact="An attacker can phish users by redirecting them to a hostile site.",
        evidence=["EVD-001 request response"],
        remediation="Validate next against an allowlist of internal paths.",
    )
    base.update(overrides)
    return ReportData(**base)


def test_complete_report_passes():
    r = run_qa(_complete_report(), finding_status="validated")
    assert r.passed
    assert r.failures == []


def test_missing_evidence_fails():
    r = run_qa(_complete_report(evidence=[]))
    assert not r.passed
    codes = {i.code for i in r.failures}
    assert "missing_evidence" in codes


def test_missing_poc_fails():
    r = run_qa(_complete_report(poc=""))
    assert not r.passed
    assert any(i.code == "missing_poc" for i in r.failures)


def test_destructive_poc_fails():
    r = run_qa(_complete_report(poc="DROP TABLE users; then rm -rf /var/www"))
    assert not r.passed
    assert any(i.code == "destructive_poc" for i in r.failures)


def test_secret_in_report_fails():
    r = run_qa(_complete_report(summary="auth_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc"))
    assert not r.passed
    assert any(i.code == "secret_in_report" for i in r.failures)


def test_premature_report_fails():
    r = run_qa(_complete_report(), finding_status="candidate")
    assert not r.passed
    assert any(i.code == "premature_report" for i in r.failures)


def test_bare_impact_label_fails():
    r = run_qa(_complete_report(impact="High"))
    assert not r.passed
    assert any(i.code == "unsupported_impact" for i in r.failures)


def test_render_separates_facts_from_interpretation():
    report = _complete_report(interpretation=["The bug likely also affects /login."])
    rendered = report.render()
    assert "## Interpretation" in rendered
    assert "demonstrated" in rendered
