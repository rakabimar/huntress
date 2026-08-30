"""Strongest acceptance test: a complete localhost-only autonomous hunt."""

import time

from bughunt_harness.engagement.models import (
    AccountAuthModel,
    AccountModel,
    AccountsModel,
    AutonomyModel,
    Engagement,
    ProgramModel,
    ROEModel,
    ScopeModel,
    ScopeSet,
)
from bughunt_harness.engagement.workspace import create_workspace, save_engagement
from bughunt_harness.hunt import load_program_context
from bughunt_harness.registry import ProgramRegistry
from bughunt_harness.recon import run_authorized_recon
from bughunt_harness.synthetic import SyntheticFixture, run_synthetic_autonomous_hunt


def test_standard_recon_profile_is_bounded_and_useful_on_loopback(config):
    registry = ProgramRegistry(config)
    workspace = config.programs_dir / "local-recon-profile"
    record = registry.create(
        slug="local-recon-profile", name="Local recon profile", platform="custom",
        workspace_path=str(workspace), status="active",
    )
    registry.close()
    create_workspace(record)
    with SyntheticFixture() as fixture:
        engagement = Engagement(
            program=ProgramModel(name=record.name, status="active"),
            scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"], urls=[fixture.base_url])),
            roe=ROEModel(
                automation_allowed=True, active_recon=True, crawling=True,
                max_rps=20.0, max_concurrency=2,
            ),
        )
        save_engagement(workspace, engagement)
        with load_program_context("local-recon-profile", config, require_active=True) as ctx:
            session = ctx.db.start_session("pytest", "orchestrator", ctx.slug)
            started = time.monotonic()
            result = run_authorized_recon(
                ctx, profile="standard", session_id=session.id,
                max_results=30, timeout_seconds=10,
            )
            assert time.monotonic() - started < 15
            assert result.ok and result.leads
            assert ctx.db.get_recon_run(1)["status"] in {"completed", "partial"}
            order = next(
                endpoint for endpoint in ctx.db.list_endpoints()
                if endpoint["normalized_path"] == "/api/orders/{id}"
            )
            assert order["metadata"]["observed_url"].startswith(fixture.base_url)


def test_full_localhost_autonomous_hunt(config, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_ACCOUNT_A_COOKIE", "session=synthetic-account-a")
    monkeypatch.setenv("SYNTHETIC_ACCOUNT_B_COOKIE", "session=synthetic-account-b")
    registry = ProgramRegistry(config)
    workspace = config.programs_dir / "local-test"
    record = registry.create(
        slug="local-test", name="Local synthetic acceptance", platform="custom",
        workspace_path=str(workspace), status="active",
    )
    registry.close()
    create_workspace(record)
    engagement = Engagement(
        program=ProgramModel(name=record.name, status="active"),
        scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"])),
        roe=ROEModel(
            automation_allowed=True,
            authentication_testing=True,
            authorization_testing=True,
            active_recon=True,
            max_rps=100.0,
            max_concurrency=2,
        ),
        accounts=AccountsModel(accounts=[
            AccountModel(
                id="account_a", role="regular_user",
                auth=AccountAuthModel(
                    type="cookie", cookie_ref="env:SYNTHETIC_ACCOUNT_A_COOKIE",
                ),
            ),
            AccountModel(
                id="account_b", role="regular_user",
                auth=AccountAuthModel(
                    type="cookie", cookie_ref="env:SYNTHETIC_ACCOUNT_B_COOKIE",
                ),
            ),
        ]),
        autonomy=AutonomyModel(
            enabled=True, goal="report_ready", max_session_minutes=10,
            max_total_requests=30, max_leads_per_session=5,
        ),
    )
    save_engagement(workspace, engagement)

    with SyntheticFixture() as fixture:
        with load_program_context("local-test", config, require_active=True) as ctx:
            result = run_synthetic_autonomous_hunt(ctx, fixture.base_url)
            assert result["finding_status"] == "qa_passed"
            assert result["autonomy"]["mode"] == "STOP"
            assert result["autonomy"]["reason"] == "goal_reached"
            assert ctx.db.latest_checkpoint().autonomy_state["status"] == "running"
            hypotheses = ctx.db.list_hypotheses()
            assert any(h.status == "rejected" for h in hypotheses)
            assert any(h.status == "supported" for h in hypotheses)
            # Brokered recon + rejected admin probe + paired A/B requests.
            assert len(ctx.db.list_request_records()) == 4
            finding = ctx.db.list_findings()[0]
            assert finding.evidence_refs
            assert finding.test_ids
