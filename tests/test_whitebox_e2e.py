"""Local hybrid whitebox→runtime→independent-validation acceptance flow."""

from __future__ import annotations

import subprocess

from bughunt_harness.engagement.models import (
    AccountAuthModel, AccountModel, AccountsModel, AutonomyModel, Engagement,
    ProgramModel, ROEModel, ScopeModel, ScopeSet,
)
from bughunt_harness.engagement.workspace import create_workspace, save_engagement
from bughunt_harness.hunt import load_program_context
from bughunt_harness.recon import run_authorized_recon
from bughunt_harness.registry import ProgramRegistry
from bughunt_harness.source import SourceService
from bughunt_harness.synthetic import SyntheticFixture, run_synthetic_autonomous_hunt


def _git(repo, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
         "-C", str(repo), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def test_whitebox_source_lead_correlates_and_reaches_validated_pipeline(config, tmp_path, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_ACCOUNT_A_COOKIE", "session=synthetic-account-a")
    monkeypatch.setenv("SYNTHETIC_ACCOUNT_B_COOKIE", "session=synthetic-account-b")
    registry = ProgramRegistry(config)
    workspace = config.programs_dir / "whitebox-local"
    record = registry.create(
        slug="whitebox-local", name="Whitebox local", platform="custom",
        workspace_path=str(workspace), status="active",
    )
    registry.close(); create_workspace(record)
    save_engagement(workspace, Engagement(
        program=ProgramModel(name=record.name, status="active"),
        scope=ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"])),
        roe=ROEModel(
            automation_allowed=True, authentication_testing=True, authorization_testing=True,
            active_recon=True, crawling=True,
            max_rps=100.0, max_concurrency=2,
        ),
        accounts=AccountsModel(accounts=[
            AccountModel(id="account_a", role="regular_user", auth=AccountAuthModel(type="cookie", cookie_ref="env:SYNTHETIC_ACCOUNT_A_COOKIE")),
            AccountModel(id="account_b", role="regular_user", auth=AccountAuthModel(type="cookie", cookie_ref="env:SYNTHETIC_ACCOUNT_B_COOKIE")),
        ]),
        autonomy=AutonomyModel(enabled=True, goal="report_ready", max_session_minutes=10, max_total_requests=40, max_leads_per_session=8),
    ))

    repo = tmp_path / "official-api"; repo.mkdir(); _git(repo, "init")
    (repo / "routes.js").write_text(
        "router.delete('/api/orders/:id', requireOwner, deleteOrder);\n"
        + "// unrelated source context\n" * 15
        + "router.get('/api/orders/:id', getOrder);\n",
        encoding="utf-8",
    )
    _git(repo, "add", "."); _git(repo, "commit", "-m", "synthetic source")

    with SyntheticFixture() as fixture:
        with load_program_context("whitebox-local", config, require_active=True) as ctx:
            source = SourceService(ctx)
            registered = source.add_repository(str(repo), "HEAD")
            source.build_context(registered["repository_id"])
            audit = source.audit_authorization_inconsistencies(registered["repository_id"])
            assert audit["lead_ids"] and audit["observations"]

            recon_session = ctx.db.start_session("pytest", "recon-specialist", ctx.slug)
            recon = run_authorized_recon(
                ctx, profile="standard", seeds=[fixture.base_url], session_id=recon_session.id,
                max_results=20, timeout_seconds=10,
            )
            assert recon.ok
            mapped = source.correlate_runtime(registered["repository_id"])
            assert any("/api/orders/" in item["runtime_target"] for item in mapped["mappings"])
            ctx.db.end_session(recon_session.id)

            result = run_synthetic_autonomous_hunt(ctx, fixture.base_url)
            assert result["finding_status"] == "qa_passed"
            finding = ctx.db.get_finding(int(result["finding"].split("-")[1]))
            review = ctx.db.latest_validation_review(finding.id)
            assert review and review.verdict == "supported"
            assert review.reviewer_session_id != finding.creator_session_id
            assert ctx.db.list_source_runtime_mappings(registered["id"])
