"""Program-context / workspace loading tests (authorization-first wiring)."""

import pytest

from bughunt_harness.config import HarnessConfig
from bughunt_harness.engagement.models import ScopeModel, ScopeSet
from bughunt_harness.engagement.workspace import (
    create_workspace,
    load_engagement,
    slug_ok,
    workspace_path_for,
)
from bughunt_harness.errors import EngagementValidationError, ProgramInactiveError, ProgramNotActiveError
from bughunt_harness.hunt import load_program_context, resolve_program_slug
from bughunt_harness.registry import ProgramRegistry


def _make_program(cfg, slug="acme-test"):
    reg = ProgramRegistry(cfg)
    try:
        record = reg.create(
            slug=slug, name="Acme", workspace_path=str(cfg.programs_dir / slug)
        )
    finally:
        reg.close()
    ws = create_workspace(record, fixture=True)
    return record, ws


def test_create_and_load_engagement(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    _record, ws = _make_program(cfg)
    eng = load_engagement(ws)
    assert eng.scope.has_includes
    assert eng.program.platform.value == "custom"


def test_load_program_context_end_to_end(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    _record, _ws = _make_program(cfg)
    with load_program_context("acme-test", config=cfg) as ctx:
        assert ctx.slug == "acme-test"
        assert ctx.engagement.scope.has_includes
        assert ctx.scope.check("https://example.test").allowed
        assert ctx.policy.check("analyze").allowed


def test_resolve_program_slug_requires_active(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    with pytest.raises(ProgramNotActiveError):
        resolve_program_slug(None, config=cfg)
    assert resolve_program_slug("explicit-slug", config=cfg) == "explicit-slug"


def test_slug_validation():
    assert slug_ok("acme-test")
    assert not slug_ok("UPPER")
    assert not slug_ok("a")  # too short
    assert not slug_ok(" leading-dash")
    with pytest.raises(Exception):
        workspace_path_for("!bad slug!")


def test_create_workspace_reflects_record_metadata(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    reg = ProgramRegistry(cfg)
    try:
        record = reg.create(
            slug="acme-test", name="Acme Corp", platform="hackerone",
            program_url="https://hackerone.com/acme",
            workspace_path=str(cfg.programs_dir / "acme-test"), notes="n1",
        )
    finally:
        reg.close()
    ws = create_workspace(record, fixture=True)
    eng = load_engagement(ws)
    # program.yaml mirrors the registry record (P0.1 single source of truth).
    assert eng.program.name == "Acme Corp"
    assert eng.program.platform.value == "hackerone"
    assert eng.program.program_url == "https://hackerone.com/acme"
    assert eng.program.status == "paused"
    assert eng.program.notes == "n1"
    # fixture scope is explicitly synthetic (P0.2).
    assert eng.scope.include.domains == ["example.test"]


def test_create_workspace_normal_has_empty_scope(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    reg = ProgramRegistry(cfg)
    try:
        record = reg.create(
            slug="acme-test", name="Acme",
            workspace_path=str(cfg.programs_dir / "acme-test"),
        )
    finally:
        reg.close()
    ws = create_workspace(record)  # no --fixture -> empty scope (P0.2)
    with pytest.raises(EngagementValidationError):
        load_engagement(ws)


def test_scope_set_has_entries_vs_bool():
    # P0.3: emptiness is judged by has_entries(), not bool(self).
    assert not ScopeSet().has_entries()
    assert bool(ScopeSet())  # a ScopeSet is always truthy — the old bug
    assert ScopeSet(domains=["example.test"]).has_entries()
    assert ScopeSet(wildcards=["*.example.test"]).has_entries()
    with pytest.raises(ValueError):
        ScopeModel.model_validate({"include": {}, "exclude": {}})


def test_scope_set_included_hosts_egress_allowlist():
    # P0.11: included_hosts() yields the runtime egress allowlist — normalized,
    # deduplicated host selectors with wildcards + URL hosts, CIDR omitted.
    s = ScopeSet(
        domains=["Api.Example.COM"],
        wildcards=["*.example.com"],
        subdomains=["sub.example.com"],
        urls=["https://Docs.Example.com/ref"],
        ipv4=["192.0.2.10", "192.0.2.10"],  # dup normalized out
        cidr=["192.0.2.0/24"],  # not expressible as a domain -> omitted
    )
    hosts = s.included_hosts()
    assert hosts == [
        "api.example.com",
        "sub.example.com",
        "*.example.com",
        "192.0.2.10",
        "docs.example.com",
    ]
    assert "192.0.2.0/24" not in hosts
    assert ScopeSet().included_hosts() == []


def _make_scoped_program(cfg, slug="acme-test", status="paused"):
    reg = ProgramRegistry(cfg)
    try:
        record = reg.create(
            slug=slug, name="Acme", workspace_path=str(cfg.programs_dir / slug), status=status
        )
    finally:
        reg.close()
    create_workspace(record, fixture=True)
    return record


def test_load_program_context_require_active_blocks_paused(tmp_path):
    from bughunt_harness.hunt import load_program_context

    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    _make_scoped_program(cfg, status="paused")
    with pytest.raises(ProgramInactiveError):
        load_program_context("acme-test", config=cfg, require_active=True)
    # Without require_active, read-only context still loads.
    with load_program_context("acme-test", config=cfg) as ctx:
        assert ctx.record.status == "paused"


def test_load_program_context_require_active_allows_active(tmp_path):
    from bughunt_harness.hunt import load_program_context

    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    _make_scoped_program(cfg, status="active")
    with load_program_context("acme-test", config=cfg, require_active=True) as ctx:
        assert ctx.record.status == "active"


def test_broker_blocks_inactive_program(tmp_path):
    from bughunt_harness.hunt import load_program_context
    from bughunt_harness.requests.broker import RequestBroker

    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    _make_scoped_program(cfg, status="paused")
    with load_program_context("acme-test", config=cfg) as ctx:
        b = RequestBroker(
            ctx.engagement, program_slug="acme-test", workspace=ctx.workspace,
            hunt_db=ctx.db, secrets=ctx.secrets, program_status="paused",
        )
        r = b.execute(target="https://example.test", action="read_http")
    assert not r.ok
    assert r.decision == "deny"
    assert "active" in r.reason