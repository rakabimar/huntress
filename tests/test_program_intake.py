"""Offline program-intake authorization, approval, and refresh regressions."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from bughunt_harness.engagement.workspace import load_engagement, write_program_status
from bughunt_harness.errors import ProgramIntakeError
from bughunt_harness.hunt import load_program_context
from bughunt_harness.program_intake.adapters.base import detect_platform
from bughunt_harness.program_intake.adapters.hackerone import HackerOneAdapter
from bughunt_harness.program_intake.adapters.bugcrowd import BugcrowdAdapter
from bughunt_harness.program_intake.adapters.generic import GenericAdapter
from bughunt_harness.program_intake.adapters.intigriti import IntigritiAdapter
from bughunt_harness.program_intake.fetcher import IntakeFetcher
from bughunt_harness.program_intake.models import RuleStatus
from bughunt_harness.program_intake.normalizer import classify_selector
from bughunt_harness.program_intake.policy_parser import parse_policy
from bughunt_harness.program_intake.service import ProgramIntakeService
from bughunt_harness.program_intake.provenance import SnapshotWriter
from bughunt_harness.registry import ProgramRegistry

FIXTURES = Path(__file__).parent / "fixtures" / "program_intake"


def _import_and_approve(config):
    service = ProgramIntakeService(config)
    result = service.import_program(
        platform="hackerone", handle="acme",
        from_file=FIXTURES / "hackerone" / "import.json",
    )
    ambiguities = service.ambiguities("acme")
    header = next(item for item in ambiguities if item["category"] == "REQUIRED_HEADER_VALUE_MISSING")
    service.resolve_ambiguity("acme", header["public_id"], value={"X-Researcher": "researcher-fixture"})
    approved = service.approve("acme", approved_by="pytest-human", actor_kind="human")
    return service, result, approved


def test_platform_detection_and_hackerone_handle_validation():
    assert detect_platform("https://hackerone.com/acme") == "hackerone"
    assert detect_platform("https://bugcrowd.com/acme") == "bugcrowd"
    assert HackerOneAdapter().resolve_handle(handle=None, url="https://hackerone.com/acme") == "acme"
    with pytest.raises(ValueError):
        HackerOneAdapter().resolve_handle(handle="acme", url="https://attacker.example/acme")


def test_scope_normalization_preserves_wildcards_and_paths():
    selector, kind, _ = classify_selector("*.example.test", "WILDCARD")
    assert selector == "*.example.test"
    assert kind == "wildcard"
    selector, kind, _ = classify_selector("https://example.test/api/*", "URL")
    assert selector == "https://example.test/api/"
    assert kind == "path_url"
    assert classify_selector("com.example.app", "ANDROID")[0] is None


def test_policy_parser_separates_conditional_automation_and_numeric_unknown():
    rules, _headers, accounts = parse_policy(
        "Automated scanners are allowed as long as they do not cause excessive traffic. "
        "Do not perform denial of service. Only test accounts you own.",
        import_id="IMPORT-001", source_id="policy:test",
    )
    by_key = {rule.key: rule for rule in rules}
    assert by_key["automated_scanning"].status == RuleStatus.CONDITIONAL
    assert by_key["denial_of_service"].status == RuleStatus.PROHIBITED
    assert "rate_limits" not in by_key
    assert accounts.testing_other_real_users == RuleStatus.PROHIBITED


def test_malicious_policy_is_data_and_cannot_expand_scope():
    policy = (FIXTURES / "generic" / "policy.md").read_text(encoding="utf-8")
    rules, _, _ = parse_policy(policy, import_id="IMPORT-001", source_id="policy:test")
    assert all(rule.key != "scope" for rule in rules)
    assert next(rule for rule in rules if rule.key == "denial_of_service").status == RuleStatus.PROHIBITED


def test_hackerone_fixture_import_review_approval_and_scope(config):
    service, result, approved = _import_and_approve(config)
    assert result["review"]["scope"]["total"] == 4
    assert result["review"]["scope"]["bounty_eligible"] == 2
    assert approved["status"] == "VALIDATED"
    workspace = config.programs_dir / "acme"
    assert (workspace / "intake" / result["import_id"] / "manifest.json").is_file()
    assert (workspace / "intake" / result["import_id"] / "provenance.json").is_file()
    engagement = load_engagement(workspace)
    assert engagement.scope.include.domains == ["api-old.example.test"]
    assert engagement.scope.include.path_urls == ["https://www.example.test/api/"]
    assert "admin.example.test" in engagement.scope.exclude.domains
    assert engagement.headers.headers[0].value == "researcher-fixture"
    service.assert_activation_ready("acme")


def test_nonhuman_approval_is_refused(config):
    service = ProgramIntakeService(config)
    service.import_program(platform="hackerone", handle="acme",
                           from_file=FIXTURES / "hackerone" / "import.json")
    header = next(item for item in service.ambiguities("acme") if item["category"] == "REQUIRED_HEADER_VALUE_MISSING")
    service.resolve_ambiguity("acme", header["public_id"], value={"X-Researcher": "fixture"})
    with pytest.raises(PermissionError):
        service.approve("acme", approved_by="agent", actor_kind="agent")


def test_approval_hash_invalidates_after_scope_edit(config):
    service, _result, _approved = _import_and_approve(config)
    path = config.programs_dir / "acme" / "scope.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["include"]["domains"].append("tampered.example.test")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ProgramIntakeError, match="scope_hash"):
        service.assert_activation_ready("acme")


def test_refresh_restricts_now_and_does_not_expand(config):
    service, _result, _approved = _import_and_approve(config)
    registry = ProgramRegistry(config)
    try:
        registry.set_status("acme", "active")
        record = registry.get("acme")
    finally:
        registry.close()
    write_program_status(record)
    service.mark_active("acme")

    refreshed = service.refresh("acme", from_file=FIXTURES / "hackerone" / "refresh.json")
    assert refreshed["review"]["refresh"]["result"] == "CHANGE_REVIEW_REQUIRED"
    assert refreshed["review"]["refresh"]["restrictive"]
    assert refreshed["review"]["refresh"]["permissive"]
    from bughunt_harness.errors import ProgramInactiveError
    with pytest.raises(ProgramInactiveError):
        load_program_context("acme", config, require_active=True)
    with load_program_context("acme", config) as ctx:
        assert not ctx.scope.check("api-old.example.test").allowed
        assert not ctx.scope.check("new.example.test").allowed
        assert not ctx.engagement.roe.race_conditions


def test_submission_and_bounty_eligibility_remain_distinct(config):
    service = ProgramIntakeService(config)
    service.import_program(platform="hackerone", handle="acme",
                           from_file=FIXTURES / "hackerone" / "import.json")
    provenance = json.loads((config.programs_dir / "acme" / "intake" / "IMPORT-001" /
                             "normalized_draft.json").read_text(encoding="utf-8"))
    accepted_no_bounty = next(item for item in provenance["scope_entries"]
                              if item["asset_identifier"].startswith("https://www"))
    assert accepted_no_bounty["testing_allowed"] is True
    assert accepted_no_bounty["submission_eligible"] is True
    assert accepted_no_bounty["bounty_eligible"] is False


class _Response:
    def __init__(self, status, payload, headers=None):
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.headers = headers or {}


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_fetcher_pagination_and_bounded_429_retry(monkeypatch):
    session = _Session([
        _Response(429, {}, {"Retry-After": "0"}),
        _Response(200, {"data": [{"id": "1"}], "links": {"next": "https://api.hackerone.com/page2"}}),
        _Response(200, {"data": [{"id": "2"}], "links": {}}),
    ])
    monkeypatch.setattr("bughunt_harness.program_intake.fetcher.time.sleep", lambda _seconds: None)
    fetcher = IntakeFetcher({"api.hackerone.com"}, session=session,
                            requests_per_minute=10_000_000, max_attempts=3)
    pages = fetcher.json_pages("https://api.hackerone.com/page1")
    assert [page.json()["data"][0]["id"] for page in pages] == ["1", "2"]
    assert len(session.calls) == 3


def test_fetcher_uses_etag_cache_for_304(monkeypatch):
    session = _Session([_Response(304, {}, {"ETag": "v1"})])
    monkeypatch.setattr("bughunt_harness.program_intake.fetcher.time.sleep", lambda _seconds: None)
    fetcher = IntakeFetcher({"api.hackerone.com"}, session=session,
                            requests_per_minute=10_000_000)
    body = b'{"data":{"id":"42"}}'
    fetcher.prime_cache("https://api.hackerone.com/program", body, etag="v1")
    result = fetcher.get("https://api.hackerone.com/program")
    assert result.status_code == 304
    assert result.body == body
    assert session.calls[0][1]["headers"]["If-None-Match"] == "v1"


def test_generic_url_requires_explicit_confirmation(config):
    service = ProgramIntakeService(config)
    with pytest.raises(ProgramIntakeError, match="confirm-generic-url"):
        service.import_program(platform="generic", url="https://example.test/policy")


def test_mcp_intake_surface_cannot_approve_activate_or_resolve():
    from bughunt_harness.mcp.server import tool_names_for_role
    tools = tool_names_for_role("orchestrator")
    assert {"get_program_intake_status", "get_program_review_summary",
            "list_program_ambiguities", "refresh_program_intake"} <= tools
    assert "approve_program_import" not in tools
    assert "activate_program" not in tools
    assert "resolve_program_ambiguity" not in tools


@pytest.mark.parametrize(
    ("adapter", "fixture", "expected_scope"),
    [
        (BugcrowdAdapter(), "bugcrowd/program.json", "api.example.test"),
        (IntigritiAdapter(), "intigriti/program.json", "api.example.test"),
        (GenericAdapter(), "generic/program.json", "*.example.test"),
    ],
)
def test_platform_fixture_adapters_are_structured_and_offline(tmp_path, adapter, fixture, expected_scope):
    workspace = tmp_path / "program"
    snapshot = SnapshotWriter(workspace, "IMPORT-001")
    payload = adapter.fetch(
        handle="acme", url=None,
        fetcher=IntakeFetcher(adapter.official_hosts or {"example.test"}),
        snapshot=snapshot, credential=None, from_file=FIXTURES / fixture,
    )
    assert payload.scopes
    assert payload.scopes[0]["attributes"]["asset_identifier"] == expected_scope
    assert snapshot.sources


def test_conflicting_structured_instruction_creates_critical_ambiguity(config):
    service = ProgramIntakeService(config)
    service.import_program(
        platform="generic", handle="conflict",
        from_file=FIXTURES / "malformed" / "conflict.json",
    )
    categories = {item["category"]: item["severity"] for item in service.ambiguities("conflict")}
    assert categories["STRUCTURED_POLICY_CONFLICT"] == "CRITICAL"


def test_missing_referenced_policy_document_is_critical(config, tmp_path):
    fixture = tmp_path / "linked.json"
    fixture.write_text(json.dumps({
        "program": {"name": "Linked", "handle": "linked", "submission_state": "open",
                    "policy": "Follow https://official.example.test/Rules.pdf"},
        "scopes": [{"asset_identifier": "api.example.test", "asset_type": "DOMAIN",
                    "eligible_for_submission": True, "eligible_for_bounty": False}],
    }), encoding="utf-8")
    service = ProgramIntakeService(config)
    service.import_program(platform="generic", handle="linked", from_file=fixture)
    assert any(item["category"] == "MISSING_REFERENCED_POLICY_DOCUMENT" and item["severity"] == "CRITICAL"
               for item in service.ambiguities("linked"))


def test_platform_credential_listing_never_returns_values(config, monkeypatch):
    from bughunt_harness.program_intake.credentials import PlatformCredentialStore
    monkeypatch.setenv("FIXTURE_H1_USER", "researcher")
    monkeypatch.setenv("FIXTURE_H1_TOKEN", "top-secret-token")
    store = PlatformCredentialStore(config)
    store.add("hackerone", "main", username_ref="env:FIXTURE_H1_USER",
              token_ref="env:FIXTURE_H1_TOKEN")
    rendered = json.dumps(store.list_safe())
    assert "top-secret-token" not in rendered
    assert "[REDACTED]" in rendered


def test_closed_program_refresh_blocks_immediately(config, tmp_path):
    service, _result, _approved = _import_and_approve(config)
    registry = ProgramRegistry(config)
    try:
        registry.set_status("acme", "active")
        write_program_status(registry.get("acme"))
    finally:
        registry.close()
    service.mark_active("acme")
    closed = json.loads((FIXTURES / "hackerone" / "import.json").read_text(encoding="utf-8"))
    closed["program"]["data"]["attributes"]["submission_state"] = "closed"
    fixture = tmp_path / "closed.json"
    fixture.write_text(json.dumps(closed), encoding="utf-8")
    refreshed = service.refresh("acme", from_file=fixture)
    kinds = {item["change_type"] for item in refreshed["review"]["refresh"]["restrictive"]}
    assert "PROGRAM_CLOSED" in kinds
    from bughunt_harness.errors import ProgramInactiveError
    with pytest.raises(ProgramInactiveError):
        load_program_context("acme", config, require_active=True)


def test_llm_policy_proposals_only_fill_unresolved_rules_and_cannot_approve():
    seen = {}

    def proposal(prompt):
        seen["prompt"] = prompt
        return {"rules": [
            {"key": "denial_of_service", "status": "ALLOWED", "confidence": 0.99,
             "source_excerpt": "Do not perform denial of service.", "note": "conflicts"},
            {"key": "api_testing", "status": "CONDITIONAL", "confidence": 0.7,
             "source_excerpt": "API review is permitted for owned accounts.", "condition": "owned accounts"},
            {"key": "not_a_policy_key", "status": "ALLOWED", "confidence": 1.0,
             "source_excerpt": "invented"},
        ]}

    rules, _headers, _accounts = parse_policy(
        "Do not perform denial of service. API review is permitted for owned accounts.",
        import_id="IMPORT-001", source_id="official:policy", llm_extract=proposal,
    )
    by_key = {item.key: item for item in rules}
    assert by_key["denial_of_service"].status == RuleStatus.PROHIBITED
    assert by_key["api_testing"].explicit is False
    assert by_key["api_testing"].provenance.source_id == "official:policy"
    assert "not_a_policy_key" not in by_key
    assert "cannot authorize testing" in seen["prompt"]


def test_official_source_asset_creates_proposal_without_clone(config, tmp_path):
    fixture = tmp_path / "source-program.json"
    fixture.write_text(json.dumps({
        "program": {"name": "Source", "handle": "source-program", "submission_state": "open",
                    "policy": "Do not perform denial of service."},
        "scopes": [{"asset_identifier": "https://github.com/acme/official-project",
                    "asset_type": "SOURCE_CODE", "eligible_for_submission": True,
                    "eligible_for_bounty": True}],
    }), encoding="utf-8")
    result = ProgramIntakeService(config).import_program(
        platform="generic", handle="source-program", from_file=fixture,
    )
    workspace = config.programs_dir / result["program"]
    draft = json.loads((workspace / "intake" / result["import_id"] / "normalized_draft.json").read_text(encoding="utf-8"))
    proposal = draft["reward_metadata"]["source_repository_proposals"][0]
    assert proposal["status"] == "PROPOSED"
    assert proposal["registration_requires_human_approval"] is True
    assert proposal["automatic_clone"] is False
    assert not (workspace / "source" / "repositories").exists()


def test_refresh_reuses_local_header_value_and_preserves_accounts(config):
    service, _result, _approved = _import_and_approve(config)
    workspace = config.programs_dir / "acme"
    accounts_path = workspace / "accounts.yaml"
    accounts = yaml.safe_load(accounts_path.read_text(encoding="utf-8"))
    accounts["accounts"][0]["secret_ref"] = "env:ACME_ACCOUNT_A"
    accounts_path.write_text(yaml.safe_dump(accounts, sort_keys=False), encoding="utf-8")
    service.refresh("acme", from_file=FIXTURES / "hackerone" / "refresh.json")
    assert not any(item["category"] == "REQUIRED_HEADER_VALUE_MISSING" and item["status"] == "OPEN"
                   for item in service.ambiguities("acme"))
    service.approve("acme", approved_by="pytest-human", actor_kind="human")
    engagement = load_engagement(workspace)
    assert engagement.accounts.accounts[0].secret_ref == "env:ACME_ACCOUNT_A"
    assert engagement.headers.by_name()["x-researcher"].value == "researcher-fixture"


def test_doctor_reports_import_provenance_and_approval(config, monkeypatch):
    from bughunt_harness import config as config_module
    from bughunt_harness.doctor import run_doctor
    monkeypatch.setattr(config_module, "_default_config", config)
    _import_and_approve(config)
    report = run_doctor("acme")
    checks = {item.name: item for item in report.checks}
    for name in ("intake_source", "intake_freshness", "scope_roe_provenance",
                 "intake_critical_ambiguities", "intake_approval"):
        assert checks[name].status == "ok", checks[name].detail
