"""Synthetic/offline tests for persistent recon intelligence."""

from __future__ import annotations

from types import SimpleNamespace

from bughunt_harness.engagement.models import Engagement, ProgramModel, ROEModel, ScopeModel, ScopeSet
from bughunt_harness.integrations.burp import scope_filter_burp_result
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.recon import (
    classify_parameter,
    derive_passive_discovery_seeds,
    extract_js_signals,
    extract_html_forms,
    ingest_burp_recon,
    ingest_burp_websocket_recon,
    ingest_openapi_document,
    normalize_endpoint_path,
    normalize_host,
    normalize_url,
    parse_dnsx_line,
    parse_httpx_line,
    parse_katana_line,
    run_authorized_recon,
    score_endpoint,
)
from bughunt_harness.scope.engine import ScopeEngine


def _ctx(db, tmp_path, *, wildcard=True, active=False, crawl=False):
    scope = ScopeModel(include=ScopeSet(wildcards=["*.example.test"] if wildcard else [], domains=[] if wildcard else ["example.test"]))
    roe = ROEModel(automation_allowed=True, active_recon=active, crawling=crawl)
    engagement = Engagement(program=ProgramModel(name="fixture", status="active"), scope=scope, roe=roe)
    return SimpleNamespace(
        slug="acme-test", db=db, workspace=tmp_path, engagement=engagement,
        scope=ScopeEngine(scope), policy=PolicyEngine(scope, roe),
        record=SimpleNamespace(status="active"),
    )


def _detected(*available):
    names = ("subfinder", "assetfinder", "amass", "dnsx", "httpx", "gau", "waybackurls", "katana", "nuclei", "ffuf", "naabu", "nmap")
    return {name: {"available": name in available, "version": "fixture"} for name in names}


def test_normalization_parameter_shapes_and_js():
    assert normalize_host("Täst.Example.TEST.") == "xn--tst-qla.example.test"
    first = normalize_url("HTTPS://API.Example.Test:443/users?id=1&id=2#frag")
    second = normalize_url("https://api.example.test/users?id=99")
    assert first["url"] == second["url"] == "https://api.example.test/users?id="
    assert normalize_url("https://api.example.test/a/../users#x")["path"] == "/users"
    assert normalize_endpoint_path("/orders/123")[0] == "/orders/123"
    assert normalize_endpoint_path("/orders/550e8400-e29b-41d4-a716-446655440000")[0] == "/orders/{id}"
    assert classify_parameter("order_id", "query")["object_identifier_candidate"]
    assert "redirect" in classify_parameter("callback_url", "query")["metadata"]["categories"]
    signals = extract_js_signals('fetch("/api/hidden?order_id="); new WebSocket("wss://api.example.test/ws")', "https://api.example.test/app.js")
    assert any("/api/hidden" in url for url in signals["urls"])
    assert signals["websockets"] == ["wss://api.example.test/ws"]
    assert extract_html_forms('<form action="/upload" method="post"><input name="file"><input name="order_id"></form>', "https://api.example.test")[0]["parameter_names"] == ["file", "order_id"]


def test_passive_seed_does_not_weaken_active_scope():
    model = ScopeModel(include=ScopeSet(wildcards=["*.example.test"]))
    engine = ScopeEngine(model)
    assert derive_passive_discovery_seeds(model) == ["example.test"]
    assert not engine.check("https://example.test").allowed
    assert engine.check("https://api.example.test").allowed


def test_explicit_passive_seed_must_derive_from_scope(db, tmp_path, monkeypatch):
    ctx = _ctx(db, tmp_path)
    session = db.start_session("test", "recon-executor", "acme-test")
    monkeypatch.setattr("bughunt_harness.recon.detect_recon_tools", lambda: _detected())
    root = run_authorized_recon(ctx, stage="passive", seeds=["example.test"], session_id=session.id)
    unrelated = run_authorized_recon(ctx, stage="passive", seeds=["unrelated.test"], session_id=session.id)
    assert root.ok and root.reason == "partial"
    assert not unrelated.ok and unrelated.mode == "DENY"


def test_multi_source_passive_correlates_and_is_incremental(db, tmp_path, monkeypatch):
    ctx = _ctx(db, tmp_path)
    session = db.start_session("test", "recon-executor", "acme-test")
    monkeypatch.setattr("bughunt_harness.recon.detect_recon_tools", lambda: _detected("subfinder", "assetfinder", "amass"))
    monkeypatch.setattr("bughunt_harness.recon._run_tool", lambda *a, **k: {"argv": list(a[0]), "exit_code": 0, "lines": ["api.example.test"], "stderr": "", "partial": False})
    first = run_authorized_recon(ctx, stage="passive", seeds=[], session_id=session.id)
    second = run_authorized_recon(ctx, stage="passive", seeds=[], session_id=session.id)
    hosts = db.list_assets(type="host")
    assert first.ok and second.ok and len(hosts) == 1
    assert hosts[0]["observation_count"] == 6
    assert {o["source_tool"] for o in db.list_asset_observations(asset_id=hosts[0]["id"])} == {"subfinder", "assetfinder", "amass"}
    assert second.counts["new_asset_count"] == 0


def test_parsers_and_deterministic_interest_score():
    assert parse_dnsx_line('{"host":"api.example.test","a":["127.0.0.1"],"cname":[]}')["status"] == "resolved"
    assert parse_httpx_line('{"url":"https://api.example.test","status_code":200,"tech":["FastAPI"]}')["technologies"] == ["FastAPI"]
    assert parse_katana_line('{"request":{"endpoint":"https://api.example.test/api/orders/123","method":"PATCH"}}')["method"] == "PATCH"
    endpoint = {"normalized_path": "/api/orders/{id}", "method": "PATCH", "content_type": "application/json", "auth_observed": True, "metadata": {}}
    score, reasons, skills, specialist = score_endpoint(endpoint, [classify_parameter("order_id", "path")])
    assert score >= 70 and "object identifier parameter" in reasons
    assert "api-authorization" in skills and specialist == "api-authz-specialist"


def test_burp_owner_scope_ignores_response_body_urls_and_redacts(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    run = db.start_recon_run(stage="burp")
    raw = "GET /api/orders/123?id=9 HTTP/1.1\r\nHost: api.example.test\r\nCookie: session=very-secret\r\nContent-Type: application/json\r\n\r\n{\"order_id\":123,\"docs\":\"https://third-party.invalid/x\"}"
    filtered = scope_filter_burp_result({"content": [{"type": "text", "text": raw}]}, ctx.scope)
    assert filtered["filtered_items"] == 0
    assert "very-secret" not in filtered["content"][0]["text"]
    stats = ingest_burp_recon(ctx, filtered, recon_run_id=run["id"], auth_context="account_a")
    assert stats["new_endpoints"] == 1
    endpoint = db.list_endpoints()[0]
    assert endpoint["auth_observed"] and endpoint["normalized_path"] == "/api/orders/123"
    names = {p["name"] for p in db.list_endpoint_parameters(endpoint["id"])}
    assert {"id", "order_id"} <= names
    assert "very-secret" not in str(db.list_assets()) + str(db.list_endpoint_parameters())


def test_burp_websocket_ingestion_persists_shape_not_message_values(db, tmp_path):
    ctx = _ctx(db, tmp_path)
    run = db.start_recon_run(stage="burp")
    stats = ingest_burp_websocket_recon(
        ctx,
        [{"url": "wss://api.example.test/socket", "direction": "client_to_server", "message": '{"order_id":123,"token":"very-secret"}'}],
        recon_run_id=run["id"], auth_context="account_a",
    )

    assert stats["websockets_observed"] == 1
    endpoint = db.list_endpoints()[0]
    assert endpoint["metadata"]["websocket"] is True
    assert endpoint["metadata"]["message_keys"] == ["order_id", "token"]
    assert "very-secret" not in str(endpoint)


def test_url_path_scope_can_inventory_host_without_granting_host_authority(db, tmp_path):
    scope = ScopeModel(include=ScopeSet(path_urls=["https://example.test/allowed/"]))
    roe = ROEModel()
    engagement = Engagement(program=ProgramModel(name="fixture", status="active"), scope=scope, roe=roe)
    ctx = SimpleNamespace(slug="acme-test", db=db, workspace=tmp_path, engagement=engagement, scope=ScopeEngine(scope), policy=PolicyEngine(scope, roe), record=SimpleNamespace(status="active"))
    run = db.start_recon_run(stage="burp")
    stats = ingest_burp_recon(ctx, [{"url": "https://example.test/allowed/api", "method": "GET"}], recon_run_id=run["id"])
    assert stats["new_endpoints"] == 1
    assert db.list_assets(type="host")[0]["scope_status"] == "in_scope_via_url"
    assert not ctx.scope.check("https://example.test/").allowed


def test_repeated_endpoint_upsert_and_new_endpoint_change(db, tmp_path):
    ctx = _ctx(db, tmp_path, wildcard=False)
    first = db.start_recon_run(profile="standard")
    ingest_burp_recon(ctx, [{"url": "https://example.test/api/users?id=1", "method": "GET"}], recon_run_id=first["id"])
    db.finish_recon_run(first["id"])
    second = db.start_recon_run(profile="standard")
    ingest_burp_recon(ctx, [
        {"url": "https://example.test/api/users?id=2", "method": "GET"},
        {"url": "https://example.test/graphql", "method": "POST"},
    ], recon_run_id=second["id"])
    db.finish_recon_run(second["id"])
    assert len(db.list_endpoints()) == 2
    changes = db.list_recon_changes(recon_run_id=second["id"], change_type="NEW_ENDPOINT")
    assert len(changes) == 1 and "graphql" in changes[0]["new_value"]


def test_openapi_ingestion_stores_shapes_not_values(db, tmp_path):
    ctx = _ctx(db, tmp_path, wildcard=False)
    run = db.start_recon_run(stage="openapi")
    stats = ingest_openapi_document(ctx, {
        "openapi": "3.0.0",
        "paths": {"/api/orders/{order_id}": {"patch": {
            "parameters": [{"name": "order_id", "in": "path", "schema": {"type": "string"}}],
            "requestBody": {"content": {"application/json": {"schema": {"properties": {"amount": {"type": "number"}, "token": {"type": "string"}}}}}},
        }}},
    }, recon_run_id=run["id"], base_url="https://example.test")
    endpoint = db.list_endpoints()[0]
    assert stats["new_endpoints"] == 1 and endpoint["normalized_path"] == "/api/orders/{order_id}"
    assert {p["name"] for p in db.list_endpoint_parameters(endpoint["id"])} == {"order_id", "amount", "token"}
    assert "string" not in str(db.list_assets(type="url"))


def test_standard_profile_to_contextual_lead_is_fully_synthetic(db, tmp_path, monkeypatch):
    ctx = _ctx(db, tmp_path, active=True, crawl=True)
    session = db.start_session("test", "recon-executor", "acme-test")
    monkeypatch.setattr("bughunt_harness.recon.detect_recon_tools", lambda: _detected(
        "subfinder", "assetfinder", "amass", "dnsx", "httpx", "gau", "waybackurls", "katana",
    ))
    def fake_run(argv, **kwargs):
        tool = argv[0]
        lines = {
            "subfinder": ["api.example.test"], "assetfinder": ["api.example.test"],
            "amass": ["api.example.test"],
            "dnsx": ['{"host":"api.example.test","a":["127.0.0.1"]}'],
            "httpx": ['{"url":"https://api.example.test/api/orders/550e8400-e29b-41d4-a716-446655440000?order_id=1","status_code":200,"content_type":"application/json","tech":["FastAPI"]}'],
            "gau": ["https://api.example.test/api/orders?order_id=1"],
            "waybackurls": ["https://api.example.test/api/orders?order_id=2"],
            "katana": ['{"request":{"endpoint":"https://api.example.test/graphql","method":"POST"}}'],
        }[tool]
        return {"argv": argv, "exit_code": 0, "lines": lines, "stderr": "", "partial": False}
    monkeypatch.setattr("bughunt_harness.recon._run_tool", fake_run)
    class FakeBurp:
        def __init__(self, *args, **kwargs): self.tools = []
        def connect(self): return None
        def close(self): return None
    monkeypatch.setattr("bughunt_harness.integrations.burp.BurpMCPClient", FakeBurp)
    result = run_authorized_recon(ctx, profile="standard", seeds=[], session_id=session.id)
    assert result.ok and result.run_id == "RECON-001"
    assert db.get_recon_run(1)["status"] in {"completed", "partial"}
    assert db.list_assets(type="host")[0]["observation_count"] >= 3
    assert any(endpoint["normalized_path"] == "/api/orders/{id}" for endpoint in db.list_endpoints())
    assert any(parameter["name"] == "order_id" for parameter in db.list_endpoint_parameters())
    assert db.list_technology_observations()[0]["technology"] == "FastAPI"
    assert result.leads and any(lead.source == "recon:inventory" for lead in db.list_leads())


def test_deep_stage_requires_and_consumes_matching_approval(db, tmp_path, monkeypatch):
    ctx = _ctx(db, tmp_path)
    ctx.engagement.roe.bounded_scanning = True
    session = db.start_session("test", "recon-executor", "acme-test")
    denied = run_authorized_recon(ctx, stage="nuclei", seeds=["https://api.example.test"], session_id=session.id)
    assert not denied.ok and denied.mode == "ASK"
    approval = db.request_approval(
        "bounded_scan", "https://api.example.test", program="acme-test",
        requested_by="recon-executor", session_id=session.id,
        constraints={"recon_stage": "nuclei", "max_requests": 10, "max_concurrency": 1, "duration_seconds": 60},
    )
    db.approve_approval(approval.id, approved_by="human")
    monkeypatch.setattr("bughunt_harness.recon.detect_recon_tools", lambda: _detected())
    result = run_authorized_recon(ctx, stage="nuclei", seeds=["https://api.example.test"], session_id=session.id, approval_id=approval.id)
    assert result.ok and result.reason == "partial"
    assert db.get_approval(approval.id).status == "consumed"
