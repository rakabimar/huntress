from __future__ import annotations

import json
import pytest
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

from bughunt_harness.coverage import CoverageTracker
from bughunt_harness.capability_acceptance import run_capability_completion_smoke
from bughunt_harness.config import HarnessConfig
from bughunt_harness.dedup import FindingDeduplicator
from bughunt_harness.engagement.models import Engagement, ProgramModel, ROEModel, ScopeModel, ScopeSet
from bughunt_harness.errors import StateError
from bughunt_harness.javascript import JavaScriptAnalyzer
from bughunt_harness.knowledge_store import KnowledgeStore
from bughunt_harness.learning import ProgramLearning
from bughunt_harness.oast import OASTInteractionData, OASTService, SyntheticOASTProvider
from bughunt_harness.policy.engine import PolicyEngine
from bughunt_harness.requests.broker import RequestBroker
from bughunt_harness.requests.replay import ReplayService
from bughunt_harness.requests.response_diff import ResponseComparator
from bughunt_harness.requests.templates import RequestMutation, RequestTemplate
from bughunt_harness.scope.engine import ScopeEngine
from bughunt_harness.secrets.manager import SecretManager
from bughunt_harness.state.db import HuntDB
from bughunt_harness.whitebox_taint import MultiLanguageTaintAnalyzer
from bughunt_harness.watch import ReconWatchService


def _ctx(tmp_path: Path):
    scope_model = ScopeModel(include=ScopeSet(domains=["example.test"], ipv4=["127.0.0.1"]))
    engagement = Engagement(program=ProgramModel(name="caps", status="active"), scope=scope_model, roe=ROEModel(automation_allowed=True, out_of_band_testing=True))
    db = HuntDB(tmp_path / "state" / "hunt.db", "caps")
    return SimpleNamespace(slug="caps", workspace=tmp_path, db=db, engagement=engagement, scope=ScopeEngine(scope_model), policy=PolicyEngine(scope_model, engagement.roe))


def test_request_template_structured_mutations():
    template = RequestTemplate(
        "POST", "https://example.test/api/items?id=1", [("id", "1")],
        {"Content-Type": "application/json", "X-Test": "a"}, "application/json", "json",
        {"body": {"user": {"id": 1}}, "items": [{"quantity": 1}]},
    )
    changed = template.mutated([
        RequestMutation("query", "id", "SET", "2"),
        RequestMutation("json", "items[0].quantity", "SET", 3),
        RequestMutation("header", "X-Test", "APPEND", "b"),
    ])
    assert changed.query_parameters == [("id", "2")]
    assert changed.body["items"][0]["quantity"] == 3
    assert changed.headers["X-Test"] == "ab"


def test_response_comparator_json_noise_and_sensitive_differences(tmp_path):
    db = HuntDB(tmp_path / "hunt.db", "caps")
    a = db.record_request("caps", "GET", "https://example.test/a", response_metadata={"status": 200, "headers": {"Content-Type": "application/json"}, "body": '{"timestamp":1,"private":"a"}', "length": 29})
    b = db.record_request("caps", "GET", "https://example.test/a", response_metadata={"status": 200, "headers": {"Content-Type": "application/json", "Set-Cookie": "[REDACTED]"}, "body": '{"timestamp":2,"private":"b"}', "length": 29})
    diff = ResponseComparator(ignore_json_paths={"$.timestamp"}).compare_records([a, b]).as_dict()
    assert diff["status"] == [200, 200]
    changes = diff["json_differences"]["comparisons"][0]
    assert changes == [{"path": "$.private", "kind": "changed_value", "from": "a", "to": "b"}]
    assert diff["set_cookie_changed"]
    db.close()


def test_oast_exact_correlation_dedup_and_evidence(tmp_path):
    ctx = _ctx(tmp_path); provider = SyntheticOASTProvider(); service = OASTService(ctx, {"synthetic": provider})
    session = ctx.db.start_session("pytest", "researcher", "caps")
    hypothesis = ctx.db.create_hypothesis("blind callback")
    test = ctx.db.add_test(hypothesis.id, "one OAST callback")
    oast_session = service.create_session("synthetic", session_id=session.id, expires_in=300)
    probe = service.create_probe(oast_session["id"], hypothesis_id=hypothesis.id, research_test_id=test.id)
    request = ctx.db.record_request("caps", "POST", "https://example.test/hook", session_id=session.id, research_test_id=test.id, hypothesis_id=hypothesis.id)
    probe = service.link_request(probe["id"], request.id)
    assert service.poll_probe(probe["id"])["interactions"] == []  # bounded initial check
    assert "example" not in probe["correlation_token"] and "caps" not in probe["correlation_token"]
    provider.inject(oast_session["provider_session_reference"], OASTInteractionData("evt-1", "DNS", "2026-09-01T00:00:00+00:00", probe["callback_domain"]))
    first = service.poll_probe(probe["id"]); second = service.poll_probe(probe["id"])
    assert len(first["interactions"]) == 1 and len(second["interactions"]) == 1
    assert first["new_interactions"][0]["evidence_id"].startswith("EVD-")
    provider.inject(oast_session["provider_session_reference"], OASTInteractionData("wrong", "DNS", "2026-09-01T00:00:00+00:00", "other.oast.localhost"))
    assert len(service.poll_probe(probe["id"])["interactions"]) == 1
    ctx.db.close()


def test_oast_expiry_unlinked_callback_and_provider_failure(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path); provider = SyntheticOASTProvider(); service = OASTService(ctx, {"synthetic": provider})
    session = ctx.db.start_session("pytest", "researcher", "caps")
    hypothesis = ctx.db.create_hypothesis("bounded provider lifecycle")
    test = ctx.db.add_test(hypothesis.id, "provider lifecycle failure paths")
    oast_session = service.create_session("synthetic", session_id=session.id, expires_in=300)
    probe = service.create_probe(oast_session["id"], hypothesis_id=hypothesis.id, research_test_id=test.id)
    provider.inject(oast_session["provider_session_reference"], OASTInteractionData("unlinked", "DNS", "2026-09-01T00:00:00+00:00", probe["callback_domain"]))
    assert service.poll_probe(probe["id"])["interactions"] == []  # never evidence without an exact target request
    ctx.db._conn.execute("UPDATE oast_probe SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (probe["id"],)); ctx.db._conn.commit()
    assert service.poll_probe(probe["id"])["reason"] == "expired"

    second = service.create_probe(oast_session["id"], hypothesis_id=hypothesis.id, research_test_id=test.id)
    monkeypatch.setattr(provider, "poll", lambda _reference: (_ for _ in ()).throw(RuntimeError("fixture failure")))
    with pytest.raises(RuntimeError, match="fixture failure"):
        service.poll_probe(second["id"])
    assert service.get_session(oast_session["id"])["status"] == "FAILED"
    ctx.db.close()


def test_coverage_js_learning_knowledge_and_taint(tmp_path):
    ctx = _ctx(tmp_path)
    asset, _ = ctx.db.upsert_asset(type="host", value="example.test", normalized_value="example.test", scope_status="in_scope")
    endpoint, _ = ctx.db.upsert_endpoint(host_asset_id=asset["id"], scheme="https", method="GET", normalized_path="/api/a")
    tracker = CoverageTracker(ctx)
    tracker.observe(endpoint_id=endpoint["id"], method="GET", state="BASELINED", skill_family="api-authorization")
    tracker.record_test(endpoint_id=endpoint["id"], method="GET", research_test_id=None, skill_family="api-authorization")
    assert tracker.summary()["tested"] == 1
    assert tracker.mark_endpoint_changed(endpoint["id"]) == 1

    js = JavaScriptAnalyzer(ctx).analyze_text("https://example.test/app.js", 'fetch("/api/orders/123"); query GetOrder { order { id } } //# sourceMappingURL=app.js.map const apiKey="ABCDEFGHIJKLMNOP"')
    assert js["observations"]["endpoints"][0]["url"].endswith("/api/orders/123")
    assert js["observations"]["analysis_method"] in {"tree-sitter+regex", "conservative-regex"}
    assert js["observations"]["graphql_operations"][0]["name"] == "GetOrder"
    assert js["observations"]["secret_candidates"][0].get("fingerprint")

    learning = ProgramLearning(ctx.db)
    for _ in range(5): learning.record(signal="new-js-endpoint", skill="api-authorization", outcome="validated")
    assert 0 < learning.adjustment(signal="new-js-endpoint", skill="api-authorization", specialist="", surface_type="")["adjustment"] <= .2

    store = KnowledgeStore(tmp_path / "knowledge.db")
    store.import_cwe({"id": "918", "name": "SSRF", "summary": "server-side request forgery"}, source_version="fixture")
    assert store.search("request forgery")[0]["category"] == "CWE"
    store.close()

    flows = MultiLanguageTaintAnalyzer().analyze('const u = req.query.url; fetch(u);', "typescript")
    assert flows and flows[0].level == "LEVEL_1" and not flows[0].sanitized
    ctx.db.close()


def test_dedup_exact_and_related_variant(tmp_path):
    db = HuntDB(tmp_path / "hunt.db", "caps"); engine = FindingDeduplicator(db)
    fp, normalized = engine.fingerprint(category="CWE-639", target="https://example.test/invoice/123", method="GET", parameter="id", boundary="owner-vs-other", root_cause="missing owner check", impact="read")
    db._conn.execute("INSERT INTO finding(title,affected_target,category,status,impact_summary,evidence_refs,created_at,updated_at) VALUES('a','x','CWE-639','candidate','','[]','x','x')")
    finding_id = db._conn.execute("SELECT id FROM finding").fetchone()[0]
    db._conn.execute("INSERT INTO finding_fingerprint(finding_id,fingerprint,normalized,dedup_version,created_at) VALUES(?,?,?,?,?)", (finding_id, fp, json.dumps(normalized), "dedup-v1", "x")); db._conn.commit()
    assert engine.classify(normalized, fp).classification == "EXACT_DUPLICATE"
    fp2, variant = engine.fingerprint(category="CWE-639", target="https://example.test/invoice/999", method="DELETE", parameter="id", boundary="owner-vs-other", root_cause="missing owner check", impact="delete")
    assert engine.classify(variant, fp2).classification == "RELATED_VARIANT"
    db.close()


def test_multilanguage_taint_fixtures_have_true_and_sanitized_paths():
    root = Path(__file__).parent / "fixtures" / "whitebox"
    analyzer = MultiLanguageTaintAnalyzer()
    for language, path in (
        ("typescript", root / "taint-typescript" / "routes.ts"),
        ("java", root / "taint-java" / "Controller.java"),
        ("go", root / "taint-go" / "handler.go"),
    ):
        observations = analyzer.analyze(path.read_text(encoding="utf-8"), language)
        assert any(not item.sanitized for item in observations), language
        assert any(item.sanitized for item in observations), language


def test_specialist_atomic_leases_partition_independent_leads(tmp_path):
    db = HuntDB(tmp_path / "hunt.db", "caps")
    creator = db.start_session("pytest", "orchestrator", "caps")
    lead_a = db.add_lead("A"); lead_b = db.add_lead("B")
    task_a = db.create_specialist_task(created_by_role="orchestrator", assigned_role="api-authz-specialist", goal="A", session_id=creator.id, lead_id=lead_a.id)
    task_b = db.create_specialist_task(created_by_role="orchestrator", assigned_role="api-authz-specialist", goal="B", session_id=creator.id, lead_id=lead_b.id)
    worker_a = db.start_session("pytest", "api-authz-specialist", "caps")
    worker_b = db.start_session("pytest", "api-authz-specialist", "caps")
    assert db.claim_specialist_task(task_a["id"], lease_owner="a", claimed_session_id=worker_a.id, max_parallel=2)["status"] == "RUNNING"
    assert db.claim_specialist_task(task_b["id"], lease_owner="b", claimed_session_id=worker_b.id, max_parallel=2)["status"] == "RUNNING"
    with pytest.raises(StateError):
        db.claim_specialist_task(task_a["id"], lease_owner="duplicate", claimed_session_id=worker_b.id, max_parallel=2)
    db.close()


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = json.dumps({"path": self.path}).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_args): pass


def test_broker_replay_revalidates_and_persists_lineage(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler); threading.Thread(target=server.serve_forever, daemon=True).start()
    scope_model = ScopeModel(include=ScopeSet(ipv4=["127.0.0.1"]))
    engagement = Engagement(program=ProgramModel(name="replay", status="active"), scope=scope_model, roe=ROEModel(automation_allowed=True))
    db = HuntDB(tmp_path / "state" / "hunt.db", "replay"); session = db.start_session("pytest", "researcher", "replay")
    cfg = HarnessConfig(home=tmp_path / "home", burp_proxy="disabled")
    broker = RequestBroker(engagement, program_slug="replay", workspace=tmp_path, hunt_db=db, secrets=SecretManager("replay", cfg)); broker.config = cfg
    ctx = SimpleNamespace(slug="replay", workspace=tmp_path, db=db, broker=broker, engagement=engagement, scope=ScopeEngine(scope_model), policy=PolicyEngine(scope_model, engagement.roe))
    try:
        baseline = broker.execute(target=f"http://127.0.0.1:{server.server_address[1]}/echo", params={"id": "1"}, action="read_http", session_id=session.id)
        replayed = ReplayService(ctx).replay_request(int(baseline.request_id.rsplit("-", 1)[1]), mutations=[RequestMutation("query", "id", "SET", "2")], session_id=session.id)
        assert replayed.ok and 'id=2' in replayed.body_preview
        child = db.get_request_record(int(replayed.request_id.rsplit("-", 1)[1]))
        assert child.parent_request_id == int(baseline.request_id.rsplit("-", 1)[1])
        assert child.root_request_id == child.parent_request_id and child.replay_depth == 1
    finally:
        broker.limiter.close(); db.close(); server.shutdown(); server.server_close()


def test_recon_watch_second_change_creates_lead(tmp_path):
    ctx = _ctx(tmp_path); watch = ReconWatchService(ctx); watch.configure("passive", 60)
    calls = {"n": 0}
    def runner(_profile):
        calls["n"] += 1
        run = ctx.db.start_recon_run(profile="passive", stage="passive")
        if calls["n"] == 2:
            ctx.db.add_recon_change(recon_run_id=run["id"], change_type="NEW_ENDPOINT", entity_type="endpoint", entity_id=999, new_value="/new", interest_score=60)
        return {"run": run["public_id"]}
    assert watch.run_once("passive", runner)["leads"] == []
    assert watch.run_once("passive", runner)["leads"]
    assert watch.get("passive")["last_run"]
    ctx.db.close()


def test_integrated_capability_completion_acceptance_is_loopback_only(tmp_path):
    result = run_capability_completion_smoke(tmp_path)
    assert result.ok
    assert result.external_network_used is False
    assert result.auth_differential_statuses == [200, 403]
    assert result.oast_interaction_count == 1
    assert result.duplicate_classification == "EXACT_DUPLICATE"
