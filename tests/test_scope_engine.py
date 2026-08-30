"""Scope engine tests: deterministic include/exclude/wildcard/URL/IP resolution."""

import pytest

from bughunt_harness.engagement.models import ScopeModel, ScopeSet
from bughunt_harness.scope.engine import ScopeEngine, normalize_target, parse_target


def _engine(**include_kw):
    include = ScopeSet(**include_kw)
    return ScopeEngine(ScopeModel(include=include))


def test_exact_domain_match_is_allowed():
    eng = _engine(domains=["example.test"])
    assert eng.check("https://example.test/x").allowed
    assert eng.check("example.test").allowed


def test_wildcard_matches_descendants_not_apex():
    eng = _engine(wildcards=["*.example.test"])
    assert eng.check("https://a.example.test").allowed
    assert eng.check("https://a.b.example.test").allowed
    assert not eng.check("https://example.test").allowed
    assert not eng.check("https://evil-example.test").allowed


def test_exclusion_always_wins():
    eng = ScopeEngine(
        ScopeModel(
            include=ScopeSet(domains=["example.test"], wildcards=["*.example.test"]),
            exclude=ScopeSet(domains=["admin.example.test"]),
        )
    )
    assert not eng.check("https://admin.example.test").allowed
    assert eng.check("https://api.example.test").allowed


def test_out_of_scope_host_blocked():
    eng = _engine(domains=["example.test"])
    d = eng.check("https://example.org")
    assert not d.allowed
    assert "not in scope" in d.reason


def test_url_path_prefix_at_segment_boundary():
    eng = _engine(path_urls=["https://example.test/api"])
    assert eng.check("https://example.test/api").allowed
    assert eng.check("https://example.test/api/v1/users").allowed
    assert not eng.check("https://example.test/apiv2").allowed  # no segment boundary
    assert not eng.check("https://example.test/other").allowed


def test_ip_and_cidr_matching():
    eng = _engine(ipv4=["192.0.2.10"], cidr=["198.51.100.0/24"])
    assert eng.check("192.0.2.10").allowed
    assert eng.check("198.51.100.42").allowed
    assert not eng.check("198.51.101.1").allowed
    assert not eng.check("203.0.113.7").allowed


def test_parse_target_rejects_empty():
    with pytest.raises(ValueError):
        parse_target("")
    with pytest.raises(ValueError):
        parse_target("   ")


@pytest.mark.parametrize(
    "target",
    [
        "https://example.test/allowed/%252e%252e/admin",
        "https://example.test/allowed/%2fadmin",
        "https://example.test/allowed\\..\\admin",
        "https://user@example.test/allowed",
        "https://example.test/allowed//child",
        "https://example.test:0/allowed",
    ],
)
def test_ambiguous_targets_fail_closed(target):
    engine = _engine(path_urls=["https://example.test/allowed"])
    decision = engine.check(target)
    assert not decision.allowed
    assert "ambiguous_or_invalid_target" in decision.reason


def test_dot_segments_are_normalized_before_path_scope():
    engine = _engine(path_urls=["https://example.test/allowed"])
    assert not engine.check("https://example.test/allowed/../admin").allowed
    assert not engine.check("https://example.test/allowed/%2e%2e/admin").allowed


def test_host_default_port_fragment_case_and_trailing_dot_normalize():
    assert normalize_target("HTTPS://Example.TEST.:443/api#fragment") == "https://example.test/api"
