"""Scope engine tests: deterministic include/exclude/wildcard/URL/IP resolution."""

import pytest

from bughunt_harness.engagement.models import ScopeModel, ScopeSet
from bughunt_harness.scope.engine import ScopeEngine, parse_target


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