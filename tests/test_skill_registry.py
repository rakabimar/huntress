"""Skill-library registry + structural eval tests (spec §81 fixture-hosts)."""

from bughunt_harness.skills.eval import run_eval
from bughunt_harness.skills.registry import (
    is_fixture_host,
    iter_hosts,
    list_skills,
    validate_all,
)


def test_library_has_expected_skills():
    names = {s["slug"] for s in list_skills()}
    assert len(names) >= 48
    # Core skills must be present.
    for core in ("observe", "hypothesize", "research-loop", "attack", "defend",
                 "triage", "validate", "report"):
        assert core in names, f"missing core skill {core}"


def test_library_structurally_valid():
    problems = validate_all()
    assert problems == [], f"skill problems: {problems}"


def test_eval_all_pass():
    result = run_eval()
    assert result["passed"] == result["skill_count"]
    assert result["failed"] == 0


def test_fixture_host_detection():
    assert is_fixture_host("localhost")
    assert is_fixture_host("127.0.0.1")
    assert is_fixture_host("example.test")
    assert is_fixture_host("sub.example.test")
    assert is_fixture_host("evil.invalid")
    # any *.test destination is a reserved fixture TLD — still a valid fixture
    assert is_fixture_host("evil.example.test")
    # non-reserved TLDs must be rejected
    assert not is_fixture_host("example.com")
    assert not is_fixture_host("127.0.0.1.evil.com")
    # port / placeholder suffixes tolerated
    assert is_fixture_host("127.0.0.1:8080")
    assert is_fixture_host("localhost:8080")


def test_iter_hosts_extracts_url_hosts():
    body = "curl https://example.test/x and http://127.0.0.1:8080/y"
    hosts = iter_hosts(body)
    assert "example.test" in hosts or any("example.test" in h for h in hosts)
    assert any("127.0.0.1" in h or "127.0.0.1:8080" in h for h in hosts)