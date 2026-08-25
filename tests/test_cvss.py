"""CVSS scoring + severity-band tests (number computed by the FIRST calculator)."""

import pytest

from bughunt_harness.cvss.engine import (
    score_vector,
    severity_from_score,
    validate_vector,
)


def test_cvss31_critical():
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r.version == "3.1"
    assert r.severity == "Critical"
    assert 9.0 <= r.base_score <= 10.0


def test_cvss40_scores():
    r = score_vector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert r.version == "4.0"
    assert 0.0 <= r.base_score <= 10.0


def test_severity_bands():
    assert severity_from_score(None) == "Unknown"
    assert severity_from_score(0.0) == "None"
    assert severity_from_score(0.1) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(9.0) == "Critical"


def test_invalid_vector():
    with pytest.raises(ValueError):
        score_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert validate_vector("not-a-vector")


def test_valid_vector_clean():
    assert validate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == []