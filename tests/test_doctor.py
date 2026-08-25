"""Doctor readiness-level semantics (P0.13).

The four-tier level ladder (ENV/CORE/HUNT/FULL) and the program-gating of
``HUNT_READY`` are exercised against *synthetic* ``DoctorReport`` objects so the
tests are deterministic and never depend on real ``~/.bughunt`` state.  A single
structural test against ``run_doctor`` asserts the env tier + program gate exist.
"""

from bughunt_harness.doctor import (
    OK,
    FAIL,
    DoctorCheck,
    DoctorReport,
    run_doctor,
    LEVEL_NOT_READY,
    LEVEL_ENV_READY,
    LEVEL_CORE_READY,
    LEVEL_HUNT_READY,
    LEVEL_FULL_READY,
)


def _c(name, tier, status):
    return DoctorCheck(name=name, tier=tier, status=status, detail="")


def _report(env=(), core=(), hunt=(), full=()):
    checks = []
    for tier, statuses in (("env", env), ("core", core), ("hunt", hunt), ("full", full)):
        checks += [_c(f"{tier}{i}", tier, s) for i, s in enumerate(statuses)]
    return DoctorReport(checks=checks)


def test_level_progression():
    assert _report(env=[FAIL]).level == LEVEL_NOT_READY
    assert _report(env=[OK], core=[FAIL]).level == LEVEL_ENV_READY
    assert _report(env=[OK], core=[OK], hunt=[FAIL]).level == LEVEL_CORE_READY
    assert _report(env=[OK], core=[OK], hunt=[OK], full=[FAIL]).level == LEVEL_HUNT_READY
    assert _report(env=[OK], core=[OK], hunt=[OK], full=[OK]).level == LEVEL_FULL_READY


def test_program_gate_caps_hunt_ready():
    # P0.13: a failed `program_present` (no hunt target) caps readiness at
    # CORE_READY even when every other hunt check is green.
    capped = _report(env=[OK], core=[OK], hunt=[OK, OK, FAIL], full=[OK])
    assert capped.level == LEVEL_CORE_READY
    assert not capped.ready

    # With the program gate satisfied, HUNT_READY is reachable (only full fails).
    hunt_ready = _report(env=[OK], core=[OK], hunt=[OK, OK, OK], full=[FAIL])
    assert hunt_ready.level == LEVEL_HUNT_READY
    assert hunt_ready.ready


def test_ready_means_hunt_or_full():
    assert _report(env=[OK], core=[OK], hunt=[OK], full=[OK]).ready
    assert _report(env=[OK], core=[OK], hunt=[OK], full=[FAIL]).ready
    assert not _report(env=[OK], core=[OK], hunt=[FAIL], full=[OK]).ready
    assert not _report(env=[OK], core=[FAIL]).ready


def test_env_level_exported():
    assert LEVEL_ENV_READY == "ENV_READY"


def test_exit_code_groups_sound_vs_broken():
    # P0.14: doctor exits 0 when env+core are sound (CORE/HUNT/FULL), 1 only
    # when the environment/install is broken (ENV_READY / NOT_READY) — this is
    # what lets bootstrap.sh fail on a broken install without `|| true`.
    assert _report(env=[OK], core=[OK], hunt=[OK], full=[OK]).exit_code == 0
    assert _report(env=[OK], core=[OK], hunt=[FAIL]).exit_code == 0  # CORE_READY
    assert _report(env=[OK], core=[FAIL]).exit_code == 1  # ENV_READY
    assert _report(env=[FAIL]).exit_code == 1  # NOT_READY


def test_run_doctor_has_env_tier_and_program_gate():
    report = run_doctor(None)
    by_tier: dict[str, list[str]] = {}
    for c in report.checks:
        by_tier.setdefault(c.tier, []).append(c.name)
    assert {"python", "install", "dependencies", "state_home"} <= set(by_tier["env"])
    assert "program_present" in by_tier["hunt"]
    # Every check is serializable to the canonical shape.
    for c in report.checks:
        d = c.as_dict()
        assert set(d) == {"name", "tier", "status", "detail"}
    assert report.level in {
        LEVEL_NOT_READY, LEVEL_ENV_READY, LEVEL_CORE_READY, LEVEL_HUNT_READY, LEVEL_FULL_READY,
    }