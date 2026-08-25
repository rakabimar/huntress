"""Program-isolation tests: state-DB binding, registry separation, secrets.

The core invariant (spec §91): one HuntDB instance is bound to ONE program, and
workspaces never share state.
"""

import pytest

from bughunt_harness.config import HarnessConfig
from bughunt_harness.errors import StateError
from bughunt_harness.registry import ProgramRegistry
from bughunt_harness.state.db import HuntDB


def test_state_db_refuses_cross_program_binding(tmp_path):
    path = tmp_path / "state" / "hunt.db"
    a = HuntDB(path, program_slug="acme-test")
    a.add_lead("lead in acme")
    a.close()
    with pytest.raises(StateError):
        HuntDB(path, program_slug="other-test")


def test_separate_state_dbs_do_not_share(tmp_path):
    a = HuntDB(tmp_path / "a" / "hunt.db", program_slug="acme-test")
    b = HuntDB(tmp_path / "b" / "hunt.db", program_slug="other-test")
    a.add_lead("only in acme")
    assert len(a.list_leads()) == 1
    assert len(b.list_leads()) == 0
    a.close()
    b.close()


def test_registry_separates_programs(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    reg = ProgramRegistry(cfg)
    try:
        reg.create(slug="acme-test", name="Acme", workspace_path=str(tmp_path / "ws-a"))
        reg.create(slug="other-test", name="Other", workspace_path=str(tmp_path / "ws-b"))
        assert {p.slug for p in reg.list()} == {"acme-test", "other-test"}
        assert reg.get("acme-test").workspace_path != reg.get("other-test").workspace_path
        reg.set_active("acme-test")
        assert reg.get_active() == "acme-test"
        reg.clear_active()
        assert reg.get_active() is None
    finally:
        reg.close()


def test_registry_duplicate_slug_rejected(tmp_path):
    cfg = HarnessConfig(home=tmp_path / "home", programs_dir=tmp_path / "programs")
    cfg.ensure_dirs()
    reg = ProgramRegistry(cfg)
    try:
        reg.create(slug="acme-test", name="Acme", workspace_path=str(tmp_path / "ws"))
        with pytest.raises(ValueError):
            reg.create(slug="acme-test", name="Acme2", workspace_path=str(tmp_path / "ws2"))
    finally:
        reg.close()