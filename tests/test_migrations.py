"""Upgrade a synthetic v1 database without guessing or deleting legacy data."""

import sqlite3

from bughunt_harness import STATE_SCHEMA_VERSION
from bughunt_harness.state.db import HuntDB, _BASELINE_SCHEMA


def test_v1_database_migrates_to_current_and_marks_legacy_linkage(tmp_path):
    path = tmp_path / "state" / "hunt.db"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    connection.executescript(_BASELINE_SCHEMA)
    connection.execute("INSERT INTO meta(key,value) VALUES('program_slug','acme-test')")
    connection.execute(
        "INSERT INTO finding(title,status,created_at,updated_at) VALUES('legacy','candidate','t','t')"
    )
    connection.execute("PRAGMA user_version=1")
    connection.commit()
    connection.close()

    db = HuntDB(path, program_slug="acme-test")
    try:
        finding = db.get_finding(1)
        assert finding.title == "legacy"
        assert finding.linkage_state == "legacy_incomplete"
        assert finding.creator_session_id is None
        version = db._conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == STATE_SCHEMA_VERSION
        tables = {
            row[0] for row in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "validation_review", "auth_context", "rate_limit_lease", "autonomy_run",
            "recon_run", "asset", "asset_observation", "endpoint",
            "endpoint_parameter", "technology_observation", "recon_change",
            "autonomy_activity", "lead_recon_change",
            "program_import", "program_source", "program_ambiguity",
            "program_import_approval", "program_intake_audit",
            "source_repository", "source_analysis_run", "source_observation",
            "source_runtime_mapping",
        } <= tables
    finally:
        db.close()
