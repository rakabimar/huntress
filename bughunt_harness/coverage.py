"""Observed-surface coverage counts; never claims unknowable total coverage."""

from __future__ import annotations

import json
from collections import Counter

from .timeutil import utcnow

COVERAGE_STATES = {
    "DISCOVERED", "BASELINED", "TESTED", "EXHAUSTED_FOR_HYPOTHESIS", "DEFERRED",
    "BLOCKED_BY_ROE", "BLOCKED_BY_AUTH", "STALE_AFTER_CHANGE", "CHANGED_SINCE_TEST",
}


class CoverageTracker:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def observe(
        self, *, endpoint_id: int, method: str, state: str, parameter: str = "",
        auth_context_class: str = "", skill_family: str = "", research_test_id: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        if state not in COVERAGE_STATES:
            raise ValueError(f"unknown observed coverage state {state!r}")
        self.ctx.db.get_endpoint(endpoint_id)
        now = utcnow()
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "INSERT INTO coverage_observation(endpoint_id,method,parameter,auth_context_class,skill_family,state,"
                "research_test_id,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(endpoint_id,method,parameter,auth_context_class,skill_family) DO UPDATE SET "
                "state=excluded.state,research_test_id=COALESCE(excluded.research_test_id,coverage_observation.research_test_id),"
                "last_seen=excluded.last_seen,metadata=excluded.metadata",
                (endpoint_id, method.upper(), parameter, auth_context_class, skill_family, state,
                 research_test_id, now, now, json.dumps(metadata or {})),
            ); self.ctx.db._conn.commit()
        return self._find(endpoint_id, method, parameter, auth_context_class, skill_family)

    def record_test(self, **kwargs) -> dict:
        kwargs["state"] = "TESTED"
        return self.observe(**kwargs)

    def mark_endpoint_changed(self, endpoint_id: int) -> int:
        with self.ctx.db._lock:
            cur = self.ctx.db._conn.execute(
                "UPDATE coverage_observation SET state='STALE_AFTER_CHANGE',last_seen=? "
                "WHERE endpoint_id=? AND state IN ('BASELINED','TESTED','EXHAUSTED_FOR_HYPOTHESIS')",
                (utcnow(), endpoint_id),
            ); self.ctx.db._conn.commit(); return cur.rowcount

    def summary(self) -> dict:
        endpoint_count = self.ctx.db._conn.execute("SELECT COUNT(*) FROM endpoint").fetchone()[0]
        rows = self.ctx.db._conn.execute("SELECT * FROM coverage_observation ORDER BY endpoint_id,id").fetchall()
        states = Counter(row["state"] for row in rows)
        observed_ids = {row["endpoint_id"] for row in rows}
        tested_ids = {row["endpoint_id"] for row in rows if row["state"] == "TESTED"}
        skill_counts = Counter(row["skill_family"] or "unspecified" for row in rows if row["state"] == "TESTED")
        auth_counts = Counter(row["auth_context_class"] or "anonymous/unspecified" for row in rows)
        high_interest_untested = [
            row["id"] for row in self.ctx.db._conn.execute(
                "SELECT id FROM endpoint WHERE interesting=1 ORDER BY interest_score DESC"
            ).fetchall() if row["id"] not in tested_ids
        ]
        return {
            "label": "OBSERVED SURFACE COVERAGE", "observed_endpoints": endpoint_count,
            "coverage_rows": len(rows), "baselined": states["BASELINED"], "tested": states["TESTED"],
            "untested_observed_endpoints": max(0, endpoint_count - len(tested_ids)),
            "changed_since_test": states["STALE_AFTER_CHANGE"] + states["CHANGED_SINCE_TEST"],
            "parameters_observed": sum(bool(row["parameter"]) for row in rows),
            "auth_context_counts": dict(auth_counts), "tested_by_skill_family": dict(skill_counts),
            "high_interest_untested_endpoint_ids": high_interest_untested[:25],
        }

    def _find(self, endpoint_id, method, parameter, auth_context, skill):
        row = self.ctx.db._conn.execute(
            "SELECT * FROM coverage_observation WHERE endpoint_id=? AND method=? AND parameter=? "
            "AND auth_context_class=? AND skill_family=?",
            (endpoint_id, method.upper(), parameter, auth_context, skill),
        ).fetchone()
        return {key: row[key] for key in row.keys()}


__all__ = ["CoverageTracker", "COVERAGE_STATES"]
