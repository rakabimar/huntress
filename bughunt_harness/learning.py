"""Small, explainable per-program outcome adjustments that cannot alter policy."""

from __future__ import annotations

import json

from .timeutil import utcnow


class ProgramLearning:
    MIN_SAMPLES = 5
    CAP = 0.20

    def __init__(self, db) -> None:
        self.db = db

    def record(self, *, signal: str, skill: str = "", specialist: str = "", surface_type: str = "", outcome: str) -> dict:
        columns = {"attempted": 1, "supported": 0, "candidates": 0, "validator_killed": 0, "validated": 0}
        mapping = {"supported": "supported", "candidate": "candidates", "validator_killed": "validator_killed", "validated": "validated"}
        if outcome in mapping: columns[mapping[outcome]] = 1
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO program_learning(signal,skill,specialist,surface_type,attempted,supported,candidates,validator_killed,validated,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(signal,skill,specialist,surface_type) DO UPDATE SET "
                "attempted=program_learning.attempted+1,supported=program_learning.supported+excluded.supported,"
                "candidates=program_learning.candidates+excluded.candidates,validator_killed=program_learning.validator_killed+excluded.validator_killed,"
                "validated=program_learning.validated+excluded.validated,updated_at=excluded.updated_at",
                (signal, skill, specialist, surface_type, *columns.values(), utcnow()),
            ); self.db._conn.commit()
        return self.adjustment(signal=signal, skill=skill, specialist=specialist, surface_type=surface_type)

    def adjustment(self, **keys) -> dict:
        row = self.db._conn.execute(
            "SELECT * FROM program_learning WHERE signal=? AND skill=? AND specialist=? AND surface_type=?",
            (keys.get("signal", ""), keys.get("skill", ""), keys.get("specialist", ""), keys.get("surface_type", "")),
        ).fetchone()
        if row is None or row["attempted"] < self.MIN_SAMPLES:
            return {"adjustment": 0.0, "reason": f"minimum {self.MIN_SAMPLES} samples not reached", "samples": 0 if row is None else row["attempted"]}
        positive = row["validated"] * 2 + row["candidates"] + row["supported"] * .5
        negative = row["validator_killed"] * 1.5
        rate = (positive + 1) / (row["attempted"] * 2 + 2)
        penalty = negative / max(1, row["attempted"] * 2)
        adjustment = max(-self.CAP, min(self.CAP, (rate - .25) - penalty))
        return {"adjustment": round(adjustment, 4), "reason": "smoothed outcomes with validator-kill weighting", "samples": row["attempted"]}

    def explain_score(self, base: float, *, new_surface_bonus: float = 0, coverage_bonus: float = 0, **keys) -> dict:
        learned = self.adjustment(**keys)
        delta = base * learned["adjustment"]
        return {"base_score": base, "new_surface_bonus": new_surface_bonus, "coverage_bonus": coverage_bonus, "program_learning_adjustment": round(delta, 4), "total": round(base + new_surface_bonus + coverage_bonus + delta, 4), "learning_reason": learned["reason"]}

    def summary(self) -> list[dict]:
        return [{key: row[key] for key in row.keys()} for row in self.db._conn.execute("SELECT * FROM program_learning ORDER BY attempted DESC").fetchall()]

    def reset(self) -> None:
        with self.db._lock:
            self.db._conn.execute("DELETE FROM program_learning"); self.db._conn.commit()


__all__ = ["ProgramLearning"]
