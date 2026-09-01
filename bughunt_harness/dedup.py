"""Versioned deterministic finding fingerprints and explainable similarity."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .timeutil import utcnow

DEDUP_VERSION = "dedup-v1"


@dataclass
class DedupResult:
    classification: str
    score: float
    duplicate_of: int | None
    reason: str
    fingerprint: str


def normalize_endpoint(value: str) -> str:
    parsed = urlsplit(value if "://" in value else "https://placeholder" + value)
    path = re.sub(r"/(?:(?:\d+)|(?:[0-9a-f]{8}-[0-9a-f-]{27,}))(?=/|$)", "/{id}", parsed.path, flags=re.I)
    return f"{(parsed.hostname or '').lower()}{path.rstrip('/') or '/'}"


class FindingDeduplicator:
    def __init__(self, db) -> None:
        self.db = db

    def fingerprint(self, *, category: str, target: str, method: str = "", parameter: str = "", boundary: str = "", root_cause: str = "", impact: str = "") -> tuple[str, dict]:
        normalized = {
            "category": category.upper().strip(), "endpoint": normalize_endpoint(target),
            "method": method.upper(), "parameter": parameter.lower().strip(),
            "boundary": boundary.lower().strip(), "root_cause": root_cause.lower().strip(),
            "impact": impact.lower().strip(),
        }
        digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        return digest, normalized

    def classify(self, normalized: dict, fingerprint: str) -> DedupResult:
        rows = self.db._conn.execute("SELECT * FROM finding_fingerprint ORDER BY id").fetchall()
        best = DedupResult("DISTINCT", 0.0, None, "no matching dimensions", fingerprint)
        for row in rows:
            other = json.loads(row["normalized"])
            if row["fingerprint"] == fingerprint:
                return DedupResult("EXACT_DUPLICATE", 1.0, row["finding_id"], "all versioned dimensions match", fingerprint)
            weights = {"category": .25, "endpoint": .25, "method": .1, "parameter": .1, "boundary": .1, "root_cause": .15, "impact": .05}
            score = sum(weight for key, weight in weights.items() if normalized.get(key) and normalized.get(key) == other.get(key))
            if normalized.get("category") == other.get("category") and normalized.get("endpoint") == other.get("endpoint") and normalized.get("root_cause") == other.get("root_cause"):
                classification = "LIKELY_DUPLICATE" if normalized.get("method") == other.get("method") else "RELATED_VARIANT"
            elif normalized.get("category") == other.get("category") and (normalized.get("endpoint") == other.get("endpoint") or normalized.get("root_cause") == other.get("root_cause")):
                classification = "RELATED_VARIANT"
            else:
                classification = "DISTINCT"
            if score > best.score:
                best = DedupResult(classification, round(score, 3), row["finding_id"] if classification != "DISTINCT" else None, "weighted normalized dimension match", fingerprint)
        return best

    def register(self, finding_id: int, **dimensions) -> DedupResult:
        self.db.get_finding(finding_id)
        fingerprint, normalized = self.fingerprint(**dimensions)
        result = self.classify(normalized, fingerprint)
        with self.db._lock:
            self.db._conn.execute(
                "INSERT OR REPLACE INTO finding_fingerprint(finding_id,fingerprint,normalized,dedup_version,potential_duplicate_of,"
                "duplicate_score,duplicate_reason,classification,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (finding_id, fingerprint, json.dumps(normalized), DEDUP_VERSION, result.duplicate_of,
                 result.score, result.reason, result.classification, utcnow()),
            )
            self.db._conn.execute("UPDATE finding SET dedup_classification=?,potential_duplicate_of=? WHERE id=?", (result.classification, result.duplicate_of, finding_id))
            self.db._conn.commit()
        return result

    def import_prior_report(
        self, *, report_id: str, title: str, status: str, endpoint: str,
        category: str, submitted_at: str | None = None, duplicate_status: str = "",
        metadata: dict | None = None,
    ) -> dict:
        """Import a user-owned same-program report; no platform scraping."""
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO prior_finding(report_id,title,status,normalized_endpoint,category,submitted_at,duplicate_status,metadata) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(report_id) DO UPDATE SET title=excluded.title,status=excluded.status,"
                "normalized_endpoint=excluded.normalized_endpoint,category=excluded.category,submitted_at=excluded.submitted_at,"
                "duplicate_status=excluded.duplicate_status,metadata=excluded.metadata",
                (report_id, title, status, normalize_endpoint(endpoint), category.upper().strip(),
                 submitted_at, duplicate_status, json.dumps(metadata or {})),
            ); self.db._conn.commit()
        return {"report_id": report_id, "title": title, "status": status, "normalized_endpoint": normalize_endpoint(endpoint), "category": category.upper().strip()}

    def compare_prior(self, *, category: str, target: str) -> list[dict]:
        endpoint = normalize_endpoint(target)
        rows = self.db._conn.execute(
            "SELECT * FROM prior_finding WHERE category=? OR normalized_endpoint=? ORDER BY id DESC",
            (category.upper().strip(), endpoint),
        ).fetchall()
        return [{
            "report_id": row["report_id"], "title": row["title"],
            "classification": "LIKELY_DUPLICATE" if row["category"] == category.upper().strip() and row["normalized_endpoint"] == endpoint else "RELATED_VARIANT",
            "reason": "user-imported same-program prior report metadata",
        } for row in rows]


__all__ = ["FindingDeduplicator", "DedupResult", "normalize_endpoint", "DEDUP_VERSION"]
