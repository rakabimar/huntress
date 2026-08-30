"""Persistence façade for the v6 intake tables in a program HuntDB."""

from __future__ import annotations

import json
from typing import Any

from ..timeutil import utcnow
from ..state.db import HuntDB


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


class IntakeStore:
    """Keeps all intake state in the already program-bound SQLite database."""

    def __init__(self, db: HuntDB) -> None:
        self.db = db

    def next_import_id(self) -> str:
        with self.db._lock:
            row = self.db._conn.execute("SELECT COALESCE(MAX(id), 0) + 1 AS n FROM program_import").fetchone()
        return f"IMPORT-{int(row['n']):03d}"

    def create_import(
        self, *, public_id: str, program_slug: str, platform: str,
        platform_handle: str, source_locator: str, adapter_version: str,
        parser_version: str, status: str, supersedes_import_id: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        with self.db._lock:
            self.db._conn.execute(
                """INSERT INTO program_import(
                    public_id,program_slug,platform,platform_handle,source_locator,
                    adapter_version,parser_version,status,started_at,supersedes_import_id,metadata
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (public_id, program_slug, platform, platform_handle, source_locator,
                 adapter_version, parser_version, status, utcnow(), supersedes_import_id,
                 _dump(metadata or {})),
            )
            self.db._conn.commit()
        self.audit(public_id, "import_started", metadata={"status": status})
        return self.get_import(public_id)

    def update_import(self, public_id: str, **values: Any) -> dict:
        allowed = {
            "platform_program_id", "status", "completed_at", "last_checked_at",
            "source_hash", "draft_hash", "scope_hash", "roe_hash",
            "structured_source_count", "prose_source_count", "ambiguity_count",
            "critical_ambiguity_count", "approved_at", "approved_by", "metadata",
        }
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unsupported import fields: {sorted(unknown)}")
        if "metadata" in values:
            values["metadata"] = _dump(values["metadata"])
        assignments = ", ".join(f"{key}=?" for key in values)
        with self.db._lock:
            self.db._conn.execute(
                f"UPDATE program_import SET {assignments} WHERE public_id=?",
                (*values.values(), public_id),
            )
            self.db._conn.commit()
        return self.get_import(public_id)

    def get_import(self, public_id: str) -> dict:
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT * FROM program_import WHERE public_id=?", (public_id,)
            ).fetchone()
        if row is None:
            raise KeyError(public_id)
        return self._import_dict(row)

    def latest_import(self, *, approved_only: bool = False) -> dict | None:
        where = "WHERE approved_at IS NOT NULL" if approved_only else ""
        with self.db._lock:
            row = self.db._conn.execute(
                f"SELECT * FROM program_import {where} ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return self._import_dict(row) if row else None

    def list_imports(self) -> list[dict]:
        with self.db._lock:
            rows = self.db._conn.execute("SELECT * FROM program_import ORDER BY id DESC").fetchall()
        return [self._import_dict(row) for row in rows]

    @staticmethod
    def _import_dict(row) -> dict:
        value = dict(row)
        value["metadata"] = _load(value.get("metadata"), {})
        return value

    def add_source(self, import_id: str, source: dict) -> None:
        with self.db._lock:
            self.db._conn.execute(
                """INSERT INTO program_source(
                    import_id,source_type,source_identifier,retrieved_at,content_hash,
                    artifact_ref,trust_level,status,etag,last_modified,metadata
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (import_id, source["source_type"], source["source_identifier"],
                 source["retrieved_at"], source["content_hash"], source["artifact_ref"],
                 source["trust_level"], str(source["status"]), source.get("etag"),
                 source.get("last_modified"), _dump(source.get("metadata", {}))),
            )
            self.db._conn.commit()

    def list_sources(self, import_id: str) -> list[dict]:
        with self.db._lock:
            rows = self.db._conn.execute(
                "SELECT * FROM program_source WHERE import_id=? ORDER BY id", (import_id,)
            ).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["metadata"] = _load(value.get("metadata"), {})
            result.append(value)
        return result

    def replace_ambiguities(self, import_id: str, ambiguities: list[dict]) -> None:
        with self.db._lock:
            self.db._conn.execute("DELETE FROM program_ambiguity WHERE import_id=?", (import_id,))
            for item in ambiguities:
                self.db._conn.execute(
                    """INSERT INTO program_ambiguity(
                        public_id,import_id,field_path,severity,category,reason,source_refs,
                        proposed_value,alternatives,required_user_input,status,resolution,
                        resolved_at,resolved_by
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (item["id"], import_id, item["field"], item["severity"], item["category"],
                     item["reason"], _dump(item.get("source_refs", [])),
                     _dump(item.get("proposed_interpretation")), _dump(item.get("alternatives", [])),
                     item.get("required_user_input"), item.get("status", "OPEN"),
                     _dump(item.get("resolved_value")), item.get("resolved_at"), item.get("resolved_by")),
                )
            self.db._conn.commit()

    def list_ambiguities(self, import_id: str, *, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM program_ambiguity WHERE import_id=?"
        args: list[Any] = [import_id]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, id"
        with self.db._lock:
            rows = self.db._conn.execute(sql, args).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            for key, default in (("source_refs", []), ("proposed_value", None),
                                 ("alternatives", []), ("resolution", None)):
                value[key] = _load(value.get(key), default)
            result.append(value)
        return result

    def resolve_ambiguity(
        self, import_id: str, ambiguity_id: str, *, value: Any,
        resolved_by: str, status: str = "RESOLVED",
    ) -> dict:
        now = utcnow()
        with self.db._lock:
            cur = self.db._conn.execute(
                """UPDATE program_ambiguity SET status=?,resolution=?,resolved_at=?,resolved_by=?
                   WHERE import_id=? AND public_id=?""",
                (status, _dump(value), now, resolved_by, import_id, ambiguity_id),
            )
            self.db._conn.commit()
        if cur.rowcount != 1:
            raise KeyError(ambiguity_id)
        self.audit(import_id, "ambiguity_resolved", actor=resolved_by,
                   metadata={"ambiguity_id": ambiguity_id, "status": status})
        return next(item for item in self.list_ambiguities(import_id) if item["public_id"] == ambiguity_id)

    def approve(
        self, import_id: str, *, approved_by: str, actor_kind: str,
        draft_hash: str, scope_hash: str, roe_hash: str, program_hash: str,
        notes: str = "",
    ) -> dict:
        if actor_kind != "human":
            raise PermissionError("program import approval is human-only")
        now = utcnow()
        with self.db._lock:
            self.db._conn.execute(
                """INSERT INTO program_import_approval(
                    import_id,approved_at,approved_by,actor_kind,draft_hash,scope_hash,
                    roe_hash,program_hash,notes
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (import_id, now, approved_by, actor_kind, draft_hash, scope_hash,
                 roe_hash, program_hash, notes),
            )
            self.db._conn.commit()
        self.audit(import_id, "approval_performed", actor=approved_by,
                   metadata={"draft_hash": draft_hash})
        return self.get_approval(import_id) or {}

    def get_approval(self, import_id: str) -> dict | None:
        with self.db._lock:
            row = self.db._conn.execute(
                "SELECT * FROM program_import_approval WHERE import_id=?", (import_id,)
            ).fetchone()
        return dict(row) if row else None

    def audit(self, import_id: str | None, event: str, *, actor: str = "system", metadata: dict | None = None) -> None:
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO program_intake_audit(import_id,event,actor,created_at,metadata) VALUES(?,?,?,?,?)",
                (import_id, event, actor, utcnow(), _dump(metadata or {})),
            )
            self.db._conn.commit()


__all__ = ["IntakeStore"]
