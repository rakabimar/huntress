"""Global program registry.

Stores ONLY non-sensitive registration metadata in ``~/.bughunt/registry.db``:
slug, name, platform, workspace path, status, timestamps, notes.  Full recon,
findings, secrets, and evidence live in the per-program workspace — never here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import HarnessConfig, get_config

VALID_STATUSES = ("active", "paused", "archived")
VALID_PLATFORMS = ("hackerone", "bugcrowd", "yeswehack", "intigriti", "custom")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ProgramRecord:
    slug: str
    name: str
    platform: str
    workspace_path: str
    status: str
    program_url: str | None
    notes: str | None
    created_at: str
    last_opened_at: str | None

    @property
    def workspace(self) -> Path:
        return Path(self.workspace_path)

    def as_dict(self) -> dict:
        return {
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "program_url": self.program_url,
            "workspace_path": self.workspace_path,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at,
            "last_opened_at": self.last_opened_at,
        }


class ProgramRegistry:
    """Thin wrapper over the global registry SQLite database."""

    def __init__(self, config: HarnessConfig | None = None) -> None:
        self.config = config or get_config()
        self._conn = sqlite3.connect(self.config.registry_db)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS programs (
                slug           TEXT PRIMARY KEY,
                name           TEXT NOT NULL,
                platform       TEXT NOT NULL DEFAULT 'custom',
                program_url    TEXT,
                workspace_path TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'paused',
                notes          TEXT,
                created_at     TEXT NOT NULL,
                last_opened_at TEXT
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_programs_status ON programs(status)")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- CRUD -------------------------------------------------------------
    def create(
        self,
        *,
        slug: str,
        name: str,
        platform: str = "custom",
        program_url: str | None = None,
        workspace_path: str,
        notes: str | None = None,
        status: str = "paused",
    ) -> ProgramRecord:
        if platform not in VALID_PLATFORMS:
            raise ValueError(f"platform must be one of {VALID_PLATFORMS}")
        if status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {VALID_STATUSES}")
        now = utcnow()
        try:
            self._conn.execute(
                """
                INSERT INTO programs (slug, name, platform, program_url, workspace_path, status, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (slug, name, platform, program_url, workspace_path, status, notes, now),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"program already exists: {slug!r}") from exc
        return self.get(slug)

    def get(self, slug: str) -> ProgramRecord:
        row = self._conn.execute("SELECT * FROM programs WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            from .errors import ProgramNotFoundError

            raise ProgramNotFoundError(slug)
        return self._row_to_record(row)

    def list(self, status: str | None = None) -> list[ProgramRecord]:
        if status:
            rows = self._conn.execute("SELECT * FROM programs WHERE status = ? ORDER BY slug", (status,)).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM programs ORDER BY slug").fetchall()
        return [self._row_to_record(r) for r in rows]

    def set_status(self, slug: str, status: str) -> None:
        if status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {VALID_STATUSES}")
        cur = self._conn.execute("UPDATE programs SET status = ? WHERE slug = ?", (status, slug))
        self._conn.commit()
        if cur.rowcount == 0:
            from .errors import ProgramNotFoundError

            raise ProgramNotFoundError(slug)

    def touch_last_opened(self, slug: str) -> None:
        self._conn.execute("UPDATE programs SET last_opened_at = ? WHERE slug = ?", (utcnow(), slug))
        self._conn.commit()

    def delete(self, slug: str) -> None:
        """Remove a registration row (does not delete the workspace directory)."""
        cur = self._conn.execute("DELETE FROM programs WHERE slug = ?", (slug,))
        self._conn.commit()
        if cur.rowcount == 0:
            from .errors import ProgramNotFoundError

            raise ProgramNotFoundError(slug)

    # -- active (current) program ----------------------------------------
    def set_active(self, slug: str) -> None:
        """Persist the 'current' program slug for CLI convenience."""
        # Validate existence first.
        self.get(slug)
        self.config.active_program_file.write_text(slug + "\n", encoding="utf-8")

    def get_active(self) -> str | None:
        try:
            raw = self.config.active_program_file.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return raw or None

    def clear_active(self) -> None:
        try:
            self.config.active_program_file.unlink()
        except OSError:
            pass

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ProgramRecord:
        return ProgramRecord(
            slug=row["slug"],
            name=row["name"],
            platform=row["platform"],
            workspace_path=row["workspace_path"],
            status=row["status"],
            program_url=row["program_url"],
            notes=row["notes"],
            created_at=row["created_at"],
            last_opened_at=row["last_opened_at"],
        )