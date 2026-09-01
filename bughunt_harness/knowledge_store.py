"""SQLite/FTS5 knowledge documents; knowledge never authorizes target testing."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path

from .timeutil import utcnow


class AdvisoryProvider(ABC):
    name = "abstract"

    @abstractmethod
    def query(self, ecosystem: str, package: str, version: str) -> list[dict]: ...


class OSVProvider(AdvisoryProvider):
    """Official OSV API adapter; invoked only by an explicit knowledge sync."""
    name = "osv"

    def __init__(self, endpoint: str = "https://api.osv.dev/v1/query") -> None:
        self.endpoint = endpoint

    def query(self, ecosystem: str, package: str, version: str) -> list[dict]:
        import requests
        response = requests.post(
            self.endpoint,
            json={"package": {"ecosystem": ecosystem, "name": package}, "version": version},
            timeout=20,
        )
        response.raise_for_status()
        return list(response.json().get("vulns") or [])


class FixtureAdvisoryProvider(AdvisoryProvider):
    name = "fixture"

    def __init__(self, advisories: list[dict]) -> None:
        self.advisories = advisories

    def query(self, ecosystem: str, package: str, version: str) -> list[dict]:
        return list(self.advisories)


class KnowledgeStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path); self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS document(id INTEGER PRIMARY KEY,category TEXT,source_id TEXT,title TEXT,summary TEXT,content TEXT,source_url TEXT,content_hash TEXT,metadata TEXT,retrieved_at TEXT,UNIQUE(category,source_id,content_hash));
        CREATE VIRTUAL TABLE IF NOT EXISTS document_fts USING fts5(title,summary,content,content='document',content_rowid='id');
        CREATE TRIGGER IF NOT EXISTS document_ai AFTER INSERT ON document BEGIN INSERT INTO document_fts(rowid,title,summary,content) VALUES(new.id,new.title,new.summary,new.content); END;
        """); self.db.commit()

    def ingest(self, *, category: str, source_id: str, title: str, summary: str = "", content: str = "", source_url: str = "", metadata: dict | None = None) -> int:
        digest = hashlib.sha256((title + "\n" + summary + "\n" + content).encode()).hexdigest()
        cur = self.db.execute("INSERT OR IGNORE INTO document(category,source_id,title,summary,content,source_url,content_hash,metadata,retrieved_at) VALUES(?,?,?,?,?,?,?,?,?)", (category, source_id, title, summary, content, source_url, digest, json.dumps(metadata or {}), utcnow()))
        self.db.commit()
        if cur.lastrowid: return int(cur.lastrowid)
        return int(self.db.execute("SELECT id FROM document WHERE category=? AND source_id=? AND content_hash=?", (category, source_id, digest)).fetchone()[0])

    def import_cwe(self, document: dict, *, source_version: str) -> int:
        cwe_id = str(document.get("id") or document.get("cwe_id"))
        return self.ingest(category="CWE", source_id=cwe_id, title=f"CWE-{cwe_id}: {document.get('name','')}", summary=str(document.get("summary") or document.get("description") or ""), content=json.dumps({key: document.get(key) for key in ("consequences", "mitigations", "related_weaknesses")}), metadata={"source_version": source_version, "source": "MITRE CWE"})

    def import_cwe_json(self, path: Path | str, *, source_version: str) -> list[int]:
        """Import a user-downloaded official MITRE CWE JSON conversion."""
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        items = document.get("weaknesses", document) if isinstance(document, dict) else document
        if not isinstance(items, list):
            raise ValueError("CWE import must contain a weaknesses list")
        return [self.import_cwe(item, source_version=source_version) for item in items]

    def cache_advisory(self, *, ecosystem: str, package: str, version: str, advisory: dict) -> int:
        advisory_id = str(advisory.get("id") or hashlib.sha256(json.dumps(advisory, sort_keys=True).encode()).hexdigest()[:16])
        return self.ingest(category="ADVISORY", source_id=advisory_id, title=str(advisory.get("summary") or advisory_id), summary=f"{ecosystem}:{package}@{version}", content=json.dumps(advisory), source_url=str((advisory.get("references") or [{}])[0].get("url", "")), metadata={"ecosystem": ecosystem, "package": package, "version": version, "observation_only": True})

    def sync_advisories(self, provider: AdvisoryProvider, *, ecosystem: str, package: str, version: str) -> list[int]:
        return [self.cache_advisory(ecosystem=ecosystem, package=package, version=version, advisory=item) for item in provider.query(ecosystem, package, version)]

    def import_report(self, *, source_id: str, title: str, summary: str, tags: list[str], source_url: str = "") -> int:
        return self.ingest(category="PUBLIC_REPORT", source_id=source_id, title=title, summary=summary, content=" ".join(tags), source_url=source_url, metadata={"tags": tags})

    def search(self, query: str, *, categories: list[str] | None = None, limit: int = 10) -> list[dict]:
        sql = "SELECT d.*,bm25(document_fts) rank FROM document_fts JOIN document d ON d.id=document_fts.rowid WHERE document_fts MATCH ?"
        args: list = [query]
        if categories:
            sql += " AND d.category IN (%s)" % ",".join("?" for _ in categories); args += categories
        sql += " ORDER BY rank LIMIT ?"; args.append(max(1, min(limit, 50)))
        return [{"id": row["id"], "category": row["category"], "title": row["title"], "summary": row["summary"][:500], "source_url": row["source_url"], "observation_only": True} for row in self.db.execute(sql, tuple(args)).fetchall()]

    def close(self) -> None: self.db.close()


__all__ = ["KnowledgeStore", "AdvisoryProvider", "OSVProvider", "FixtureAdvisoryProvider"]
