"""Raw source snapshot storage and content provenance helpers."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .models import SOURCE_TRUST, SourceArtifact, SourceType, utcnow

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]+")


def content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def excerpt_hash(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


class SnapshotWriter:
    """Writes only response bodies and non-sensitive response metadata."""

    def __init__(self, workspace: Path, import_id: str) -> None:
        self.workspace = Path(workspace)
        self.import_id = import_id
        self.root = self.workspace / "intake" / import_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.sources: list[SourceArtifact] = []

    def write(
        self, name: str, content: bytes | str | dict | list, *,
        source_type: SourceType, source_identifier: str, status: int | str = 200,
        etag: str | None = None, last_modified: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SourceArtifact:
        safe = _SAFE_NAME.sub("_", name).strip("._") or "source"
        if isinstance(content, (dict, list)):
            raw = (json.dumps(content, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
        elif isinstance(content, str):
            raw = content.encode("utf-8")
        else:
            raw = bytes(content)
        path = self.root / safe
        path.write_bytes(raw)
        artifact = SourceArtifact(
            source_type=source_type,
            source_identifier=source_identifier,
            retrieved_at=utcnow(),
            content_hash=content_hash(raw),
            artifact_ref=str(path.relative_to(self.workspace)),
            trust_level=SOURCE_TRUST[source_type],
            status=status,
            etag=etag,
            last_modified=last_modified,
            metadata=metadata or {},
        )
        self.sources.append(artifact)
        return artifact

    def finalize(self, *, adapter_version: str, parser_version: str) -> Path:
        manifest = {
            "import_id": self.import_id,
            "adapter_version": adapter_version,
            "parser_version": parser_version,
            "created_at": utcnow(),
            "sources": [source.model_dump(mode="json") for source in self.sources],
        }
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return path


__all__ = ["SnapshotWriter", "content_hash", "excerpt_hash"]
