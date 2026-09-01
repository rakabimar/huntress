"""Deterministic response comparison; results are observations, never verdicts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from ..state.records import RequestRecord


@dataclass
class DifferentialResponse:
    request_ids: list[str]
    status: list[int | None]
    status_class_changed: bool
    redirect_locations: list[str]
    content_types: list[str]
    important_header_differences: dict[str, list[str | None]]
    body_lengths: list[int]
    length_delta: int
    body_hashes: list[str]
    text_similarity: float
    json_differences: dict[str, Any] = field(default_factory=dict)
    timing_ms: list[float | None] = field(default_factory=list)
    clusters: list[list[str]] = field(default_factory=list)
    set_cookie_changed: bool = False
    observation_only: bool = True

    def as_dict(self) -> dict:
        return asdict(self)


class ResponseComparator:
    IMPORTANT_HEADERS = (
        "location", "content-type", "cache-control", "vary", "etag", "age",
        "www-authenticate", "x-cache", "cf-cache-status", "set-cookie",
    )

    def __init__(self, *, ignore_json_paths: set[str] | None = None) -> None:
        self.ignore_json_paths = ignore_json_paths or set()

    def compare_records(self, records: list[RequestRecord], *, workspace: Path | None = None) -> DifferentialResponse:
        if len(records) < 2:
            raise ValueError("at least two request records are required")
        responses = [self._response(record, workspace) for record in records]
        bodies = [str(response.get("body", "")) for response in responses]
        statuses = [_int_or_none(response.get("status")) for response in responses]
        headers = [{str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()} for response in responses]
        hashes = [hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() for body in bodies]
        similarities = [self._text_similarity(bodies[0], body) for body in bodies[1:]]
        json_diff: dict[str, Any] = {}
        parsed = [_json_or_none(body) for body in bodies]
        if all(item is not None for item in parsed):
            json_diff = self._json_compare(parsed[0], parsed[1:])
        header_diff = {
            name: [h.get(name) for h in headers]
            for name in self.IMPORTANT_HEADERS
            if len({h.get(name) for h in headers}) > 1
        }
        clusters: dict[tuple, list[str]] = {}
        for record, status, digest, response in zip(records, statuses, hashes, responses):
            key = (status, digest, str((response.get("headers") or {}).get("Content-Type", "")).split(";", 1)[0])
            clusters.setdefault(key, []).append(record.public_id)
        lengths = [int(response.get("body_length", len(body.encode()))) for response, body in zip(responses, bodies)]
        timing = [record.response_metadata.get("timing_ms") for record in records]
        return DifferentialResponse(
            request_ids=[record.public_id for record in records], status=statuses,
            status_class_changed=len({s // 100 if s else None for s in statuses}) > 1,
            redirect_locations=[h.get("location", "") for h in headers],
            content_types=[h.get("content-type", "") for h in headers],
            important_header_differences=header_diff, body_lengths=lengths,
            length_delta=max(lengths) - min(lengths), body_hashes=hashes,
            text_similarity=min(similarities) if similarities else 1.0,
            json_differences=json_diff, timing_ms=timing,
            clusters=list(clusters.values()), set_cookie_changed="set-cookie" in header_diff,
        )

    def _response(self, record: RequestRecord, workspace: Path | None) -> dict:
        if workspace and record.evidence_ref:
            path = Path(workspace) / "evidence" / f"{record.evidence_ref}.json"
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                return dict(doc.get("response") or {})
            except (OSError, json.JSONDecodeError):
                pass
        return {
            "status": record.response_metadata.get("status"),
            "headers": record.response_metadata.get("headers", {}),
            "body": record.response_metadata.get("body", ""),
            "body_length": record.response_metadata.get("length", 0),
        }

    @staticmethod
    def _text_similarity(left: str, right: str) -> float:
        normalize = lambda value: re.findall(r"[a-z0-9_:/.-]+", value.lower())
        a, b = set(normalize(left)), set(normalize(right))
        jaccard = len(a & b) / len(a | b) if a or b else 1.0
        sequence = SequenceMatcher(None, " ".join(normalize(left)), " ".join(normalize(right)), autojunk=False).ratio()
        return round((jaccard + sequence) / 2, 6)

    def _json_compare(self, baseline: Any, others: list[Any]) -> dict:
        output = []
        for other in others:
            changes: list[dict] = []
            self._walk_json(baseline, other, "$", changes)
            output.append(changes)
        total = max(1, len(_flatten_json(baseline)))
        return {
            "comparisons": output,
            "structural_similarity": [round(max(0.0, 1 - len(changes) / total), 6) for changes in output],
        }

    def _walk_json(self, left: Any, right: Any, path: str, changes: list[dict]) -> None:
        if path in self.ignore_json_paths:
            return
        if type(left) is not type(right):
            changes.append({"path": path, "kind": "changed_type", "from": type(left).__name__, "to": type(right).__name__})
        elif isinstance(left, dict):
            for key in sorted(left.keys() - right.keys()):
                changes.append({"path": f"{path}.{key}", "kind": "removed_key"})
            for key in sorted(right.keys() - left.keys()):
                changes.append({"path": f"{path}.{key}", "kind": "added_key"})
            for key in sorted(left.keys() & right.keys()):
                self._walk_json(left[key], right[key], f"{path}.{key}", changes)
        elif isinstance(left, list):
            if len(left) != len(right):
                changes.append({"path": path, "kind": "array_cardinality", "from": len(left), "to": len(right)})
            for index, (a, b) in enumerate(zip(left, right)):
                self._walk_json(a, b, f"{path}[{index}]", changes)
        elif left != right:
            changes.append({"path": path, "kind": "changed_value", "from": left, "to": right})


def _json_or_none(value: str) -> Any | None:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


def _flatten_json(value: Any, prefix: str = "$") -> list[str]:
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in _flatten_json(child, f"{prefix}.{key}")]
    if isinstance(value, list):
        return [item for index, child in enumerate(value) for item in _flatten_json(child, f"{prefix}[{index}]")]
    return [prefix]


def _int_or_none(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["ResponseComparator", "DifferentialResponse"]
