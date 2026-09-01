"""Canonical secret-free request templates and structured one-field mutations."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..errors import StateError
from ..state.records import RequestRecord


class MutationLocation(StrEnum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    JSON = "json"
    FORM = "form"
    MULTIPART = "multipart"
    RAW = "raw"


class MutationOperation(StrEnum):
    SET = "SET"
    DELETE = "DELETE"
    ADD = "ADD"
    APPEND = "APPEND"
    REPLACE = "REPLACE"


@dataclass(frozen=True)
class RequestMutation:
    location: MutationLocation | str
    field: str
    operation: MutationOperation | str
    new_value: object | None = None
    reason: str = ""
    source_skill: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "location", MutationLocation(self.location))
        object.__setattr__(self, "operation", MutationOperation(self.operation))
        if self.location == MutationLocation.HEADER and self.field.lower() in {
            "authorization", "cookie", "proxy-authorization", "set-cookie",
        }:
            raise ValueError("credentials may only change through AuthContext/session lifecycle")

    def as_dict(self) -> dict:
        value = asdict(self)
        value["location"] = self.location.value
        value["operation"] = self.operation.value
        return value


@dataclass
class RequestTemplate:
    method: str
    url: str
    query_parameters: list[tuple[str, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    body_type: str = "none"
    body: object | None = None
    auth_context: str = ""
    originating_request_id: int | None = None
    originating_evidence_id: str | None = None
    program: str = ""
    target: str = ""
    created_at: str = ""

    @classmethod
    def from_request_record(cls, record: RequestRecord, *, workspace: Path | None = None) -> "RequestTemplate":
        artifact = None
        if workspace and record.evidence_ref:
            artifact = Path(workspace) / "evidence" / f"{record.evidence_ref}.json"
        doc = _read_evidence_artifact(artifact) if artifact else {}
        req = doc.get("request", {}) if isinstance(doc, dict) else {}
        headers = _safe_template_headers(dict(req.get("headers") or record.request_metadata.get("headers") or {}))
        url = str(req.get("url") or record.url)
        body = req.get("body")
        content_type = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
        body_type, parsed = _decode_body(body, content_type)
        return cls(
            method=record.method, url=url,
            query_parameters=parse_qsl(urlsplit(url).query, keep_blank_values=True),
            headers=headers, content_type=content_type, body_type=body_type, body=parsed,
            auth_context=record.auth_context, originating_request_id=record.id,
            originating_evidence_id=record.evidence_ref or None, program=record.program,
            target=url, created_at=record.created_at,
        )

    @classmethod
    def from_evidence(cls, evidence_path: Path, *, evidence_id: str = "") -> "RequestTemplate":
        doc = _read_evidence_artifact(evidence_path)
        req = doc.get("request", {})
        headers = _safe_template_headers(dict(req.get("headers") or {}))
        url = str(req.get("url") or "")
        content_type = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
        body_type, body = _decode_body(req.get("body"), content_type)
        return cls(
            method=str(req.get("method", "GET")).upper(), url=url,
            query_parameters=parse_qsl(urlsplit(url).query, keep_blank_values=True),
            headers=headers, content_type=content_type, body_type=body_type, body=body,
            auth_context=str(req.get("auth_context") or ""),
            originating_evidence_id=evidence_id or None,
            program=str(doc.get("program") or ""), target=url, created_at=str(doc.get("timestamp") or ""),
        )

    @classmethod
    def from_burp_request(
        cls, raw_request: str, *, program: str, target: str = "", auth_context: str = "",
    ) -> "RequestTemplate":
        """Parse one imported Burp request without importing credential values."""
        head, _, body_text = raw_request.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        if not lines or len(lines[0].split()) < 2:
            raise ValueError("invalid Burp HTTP request line")
        method, request_target = lines[0].split()[:2]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line: continue
            name, value = line.split(":", 1)
            if name.strip().lower() in {"authorization", "cookie", "proxy-authorization"}:
                continue
            headers[name.strip()] = value.strip()
        headers = _safe_template_headers(headers)
        if "://" in request_target:
            url = request_target
        else:
            host = next((value for name, value in headers.items() if name.lower() == "host"), "")
            base = target.rstrip("/") if target else (f"https://{host}" if host else "")
            if not base: raise ValueError("relative Burp request requires target or Host")
            url = base + "/" + request_target.lstrip("/")
        content_type = next((value for name, value in headers.items() if name.lower() == "content-type"), "")
        body_type, body = _decode_body(body_text, content_type)
        return cls(method.upper(), url, parse_qsl(urlsplit(url).query, keep_blank_values=True), headers,
                   content_type, body_type, body, auth_context, program=program, target=url)

    def mutated(self, mutations: list[RequestMutation]) -> "RequestTemplate":
        result = copy.deepcopy(self)
        for mutation in mutations:
            result._apply(mutation)
        return result

    def _apply(self, mutation: RequestMutation) -> None:
        op, field_name, value = mutation.operation, mutation.field, mutation.new_value
        if mutation.location == MutationLocation.QUERY:
            self.query_parameters = _mutate_pairs(self.query_parameters, field_name, op, value)
        elif mutation.location == MutationLocation.HEADER:
            _mutate_mapping(self.headers, field_name, op, value, case_insensitive=True)
        elif mutation.location == MutationLocation.JSON:
            if self.body_type != "json":
                raise ValueError("JSON mutation requires a JSON request body")
            _mutate_json_path(self.body, field_name, op, value)
        elif mutation.location == MutationLocation.FORM:
            if self.body_type != "form":
                raise ValueError("form mutation requires form-urlencoded body")
            self.body = _mutate_pairs(list(self.body or []), field_name, op, value)
        elif mutation.location == MutationLocation.PATH:
            self._mutate_path(field_name, op, value)
        elif mutation.location == MutationLocation.RAW:
            if self.body_type not in {"raw", "none"}:
                raise ValueError("raw mutation is only available for unstructured bodies")
            self.body = _mutate_scalar(str(self.body or ""), op, value)
            self.body_type = "raw"
        elif mutation.location == MutationLocation.MULTIPART:
            if self.body_type != "multipart" or not isinstance(self.body, dict):
                raise ValueError("multipart mutation requires parsed multipart metadata")
            part_name, _, property_name = field_name.partition(".")
            if property_name not in {"filename", "content_type"} or op not in {MutationOperation.SET, MutationOperation.REPLACE}:
                raise ValueError("multipart permits SET/REPLACE of explicit filename/content_type metadata")
            part = next((item for item in self.body.get("parts", []) if item.get("name") == part_name), None)
            if part is None: raise ValueError("multipart part metadata not found")
            old = str(part.get(property_name, "")); part[property_name] = str(value or "")
            raw = str(self.body.get("raw", ""))
            if old: raw = raw.replace(old, str(value or ""), 1)
            self.body["raw"] = raw
        else:
            raise ValueError("unsupported request mutation location")
        parts = urlsplit(self.url)
        self.url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(self.query_parameters, doseq=True), ""))
        self.target = self.url

    def _mutate_path(self, field_name: str, op: MutationOperation, value: object | None) -> None:
        if not field_name.isdigit():
            raise ValueError("path mutation field must be an explicit zero-based segment index")
        parts = urlsplit(self.url)
        segments = parts.path.split("/")
        indexes = [i for i, segment in enumerate(segments) if segment]
        index = int(field_name)
        if index >= len(indexes):
            raise ValueError("path segment index is out of range")
        actual = indexes[index]
        if op == MutationOperation.DELETE:
            del segments[actual]
        elif op in {MutationOperation.SET, MutationOperation.REPLACE}:
            segments[actual] = str(value or "")
        elif op == MutationOperation.APPEND:
            segments[actual] += str(value or "")
        else:
            segments.insert(actual + 1, str(value or ""))
        self.url = urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, ""))

    def broker_kwargs(self) -> dict:
        parts = urlsplit(self.url)
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        kwargs: dict = {"target": target, "method": self.method, "headers": dict(self.headers)}
        kwargs["params"] = self.query_parameters
        if self.body_type == "json":
            kwargs["json_body"] = self.body
        elif self.body_type == "form":
            kwargs["body"] = urlencode(list(self.body or []), doseq=True)
        elif self.body_type == "raw":
            kwargs["body"] = str(self.body or "")
        elif self.body_type == "multipart":
            kwargs["body"] = str((self.body or {}).get("raw", ""))
        return kwargs


def _read_evidence_artifact(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StateError(f"request evidence artifact is unreadable: {path}") from exc
    if value.get("schema") != "bughunt.request_response.v1":
        raise StateError("evidence does not contain a broker request")
    return value


def _safe_template_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if name.lower() not in {
        "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token",
    }}


def _decode_body(body: object, content_type: str) -> tuple[str, object | None]:
    if body in (None, ""):
        return "none", None
    if "json" in content_type.lower():
        try:
            return "json", json.loads(str(body))
        except json.JSONDecodeError:
            return "raw", str(body)
    if "application/x-www-form-urlencoded" in content_type.lower():
        return "form", parse_qsl(str(body), keep_blank_values=True)
    if "multipart/form-data" in content_type.lower():
        raw = str(body); parts = []
        for match in re.finditer(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]*)")?', raw, re.I):
            tail = raw[match.end(): raw.find("\n\n", match.end()) if "\n\n" in raw[match.end():] else match.end()]
            content_match = re.search(r"Content-Type:\s*([^\r\n]+)", tail, re.I)
            parts.append({"name": match.group(1), "filename": match.group(2) or "", "content_type": content_match.group(1).strip() if content_match else ""})
        return "multipart", {"raw": raw, "parts": parts}
    return "raw", str(body)


def _mutate_pairs(pairs: list[tuple[str, str]], key: str, op: MutationOperation, value: object | None) -> list[tuple[str, str]]:
    result = list(pairs)
    indexes = [i for i, (name, _) in enumerate(result) if name == key]
    if op == MutationOperation.DELETE:
        return [pair for pair in result if pair[0] != key]
    if op == MutationOperation.ADD:
        result.append((key, str(value or "")))
    elif not indexes:
        result.append((key, str(value or "")))
    elif op == MutationOperation.APPEND:
        i = indexes[-1]; result[i] = (key, result[i][1] + str(value or ""))
    else:
        result[indexes[0]] = (key, str(value or ""))
    return result


def _mutate_mapping(mapping: dict, key: str, op: MutationOperation, value: object | None, *, case_insensitive: bool = False) -> None:
    existing = next((item for item in mapping if (item.lower() == key.lower() if case_insensitive else item == key)), key)
    if op == MutationOperation.DELETE:
        mapping.pop(existing, None)
    elif op == MutationOperation.ADD and existing in mapping:
        raise ValueError(f"field {key!r} already exists")
    elif op == MutationOperation.APPEND:
        mapping[existing] = str(mapping.get(existing, "")) + str(value or "")
    else:
        mapping[existing] = value


_PATH_TOKEN = re.compile(r"(?:^|\.)([A-Za-z_][\w-]*)|\[(\d+)\]")


def _json_tokens(path: str) -> list[str | int]:
    if path.startswith("body."):
        path = path[5:]
    tokens: list[str | int] = []
    consumed = ""
    for match in _PATH_TOKEN.finditer(path):
        tokens.append(int(match.group(2)) if match.group(2) is not None else match.group(1))
        consumed += match.group(0)
    if not tokens or consumed.lstrip(".") != path.lstrip("."):
        raise ValueError("invalid safe JSON field path")
    return tokens


def _mutate_json_path(document: object, path: str, op: MutationOperation, value: object | None) -> None:
    tokens = _json_tokens(path)
    parent = document
    for token in tokens[:-1]:
        parent = parent[token]  # type: ignore[index]
    leaf = tokens[-1]
    if isinstance(parent, dict):
        if op == MutationOperation.DELETE:
            parent.pop(leaf, None)
        elif op == MutationOperation.ADD and leaf in parent:
            raise ValueError("JSON field already exists")
        elif op == MutationOperation.APPEND:
            parent[leaf] = _append_value(parent.get(leaf), value)
        else:
            parent[leaf] = value
    elif isinstance(parent, list) and isinstance(leaf, int):
        if op == MutationOperation.DELETE:
            del parent[leaf]
        elif op == MutationOperation.ADD:
            parent.insert(leaf, value)
        elif op == MutationOperation.APPEND:
            parent[leaf] = _append_value(parent[leaf], value)
        else:
            parent[leaf] = value
    else:
        raise ValueError("JSON field path does not resolve to a mutable container")


def _append_value(old: object, value: object) -> object:
    if isinstance(old, list):
        return old + [value]
    return str(old if old is not None else "") + str(value or "")


def _mutate_scalar(old: str, op: MutationOperation, value: object | None) -> str:
    if op == MutationOperation.DELETE:
        return ""
    if op == MutationOperation.APPEND:
        return old + str(value or "")
    if op in {MutationOperation.SET, MutationOperation.REPLACE, MutationOperation.ADD}:
        return str(value or "")
    raise ValueError("unsupported scalar mutation")


__all__ = ["RequestTemplate", "RequestMutation", "MutationLocation", "MutationOperation"]
