"""Explicit generic importer for local exports and confirmed official URLs."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .base import PlatformAdapter
from ..fetcher import IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities, SourceType
from ..provenance import SnapshotWriter


_NETWORK_TOKEN = re.compile(
    r"(?<![\w.-])(https?://[^\s<>()\[\]{}]+|\*\.[a-zA-Z0-9.-]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)"
)


class GenericAdapter(PlatformAdapter):
    name = "generic"
    version = "1.0"
    official_hosts: set[str] = set()

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(program_metadata=True, policy_text=True)

    def resolve_handle(self, *, handle: str | None, url: str | None) -> str:
        if handle:
            return handle.strip()
        if url:
            parsed = urlparse(url)
            candidate = (parsed.path.rstrip("/").split("/")[-1] or parsed.hostname or "program")
            return re.sub(r"[^a-zA-Z0-9_-]+", "-", candidate).strip("-").lower()
        return "imported-program"

    def fetch(self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
              snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
              from_file: Path | None = None) -> AdapterPayload:
        if from_file:
            raw = from_file.read_bytes()
            source = str(from_file.resolve())
            source_type = SourceType.HUMAN_INPUT
        elif url:
            result = fetcher.get(url, headers={"Accept": "application/json, text/html, text/plain"})
            raw = result.body
            source = result.url
            source_type = SourceType.OFFICIAL_STRUCTURED_HTML
        else:
            raise ValueError("generic import requires --from-file/--from-json or --url")
        suffix = (from_file.suffix.lower() if from_file else Path(urlparse(url or "").path).suffix.lower())
        if suffix == ".json" or raw.lstrip().startswith((b"{", b"[")):
            document = json.loads(raw)
            snapshot.write("source.json", document, source_type=source_type, source_identifier=source)
            return self._from_json(handle, url, document, snapshot)
        text = raw.decode("utf-8", errors="replace")
        if "<html" in text.lower() or "<body" in text.lower():
            snapshot.write("source.html", raw, source_type=source_type, source_identifier=source)
            text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.I | re.S)
            text = html.unescape(re.sub(r"<[^>]+>", "\n", text))
        else:
            snapshot.write("policy.md", raw, source_type=source_type, source_identifier=source)
        scopes = self._extract_scope_tokens(text)
        program = {"data": {"id": handle, "type": "program", "attributes": {
            "handle": handle, "name": handle, "policy": text, "submission_state": "unknown"}}}
        capabilities = PlatformCapabilities(
            program_metadata=True, structured_scope=bool(scopes), policy_text=True,
            availability={"source_quality": "GENERIC_REQUIRES_HUMAN_REVIEW"},
        )
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=url,
            capabilities=capabilities, program=program, scopes=scopes,
            policy_text=text, sources=list(snapshot.sources),
        )

    def _from_json(self, handle: str, url: str | None, document: dict | list,
                   snapshot: SnapshotWriter) -> AdapterPayload:
        if isinstance(document, list):
            document = {"scopes": document}
        raw_program = document.get("program", {})
        if "data" in raw_program:
            program = raw_program
        else:
            program = {"data": {"id": raw_program.get("id", handle), "type": "program", "attributes": {
                "handle": raw_program.get("handle", handle), "name": raw_program.get("name", handle),
                "policy": raw_program.get("policy", document.get("policy", "")),
                "submission_state": raw_program.get("submission_state", "unknown"),
            }}}
        raw_scopes = document.get("scopes", document.get("scope", []))
        scopes = []
        for index, item in enumerate(raw_scopes):
            if isinstance(item, str):
                attrs = {"asset_identifier": item, "asset_type": "OTHER",
                         "eligible_for_submission": None, "eligible_for_bounty": None}
                scopes.append({"id": str(index + 1), "type": "structured-scope", "attributes": attrs})
            elif isinstance(item, dict) and "attributes" in item:
                scopes.append(item)
            elif isinstance(item, dict):
                scopes.append({"id": str(item.get("id", index + 1)), "type": "structured-scope", "attributes": item})
        policy = program.get("data", {}).get("attributes", {}).get("policy", "")
        capabilities = PlatformCapabilities(program_metadata=True, structured_scope=bool(scopes), policy_text=bool(policy))
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=url, capabilities=capabilities,
            program=program, scopes=scopes, exclusions=document.get("exclusions", []),
            policy_text=policy, sources=list(snapshot.sources),
        )

    @staticmethod
    def _extract_scope_tokens(text: str) -> list[dict]:
        scopes = []
        seen = set()
        for index, match in enumerate(_NETWORK_TOKEN.finditer(text), 1):
            token = match.group(1).rstrip(".,;:)")
            if token in seen:
                continue
            seen.add(token)
            scopes.append({"id": str(index), "type": "structured-scope", "attributes": {
                "asset_identifier": token, "asset_type": "OTHER",
                "eligible_for_submission": None, "eligible_for_bounty": None,
            }})
        return scopes


__all__ = ["GenericAdapter"]
