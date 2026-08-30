"""HackerOne Hacker API v1 adapter (researcher-facing, GET-only)."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .base import PlatformAdapter
from ..fetcher import IntakeFetchError, IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities, SourceType
from ..provenance import SnapshotWriter
from ..policy_documents import extract_policy_document


class HackerOneAdapter(PlatformAdapter):
    name = "hackerone"
    version = "2026-04-19"
    official_hosts = {"api.hackerone.com", "hackerone.com", "www.hackerone.com"}
    # Current official documentation records 50 requests/minute for structured scopes.
    requests_per_minute = 50
    API_ROOT = "https://api.hackerone.com/v1/hackers/programs"

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            program_metadata=True, structured_scope=True, scope_exclusions=True,
            policy_text=True, reward_data=True, reporting_metadata=True,
            change_timestamps=True, public_api=True, authenticated_api=True,
        )

    def resolve_handle(self, *, handle: str | None, url: str | None) -> str:
        if handle:
            candidate = handle.strip().lower()
        elif url:
            parsed = urlparse(url)
            if (parsed.hostname or "").lower() not in {"hackerone.com", "www.hackerone.com"}:
                raise ValueError("HackerOne URL must use hackerone.com")
            parts = [part for part in parsed.path.split("/") if part]
            if not parts:
                raise ValueError("HackerOne URL does not contain a program handle")
            candidate = parts[0].lower()
        else:
            raise ValueError("HackerOne import requires --handle or --url")
        if not re.fullmatch(r"[a-z0-9_-]{2,100}", candidate):
            raise ValueError("invalid HackerOne program handle")
        if url:
            parsed = urlparse(url)
            if (parsed.hostname or "").lower() not in {"hackerone.com", "www.hackerone.com"}:
                raise ValueError("HackerOne URL host does not match adapter")
        return candidate

    def fetch(
        self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
        snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
        from_file: Path | None = None,
    ) -> AdapterPayload:
        if from_file:
            payload = json.loads(from_file.read_text(encoding="utf-8"))
            return self._fixture_payload(handle, payload, snapshot)
        if isinstance(credential, tuple):
            return self._fetch_api(handle, fetcher, snapshot, credential)
        return self._fetch_public(handle, fetcher, snapshot)

    def _fetch_api(
        self, handle: str, fetcher: IntakeFetcher, snapshot: SnapshotWriter,
        credential: tuple[str, str],
    ) -> AdapterPayload:
        program_url = f"{self.API_ROOT}/{handle}"
        result = fetcher.get(program_url, auth=credential)
        program = result.json()
        snapshot.write(
            "program.json", program, source_type=SourceType.OFFICIAL_STRUCTURED_API,
            source_identifier=program_url, status=result.status_code,
            etag=result.headers.get("ETag"), last_modified=result.headers.get("Last-Modified"),
        )

        scope_url = f"{program_url}/structured_scopes?page[size]=100"
        scope_pages = fetcher.json_pages(scope_url, auth=credential)
        scopes: list[dict] = []
        for index, page in enumerate(scope_pages, 1):
            body = page.json()
            scopes.extend(body.get("data", []))
            snapshot.write(
                f"structured_scopes_page{index}.json", body,
                source_type=SourceType.OFFICIAL_STRUCTURED_API,
                source_identifier=page.url, status=page.status_code,
                etag=page.headers.get("ETag"), last_modified=page.headers.get("Last-Modified"),
                metadata={"page": index},
            )

        exclusions_url = f"{program_url}/scope_exclusions"
        exclusion_pages = fetcher.json_pages(exclusions_url, auth=credential)
        exclusions: list[dict] = []
        for index, page in enumerate(exclusion_pages, 1):
            body = page.json()
            exclusions.extend(body.get("data", []))
            snapshot.write(
                "scope_exclusions.json" if index == 1 else f"scope_exclusions_page{index}.json",
                body, source_type=SourceType.OFFICIAL_STRUCTURED_API,
                source_identifier=page.url, status=page.status_code,
                etag=page.headers.get("ETag"), last_modified=page.headers.get("Last-Modified"),
            )

        attrs = program.get("data", {}).get("attributes", {})
        policy = attrs.get("policy") or ""
        if policy:
            snapshot.write(
                "policy.md", policy, source_type=SourceType.OFFICIAL_POLICY_TEXT,
                source_identifier=f"{program_url}#attributes.policy", status=result.status_code,
            )
            linked_text = self._fetch_linked_policy_documents(policy, fetcher, snapshot)
            if linked_text:
                policy = policy + "\n\n# Official linked policy documents\n\n" + linked_text
        return AdapterPayload(
            platform=self.name, handle=handle,
            program_url=f"https://hackerone.com/{handle}", capabilities=self.capabilities,
            program=program, scopes=scopes, exclusions=exclusions,
            policy_text=policy, sources=list(snapshot.sources),
        )

    def _fetch_linked_policy_documents(
        self, policy: str, fetcher: IntakeFetcher, snapshot: SnapshotWriter,
    ) -> str:
        """Fetch one level of explicitly linked official policy documents only."""
        links = []
        for match in re.finditer(r"https://[^\s<>()\]]+", policy, re.I):
            candidate = match.group(0).rstrip(".,;")
            if candidate not in links:
                links.append(candidate)
        extracted_parts = []
        for index, candidate in enumerate(links[:10], 1):
            parsed = urlparse(candidate)
            if (parsed.hostname or "").lower() not in self.official_hosts:
                continue
            try:
                result = fetcher.get(candidate, headers={"Accept": "application/pdf, text/markdown, text/plain, text/html, application/json"})
            except IntakeFetchError:
                continue
            suffix = Path(parsed.path).suffix.lower()
            name = f"attachment_{index}{suffix if suffix in {'.pdf', '.md', '.txt', '.html', '.json'} else '.bin'}"
            snapshot.write(
                name, result.body, source_type=SourceType.OFFICIAL_POLICY_TEXT,
                source_identifier=candidate, status=result.status_code,
                etag=result.headers.get("ETag"), last_modified=result.headers.get("Last-Modified"),
                metadata={"linked_from": "program_policy", "parsed": False,
                          "content_type": result.headers.get("Content-Type", "")},
            )
            try:
                text, extraction = extract_policy_document(
                    result.body, content_type=result.headers.get("Content-Type", ""), suffix=suffix,
                )
            except IntakeFetchError:
                continue
            snapshot.write(
                f"attachment_{index}_extracted.txt", text,
                source_type=SourceType.OFFICIAL_POLICY_TEXT,
                source_identifier=candidate, status=result.status_code,
                metadata={"linked_from": "program_policy", **extraction},
            )
            extracted_parts.append(f"## {candidate}\n{text}")
        return "\n\n".join(extracted_parts)

    def _fetch_public(
        self, handle: str, fetcher: IntakeFetcher, snapshot: SnapshotWriter,
    ) -> AdapterPayload:
        public_url = f"https://hackerone.com/{handle}"
        result = fetcher.get(public_url, headers={"Accept": "text/html"})
        text = result.text
        snapshot.write(
            "program.html", text, source_type=SourceType.OFFICIAL_STRUCTURED_HTML,
            source_identifier=public_url, status=result.status_code,
            etag=result.headers.get("ETag"), last_modified=result.headers.get("Last-Modified"),
        )
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = html.unescape(re.sub(r"<[^>]+>", "", title_match.group(1))).strip() if title_match else handle
        # Deterministic fallback deliberately does not claim structured scope.
        policy = ""
        next_match = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', text, re.I | re.S)
        embedded = None
        if next_match:
            try:
                embedded = json.loads(html.unescape(next_match.group(1)))
            except json.JSONDecodeError:
                embedded = None
        program = {"data": {"id": handle, "type": "program", "attributes": {
            "handle": handle, "name": title, "policy": policy,
            "submission_state": "unknown", "state": "public_mode",
        }}, "public_page_data": embedded}
        capabilities = PlatformCapabilities(
            program_metadata=True, structured_scope=False, scope_exclusions=False,
            policy_text=False, public_api=True, authenticated_api=False,
            availability={
                "structured_scope": "CREDENTIAL_REQUIRED",
                "scope_exclusions": "CREDENTIAL_REQUIRED",
                "policy_text": "DETERMINISTIC_PUBLIC_EXTRACTION_UNAVAILABLE",
            },
        )
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=public_url,
            capabilities=capabilities, program=program, scopes=[], exclusions=[],
            policy_text=policy, sources=list(snapshot.sources),
        )

    def _fixture_payload(self, handle: str, payload: dict, snapshot: SnapshotWriter) -> AdapterPayload:
        """Offline combined fixture format used only by tests and saved exports."""
        program = payload.get("program", payload)
        scopes = payload.get("scopes", [])
        exclusions = payload.get("exclusions", [])
        attrs = program.get("data", {}).get("attributes", {})
        snapshot.write("program.json", program, source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier="fixture:hackerone:program")
        snapshot.write("structured_scopes.json", {"data": scopes},
                       source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier="fixture:hackerone:structured_scopes")
        snapshot.write("scope_exclusions.json", {"data": exclusions},
                       source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier="fixture:hackerone:scope_exclusions")
        policy = attrs.get("policy") or payload.get("policy", "")
        if policy:
            snapshot.write("policy.md", policy, source_type=SourceType.OFFICIAL_POLICY_TEXT,
                           source_identifier="fixture:hackerone:policy")
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=f"https://hackerone.com/{handle}",
            capabilities=self.capabilities, program=program, scopes=scopes,
            exclusions=exclusions, policy_text=policy, sources=list(snapshot.sources),
        )


__all__ = ["HackerOneAdapter"]
