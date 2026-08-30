"""Bugcrowd JSON:API adapter with explicit capability downgrade."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote, urlparse

from .base import PlatformAdapter
from ..fetcher import IntakeFetchError, IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities, SourceType
from ..provenance import SnapshotWriter


class BugcrowdAdapter(PlatformAdapter):
    name = "bugcrowd"
    version = "current-jsonapi"
    official_hosts = {"api.bugcrowd.com", "bugcrowd.com", "www.bugcrowd.com"}
    requests_per_minute = 60

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            program_metadata=True, structured_scope=True, policy_text=True,
            reward_data=True, reporting_metadata=True, authenticated_api=True,
            availability={"authenticated_api": "ROLE_DEPENDENT"},
        )

    def resolve_handle(self, *, handle: str | None, url: str | None) -> str:
        if handle:
            return handle.strip()
        if not url:
            raise ValueError("Bugcrowd import requires --handle or --url")
        parsed = urlparse(url)
        if (parsed.hostname or "").lower() not in {"bugcrowd.com", "www.bugcrowd.com"}:
            raise ValueError("Bugcrowd URL host does not match adapter")
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            raise ValueError("Bugcrowd URL does not contain a program code")
        return parts[-1]

    def fetch(self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
              snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
              from_file: Path | None = None) -> AdapterPayload:
        if from_file:
            document = json.loads(from_file.read_text(encoding="utf-8"))
            return self._parse_document(handle, document, snapshot, "fixture:bugcrowd")
        if not isinstance(credential, str):
            return self._public_fallback(handle, fetcher, snapshot)
        endpoint = (
            "https://api.bugcrowd.com/programs?"
            f"filter[code]={quote(handle)}&include=current_brief.target_groups.targets,"
            "current_brief.target_groups.reward_range&page[limit]=100"
        )
        headers = {
            "Accept": "application/vnd.bugcrowd+json",
            "Authorization": f"Token {credential}",
        }
        pages = fetcher.json_pages(endpoint, headers=headers)
        combined = {"data": [], "included": []}
        for index, result in enumerate(pages, 1):
            body = result.json()
            combined["data"].extend(body.get("data", []))
            combined["included"].extend(body.get("included", []))
            snapshot.write(f"program_page{index}.json", body,
                           source_type=SourceType.OFFICIAL_STRUCTURED_API,
                           source_identifier=result.url, status=result.status_code)
        matches = [item for item in combined["data"] if str(item.get("attributes", {}).get("code", "")).lower() == handle.lower()]
        if len(matches) != 1:
            raise IntakeFetchError("Bugcrowd program code was not uniquely resolved", category="not_found_or_ambiguous")
        combined["data"] = matches
        return self._parse_document(handle, combined, snapshot, endpoint, snapshot_document=False)

    def _parse_document(self, handle: str, document: dict, snapshot: SnapshotWriter,
                        source: str, *, snapshot_document: bool = True) -> AdapterPayload:
        if snapshot_document:
            snapshot.write("program.json", document, source_type=SourceType.OFFICIAL_STRUCTURED_API,
                           source_identifier=source)
        data = document.get("data", [])
        program_resource = data[0] if isinstance(data, list) and data else data if isinstance(data, dict) else {}
        included = document.get("included", [])
        by_ref = {(item.get("type"), item.get("id")): item for item in included}
        attrs = program_resource.get("attributes", {})
        brief_ref = ((program_resource.get("relationships", {}).get("current_brief", {}) or {}).get("data") or {})
        brief = by_ref.get((brief_ref.get("type"), brief_ref.get("id")), {})
        brief_attrs = brief.get("attributes", {})
        policy_parts = [
            brief_attrs.get("description"), brief_attrs.get("rules"),
            brief_attrs.get("additional_notes"), brief_attrs.get("researcher_notes"),
        ]
        policy = "\n\n".join(str(item) for item in policy_parts if item)
        target_refs = []
        group_refs = ((brief.get("relationships", {}).get("target_groups", {}) or {}).get("data") or [])
        for group_ref in group_refs:
            group = by_ref.get((group_ref.get("type"), group_ref.get("id")), {})
            refs = ((group.get("relationships", {}).get("targets", {}) or {}).get("data") or [])
            target_refs.extend((group, ref) for ref in refs)
        scopes = []
        for group, target_ref in target_refs:
            target = by_ref.get((target_ref.get("type"), target_ref.get("id")), {})
            target_attrs = target.get("attributes", {})
            group_attrs = group.get("attributes", {})
            group_name = str(group_attrs.get("name", ""))
            in_scope = "out of scope" not in group_name.lower()
            scopes.append({"id": target.get("id"), "type": "structured-scope", "attributes": {
                "asset_identifier": target_attrs.get("name") or target_attrs.get("url"),
                "asset_type": target_attrs.get("category") or target_attrs.get("type") or "OTHER",
                "eligible_for_submission": in_scope,
                "eligible_for_bounty": bool(group.get("relationships", {}).get("reward_range", {}).get("data")) if in_scope else False,
                "instruction": target_attrs.get("description") or group_attrs.get("description"),
            }})
        if policy:
            snapshot.write("policy.md", policy, source_type=SourceType.OFFICIAL_POLICY_TEXT,
                           source_identifier=source + "#current_brief")
        snapshot.write("structured_scopes.json", {"data": scopes},
                       source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier=source + "#target_groups.targets")
        program = {"data": {"id": program_resource.get("id"), "type": "program", "attributes": {
            "handle": attrs.get("code", handle), "name": attrs.get("name", handle),
            "policy": policy, "submission_state": attrs.get("status", "unknown"),
            "offers_bounties": any(s["attributes"].get("eligible_for_bounty") for s in scopes),
        }}}
        return AdapterPayload(
            platform=self.name, handle=handle,
            program_url=f"https://bugcrowd.com/{handle}", capabilities=self.capabilities,
            program=program, scopes=scopes, exclusions=[], policy_text=policy,
            sources=list(snapshot.sources),
        )

    def _public_fallback(self, handle: str, fetcher: IntakeFetcher, snapshot: SnapshotWriter) -> AdapterPayload:
        url = f"https://bugcrowd.com/{handle}"
        result = fetcher.get(url, headers={"Accept": "text/html"})
        snapshot.write("program.html", result.body, source_type=SourceType.OFFICIAL_STRUCTURED_HTML,
                       source_identifier=url, status=result.status_code)
        capabilities = PlatformCapabilities(
            program_metadata=True, public_api=True,
            availability={"structured_scope": "UNAVAILABLE_TO_CURRENT_CREDENTIAL",
                          "policy_text": "PUBLIC_FALLBACK_REVIEW_REQUIRED"},
        )
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=url, capabilities=capabilities,
            program={"data": {"id": handle, "type": "program", "attributes": {
                "handle": handle, "name": handle, "submission_state": "unknown", "policy": ""}}},
            sources=list(snapshot.sources),
        )


__all__ = ["BugcrowdAdapter"]
