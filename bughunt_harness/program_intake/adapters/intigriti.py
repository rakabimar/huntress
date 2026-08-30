"""Official Intigriti researcher API v1 adapter (Bearer, GET-only)."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from .base import PlatformAdapter
from ..fetcher import IntakeFetchError, IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities, SourceType
from ..provenance import SnapshotWriter


class IntigritiAdapter(PlatformAdapter):
    name = "intigriti"
    version = "researcher-v1.0"
    official_hosts = {"api.intigriti.com", "app.intigriti.com", "intigriti.com", "www.intigriti.com"}
    API_ROOT = "https://api.intigriti.com/external/researcher/v1"

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            program_metadata=True, structured_scope=True, policy_text=True,
            reward_data=True, reporting_metadata=True, change_timestamps=True,
            authenticated_api=True,
        )

    def resolve_handle(self, *, handle: str | None, url: str | None) -> str:
        if handle:
            return handle.strip()
        if not url:
            raise ValueError("Intigriti import requires --handle or --url")
        parsed = urlparse(url)
        if (parsed.hostname or "").lower() not in self.official_hosts:
            raise ValueError("Intigriti URL host does not match adapter")
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            raise ValueError("Intigriti URL does not contain a program handle")
        return parts[-1]

    def fetch(self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
              snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
              from_file: Path | None = None) -> AdapterPayload:
        if from_file:
            import json
            body = json.loads(from_file.read_text(encoding="utf-8"))
            detail = body.get("program", body)
            return self._payload(handle, detail, snapshot, "fixture:intigriti")
        if not isinstance(credential, str):
            raise IntakeFetchError("Intigriti researcher API requires an explicit token reference", category="credentials_required")
        headers = {"Authorization": f"Bearer {credential}", "Accept": "application/json"}
        listing_url = f"{self.API_ROOT}/programs?limit=500&offset=0"
        listing_result = fetcher.get(listing_url, headers=headers)
        listing = listing_result.json()
        snapshot.write("programs.json", listing, source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier=listing_url, status=listing_result.status_code)
        matches = [item for item in listing.get("records", []) if str(item.get("handle", "")).lower() == handle.lower()]
        if len(matches) != 1:
            raise IntakeFetchError(
                "Intigriti handle was not uniquely resolved for this researcher credential",
                category="not_found_or_ambiguous",
            )
        program_id = matches[0]["id"]
        detail_url = f"{self.API_ROOT}/programs/{program_id}"
        detail_result = fetcher.get(detail_url, headers=headers)
        detail = detail_result.json()
        return self._payload(handle, detail, snapshot, detail_url, status=detail_result.status_code)

    def _payload(self, handle: str, detail: dict, snapshot: SnapshotWriter,
                 source: str, status: int = 200) -> AdapterPayload:
        snapshot.write("program.json", detail, source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier=source, status=status)
        domains = (detail.get("domains") or {}).get("content") or []
        roe = ((detail.get("rulesOfEngagement") or {}).get("content") or {})
        policy_parts = [str(roe.get("description") or "")]
        requirements = roe.get("testingRequirements") or {}
        if requirements:
            policy_parts.append("Testing requirements: " + str(requirements))
        for attachment in (detail.get("rulesOfEngagement") or {}).get("attachments", []):
            if attachment.get("url"):
                policy_parts.append("Referenced attachment: " + str(attachment["url"]))
        policy = "\n\n".join(part for part in policy_parts if part)
        if policy:
            snapshot.write("policy.md", policy, source_type=SourceType.OFFICIAL_POLICY_TEXT,
                           source_identifier=source + "#rulesOfEngagement", status=status)
        scopes = []
        for domain in domains:
            type_value = domain.get("type", {})
            scopes.append({
                "id": domain.get("id"),
                "type": "structured-scope",
                "attributes": {
                    "asset_identifier": domain.get("endpoint"),
                    "asset_type": type_value.get("value") if isinstance(type_value, dict) else type_value,
                    "eligible_for_submission": True,
                    "eligible_for_bounty": None,
                    "instruction": domain.get("description"),
                    "max_severity": (domain.get("tier") or {}).get("value") if isinstance(domain.get("tier"), dict) else None,
                },
            })
        snapshot.write("structured_scopes.json", {"data": scopes},
                       source_type=SourceType.OFFICIAL_STRUCTURED_API,
                       source_identifier=source + "#domains", status=status)
        return AdapterPayload(
            platform=self.name, handle=handle,
            program_url=(detail.get("webLinks") or {}).get("detail"),
            capabilities=self.capabilities, program={"data": {"id": detail.get("id"),
                "type": "program", "attributes": {
                    "handle": detail.get("handle", handle), "name": detail.get("name", handle),
                    "submission_state": ((detail.get("status") or {}).get("value")
                                         if isinstance(detail.get("status"), dict) else detail.get("status")),
                    "policy": policy,
                }}}, scopes=scopes, exclusions=[], policy_text=policy,
            sources=list(snapshot.sources),
        )


__all__ = ["IntigritiAdapter"]
