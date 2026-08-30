"""YesWeHack adapter skeleton with explicit researcher-API capability status."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .base import PlatformAdapter
from ..fetcher import IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities, SourceType
from ..provenance import SnapshotWriter


class YesWeHackAdapter(PlatformAdapter):
    name = "yeswehack"
    version = "public-fallback-1.0"
    official_hosts = {"yeswehack.com", "www.yeswehack.com"}

    @property
    def capabilities(self) -> PlatformCapabilities:
        return PlatformCapabilities(
            program_metadata=True, public_api=True,
            availability={"structured_scope": "NO_DOCUMENTED_RESEARCHER_API_ADAPTER"},
        )

    def resolve_handle(self, *, handle: str | None, url: str | None) -> str:
        if handle:
            return handle.strip()
        if not url:
            raise ValueError("YesWeHack import requires --handle or --url")
        parsed = urlparse(url)
        if (parsed.hostname or "").lower() not in self.official_hosts:
            raise ValueError("YesWeHack URL host does not match adapter")
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            raise ValueError("YesWeHack URL does not contain a program handle")
        return parts[-1]

    def fetch(self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
              snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
              from_file: Path | None = None) -> AdapterPayload:
        source = url or f"https://yeswehack.com/programs/{handle}"
        result = fetcher.get(source, headers={"Accept": "text/html"})
        snapshot.write("program.html", result.body, source_type=SourceType.OFFICIAL_STRUCTURED_HTML,
                       source_identifier=result.url, status=result.status_code)
        return AdapterPayload(
            platform=self.name, handle=handle, program_url=source,
            capabilities=self.capabilities,
            program={"data": {"id": handle, "type": "program", "attributes": {
                "handle": handle, "name": handle, "policy": "", "submission_state": "unknown"}}},
            sources=list(snapshot.sources),
        )


__all__ = ["YesWeHackAdapter"]
