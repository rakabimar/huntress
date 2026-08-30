"""Common adapter contract and safe platform detection."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from ..fetcher import IntakeFetcher
from ..models import AdapterPayload, PlatformCapabilities
from ..provenance import SnapshotWriter


class PlatformAdapter(ABC):
    name = "base"
    version = "1.0"
    official_hosts: set[str] = set()
    requests_per_minute = 30

    @property
    @abstractmethod
    def capabilities(self) -> PlatformCapabilities: ...

    def create_fetcher(self) -> IntakeFetcher:
        return IntakeFetcher(self.official_hosts, requests_per_minute=self.requests_per_minute)

    @abstractmethod
    def resolve_handle(self, *, handle: str | None, url: str | None) -> str: ...

    @abstractmethod
    def fetch(
        self, *, handle: str, url: str | None, fetcher: IntakeFetcher,
        snapshot: SnapshotWriter, credential: tuple[str, str] | str | None,
        from_file: Path | None = None,
    ) -> AdapterPayload: ...


def detect_platform(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host in {"hackerone.com", "www.hackerone.com"}:
        return "hackerone"
    if host in {"bugcrowd.com", "www.bugcrowd.com"}:
        return "bugcrowd"
    if host in {"app.intigriti.com", "intigriti.com", "www.intigriti.com"}:
        return "intigriti"
    if host in {"yeswehack.com", "www.yeswehack.com"}:
        return "yeswehack"
    raise ValueError("URL does not match a supported platform; use --platform generic explicitly")


def adapter_for(name: str) -> PlatformAdapter:
    from .bugcrowd import BugcrowdAdapter
    from .generic import GenericAdapter
    from .hackerone import HackerOneAdapter
    from .intigriti import IntigritiAdapter
    from .yeswehack import YesWeHackAdapter
    adapters = {
        "hackerone": HackerOneAdapter,
        "bugcrowd": BugcrowdAdapter,
        "intigriti": IntigritiAdapter,
        "yeswehack": YesWeHackAdapter,
        "generic": GenericAdapter,
        "custom": GenericAdapter,
    }
    try:
        return adapters[name.lower()]()
    except KeyError as exc:
        raise ValueError(f"unsupported intake platform {name!r}") from exc


__all__ = ["PlatformAdapter", "adapter_for", "detect_platform"]
