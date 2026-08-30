"""Read-only, host-allowlisted HTTP client for bounty platform metadata."""

from __future__ import annotations

import email.utils
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


class IntakeFetchError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, category: str = "network") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.category = category


@dataclass
class FetchResult:
    url: str
    status_code: int
    body: bytes
    headers: dict[str, str]

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntakeFetchError(f"invalid JSON from official source {self.url}", category="parser") from exc

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class PlatformRateLimiter:
    def __init__(self, requests_per_minute: int = 30) -> None:
        self.interval = 60.0 / max(1, requests_per_minute)
        self._next = 0.0

    def wait(self) -> None:
        delay = self._next - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next = time.monotonic() + self.interval


def _retry_after(value: str | None, *, maximum: float = 30.0) -> float:
    if not value:
        return 1.0
    try:
        return min(maximum, max(0.0, float(value)))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return min(maximum, max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return 1.0


class IntakeFetcher:
    """GET-only client; official platform traffic never enters the target broker."""

    def __init__(
        self, allowed_hosts: set[str], *, session: requests.Session | None = None,
        requests_per_minute: int = 30, max_attempts: int = 3,
        timeout: float = 20.0,
    ) -> None:
        self.allowed_hosts = {host.lower().rstrip(".") for host in allowed_hosts}
        self.session = session or requests.Session()
        self.rate_limiter = PlatformRateLimiter(requests_per_minute)
        self.max_attempts = max(1, min(max_attempts, 5))
        self.timeout = timeout
        self._cache: dict[str, tuple[bytes, str | None, str | None]] = {}

    def prime_cache(self, url: str, body: bytes, *, etag: str | None = None,
                    last_modified: str | None = None) -> None:
        self.validate_url(url)
        self._cache[url] = (body, etag, last_modified)

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise IntakeFetchError("platform source URL must be absolute HTTPS", category="source_policy")
        host = parsed.hostname.lower().rstrip(".")
        if host not in self.allowed_hosts:
            raise IntakeFetchError(
                f"platform source host {host!r} is not allowlisted for this adapter",
                category="source_policy",
            )
        if parsed.username or parsed.password:
            raise IntakeFetchError("credentials in source URLs are forbidden", category="source_policy")

    def get(
        self, url: str, *, auth: tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResult:
        self.validate_url(url)
        safe_headers = {"Accept": "application/json", **(headers or {})}
        for attempt in range(1, self.max_attempts + 1):
            request_headers = dict(safe_headers)
            cached = self._cache.get(url)
            if cached:
                if cached[1]:
                    request_headers.setdefault("If-None-Match", cached[1])
                if cached[2]:
                    request_headers.setdefault("If-Modified-Since", cached[2])
            self.rate_limiter.wait()
            try:
                response = self.session.get(
                    url, auth=auth, headers=request_headers, timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                if attempt == self.max_attempts:
                    raise IntakeFetchError("official platform request failed after bounded retries") from exc
                time.sleep(min(2 ** (attempt - 1), 4))
                continue
            limit_value = response.headers.get("RateLimit-Limit") or response.headers.get("X-RateLimit-Limit")
            if limit_value:
                try:
                    documented_interval = 60.0 / max(1, int(str(limit_value).split(",", 1)[0]))
                    self.rate_limiter.interval = max(self.rate_limiter.interval, documented_interval)
                except ValueError:
                    pass
            if response.status_code == 304:
                cached = self._cache.get(url)
                if not cached:
                    raise IntakeFetchError("platform returned 304 without a local source cache", category="cache")
                return FetchResult(
                    url=url, status_code=304, body=cached[0],
                    headers={str(k): str(v) for k, v in response.headers.items()},
                )
            if 300 <= response.status_code < 400:
                location = response.headers.get("Location")
                if not location:
                    raise IntakeFetchError("platform returned redirect without Location", status_code=response.status_code)
                redirected = urljoin(url, location)
                self.validate_url(redirected)
                url = redirected
                continue
            if response.status_code == 429 or 500 <= response.status_code < 600:
                if attempt < self.max_attempts:
                    time.sleep(_retry_after(response.headers.get("Retry-After")))
                    continue
            if response.status_code >= 400:
                category = {
                    401: "invalid_credentials",
                    403: "access_denied",
                    404: "not_found_or_inaccessible",
                    429: "rate_limited",
                }.get(response.status_code, "platform_error")
                raise IntakeFetchError(
                    f"official platform returned HTTP {response.status_code}",
                    status_code=response.status_code,
                    category=category,
                )
            return FetchResult(
                url=url,
                status_code=response.status_code,
                body=response.content,
                headers={str(k): str(v) for k, v in response.headers.items()},
            )
        raise IntakeFetchError("official platform request retries exhausted")

    def json_pages(
        self, url: str, *, auth: tuple[str, str] | None = None,
        headers: dict[str, str] | None = None, max_pages: int = 1000,
    ) -> list[FetchResult]:
        pages: list[FetchResult] = []
        next_url: str | None = url
        seen: set[str] = set()
        while next_url:
            if next_url in seen or len(pages) >= max_pages:
                raise IntakeFetchError("unsafe or excessive platform pagination", category="pagination")
            seen.add(next_url)
            result = self.get(next_url, auth=auth, headers=headers)
            pages.append(result)
            payload = result.json()
            links = payload.get("links", {}) if isinstance(payload, dict) else {}
            candidate = links.get("next") if isinstance(links, dict) else None
            if isinstance(candidate, dict):
                candidate = candidate.get("href")
            next_url = urljoin(result.url, candidate) if isinstance(candidate, str) and candidate else None
            if next_url:
                self.validate_url(next_url)
        return pages


__all__ = ["FetchResult", "IntakeFetchError", "IntakeFetcher", "PlatformRateLimiter"]
