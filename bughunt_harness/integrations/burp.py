"""Minimal MCP-over-SSE client for the installed Burp Suite extension.

Burp is an observation plane.  This client intentionally exposes only the
installed extension's read-oriented history/Organizer tools; active requests
remain the Harness Request Broker's responsibility.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

from ..redact import redact_text

READ_TOOLS = frozenset({
    "get_proxy_http_history",
    "get_proxy_http_history_regex",
    "get_proxy_websocket_history",
    "get_proxy_websocket_history_regex",
    "get_organizer_items",
    "get_organizer_items_regex",
})


@dataclass
class BurpHealth:
    ok: bool
    endpoint: str
    server_name: str = ""
    server_version: str = ""
    tool_names: list[str] | None = None
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "endpoint": self.endpoint,
            "server_name": self.server_name, "server_version": self.server_version,
            "tool_names": self.tool_names or [], "error": self.error,
        }


class BurpMCPClient:
    def __init__(self, endpoint: str, timeout: float = 4.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._stream = None
        self._lines = None
        self._message_url = ""
        self.server_info: dict[str, Any] = {}
        self.tools: list[dict] = []
        self._next_id = 1

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
        self._session.close()

    def __enter__(self) -> "BurpMCPClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _read_message(self) -> dict:
        if self._lines is None:
            raise RuntimeError("Burp MCP stream is not connected")
        for raw in self._lines:
            line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data:
                continue
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                continue
        raise RuntimeError("Burp MCP SSE stream ended")

    def _post(self, payload: dict) -> None:
        response = self._session.post(
            self._message_url, json=payload, timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        request_id = self._next_id
        self._next_id += 1
        self._post({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            message = self._read_message()
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"Burp MCP {method} failed: {message['error']}")
            return message.get("result", {})

    def connect(self) -> None:
        if self._stream is not None:
            return
        self._stream = self._session.get(
            self.endpoint, stream=True, timeout=(self.timeout, self.timeout),
            headers={"Accept": "text/event-stream"},
        )
        self._stream.raise_for_status()
        self._lines = self._stream.iter_lines(chunk_size=1)
        endpoint = ""
        for raw in self._lines:
            line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            if line.startswith("data:"):
                endpoint = line[5:].strip()
                break
        if not endpoint:
            raise RuntimeError("Burp MCP did not advertise an SSE message endpoint")
        self._message_url = urljoin(self.endpoint + "/", endpoint)
        initialized = self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "bughunt-harness", "version": "0.3"},
            },
        )
        self.server_info = initialized.get("serverInfo", {})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self.tools = self._rpc("tools/list").get("tools", [])

    def list_tools(self) -> list[dict]:
        self.connect()
        return list(self.tools)

    def call_read_tool(self, name: str, arguments: dict | None = None) -> dict:
        self.connect()
        if name not in READ_TOOLS:
            raise RuntimeError(f"Burp tool {name!r} is not in the harness read-only allowlist")
        installed = {tool.get("name") for tool in self.tools}
        if name not in installed:
            raise RuntimeError(f"Burp tool {name!r} is not installed")
        return self._rpc("tools/call", {"name": name, "arguments": arguments or {}})


def burp_mcp_health(endpoint: str, timeout: float = 4.0) -> BurpHealth:
    client = BurpMCPClient(endpoint, timeout=timeout)
    try:
        client.connect()
        names = [str(tool.get("name", "")) for tool in client.tools]
        if not names:
            raise RuntimeError("tools/list returned no tools")
        return BurpHealth(
            True, endpoint,
            server_name=str(client.server_info.get("name", "")),
            server_version=str(client.server_info.get("version", "")),
            tool_names=names,
        )
    except Exception as exc:  # local integration boundary
        return BurpHealth(False, endpoint, error=f"{type(exc).__name__}: {exc}")
    finally:
        client.close()


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HOST_RE = re.compile(r"(?im)^Host:\s*([^\s:]+)")
_REQUEST_TARGET_RE = re.compile(
    r"(?im)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+"
    r"(https?://[^\s]+|/[^\s]*)\s+HTTP/",
)


def _owning_target(raw: str) -> str | None:
    """Derive ownership from the request line/Host, never response-body URLs."""
    request = _REQUEST_TARGET_RE.search(raw)
    if request and request.group(1).startswith(("http://", "https://")):
        return request.group(1)
    host = _HOST_RE.search(raw)
    if host:
        path = request.group(1) if request else "/"
        return f"https://{host.group(1)}{path}"
    return None


def _redact_history_text(raw: str, patterns: list[str]) -> str:
    safe = re.sub(
        r"(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token):[^\r\n]*",
        lambda match: f"{match.group(1)}: [REDACTED]", raw,
    )
    return redact_text(safe, secret_patterns=patterns)


def scope_filter_burp_result(result: dict, scope_engine, *, secret_patterns: list[str] | None = None) -> dict:
    """Fail closed: omit Burp items whose owning target cannot be proven in scope."""
    content = result.get("content", []) if isinstance(result, dict) else []
    accepted: list[dict] = []
    filtered = 0
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            filtered += 1
            continue
        raw = str(block.get("text", ""))
        owner = _owning_target(raw)
        if not owner or not scope_engine.check(owner).allowed:
            filtered += 1
            continue
        accepted.append({
            "type": "text",
            "text": "UNTRUSTED TARGET DATA\n" + _redact_history_text(
                raw[:20000], secret_patterns or [],
            ),
        })
    return {"content": accepted, "filtered_items": filtered, "scope_filtered": True}


__all__ = [
    "READ_TOOLS", "BurpHealth", "BurpMCPClient", "burp_mcp_health",
    "scope_filter_burp_result",
]
