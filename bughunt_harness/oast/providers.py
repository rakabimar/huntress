"""OAST provider adapters. Providers allocate/correlate; they never exploit."""

from __future__ import annotations

import json
import os
import secrets
import select
import re
import time
import shutil
import subprocess
import tempfile
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests


@dataclass(frozen=True)
class ProviderCapabilities:
    name: str
    available: bool
    channels: tuple[str, ...]
    third_party: bool
    detail: str = ""
    self_hosted: bool = False


@dataclass
class OASTInteractionData:
    provider_interaction_id: str
    protocol: str
    observed_at: str
    hostname: str
    correlation_token: str = ""
    remote_address: str = ""
    request_method: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class OASTProvider(ABC):
    name = "abstract"

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities: ...

    def health(self) -> dict:
        cap = self.capabilities()
        return {"available": cap.available, "detail": cap.detail, "network_tested": False}

    @abstractmethod
    def create_session(self, *, expires_in: int) -> dict: ...

    @abstractmethod
    def allocate_probe(self, session_reference: str, correlation_token: str) -> dict: ...

    @abstractmethod
    def poll(self, session_reference: str) -> list[OASTInteractionData]: ...

    @abstractmethod
    def close(self, session_reference: str) -> None: ...


class SyntheticOASTProvider(OASTProvider):
    """Memory-only deterministic provider for local tests and acceptance."""

    name = "synthetic"

    def __init__(self, base_domain: str = "oast.localhost") -> None:
        self.base_domain = base_domain
        self._sessions: dict[str, list[OASTInteractionData]] = {}
        self._lock = threading.Lock()

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(self.name, True, ("DNS", "HTTP", "HTTPS"), False, "local synthetic provider")

    def create_session(self, *, expires_in: int) -> dict:
        ref = secrets.token_hex(12)
        with self._lock:
            self._sessions[ref] = []
        return {"reference": ref, "base_domain": self.base_domain}

    def allocate_probe(self, session_reference: str, correlation_token: str) -> dict:
        if session_reference not in self._sessions:
            raise RuntimeError("unknown synthetic OAST session")
        domain = f"{correlation_token}.{self.base_domain}"
        return {"domain": domain, "urls": {"HTTP": f"http://{domain}/", "HTTPS": f"https://{domain}/"}}

    def inject(self, session_reference: str, interaction: OASTInteractionData) -> None:
        with self._lock:
            self._sessions[session_reference].append(interaction)

    def poll(self, session_reference: str) -> list[OASTInteractionData]:
        with self._lock:
            return list(self._sessions.get(session_reference, []))

    def close(self, session_reference: str) -> None:
        with self._lock:
            self._sessions.pop(session_reference, None)


class InteractshProvider(OASTProvider):
    """First-class adapter around the official interactsh-client binary."""

    name = "interactsh"

    def __init__(self, *, server: str = "", token_ref: str = "", binary: str = "interactsh-client") -> None:
        self.binary = shutil.which(binary) or ""
        self.server = server
        self.token_ref = token_ref
        self._processes: dict[str, subprocess.Popen] = {}
        self._outputs: dict[str, Path] = {}

    def capabilities(self) -> ProviderCapabilities:
        mode = "self-hosted" if self.server else "official client default server"
        return ProviderCapabilities(
            self.name, bool(self.binary), ("DNS", "HTTP", "HTTPS", "SMTP"), True,
            f"interactsh-client {'installed' if self.binary else 'not installed'}; {mode}",
            self_hosted=bool(self.server),
        )

    def create_session(self, *, expires_in: int) -> dict:
        if not self.binary:
            raise RuntimeError("interactsh-client is not installed")
        root = Path(tempfile.mkdtemp(prefix="bughunt-interactsh-"))
        output, session_file = root / "interactions.jsonl", root / "session"
        argv = [self.binary, "-json", "-o", str(output), "-sf", str(session_file), "-v"]
        if self.server:
            argv += ["-s", self.server]
        # Credentials are supplied to the official client via environment or
        # its own config; never place a resolved token in argv/DB.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        allocated_domain = ""
        deadline = time.monotonic() + 10
        while proc.stdout and time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], min(0.5, deadline - time.monotonic()))
            if not ready:
                continue
            line = proc.stdout.readline()
            match = re.search(r"\b([a-z0-9]{12,}\.[a-z0-9.-]+)\b", line, re.I)
            if match:
                allocated_domain = match.group(1).lower().rstrip(".")
                break
        reference = json.dumps({"id": secrets.token_hex(16), "output": str(output), "pid": proc.pid, "domain": allocated_domain})
        self._processes[reference], self._outputs[reference] = proc, output
        # The official session file is opaque. The callback domain is emitted
        # by the client; callers should configure base_domain for self-hosted
        # deployments when deterministic immediate allocation is required.
        if not allocated_domain:
            self.close(reference)
            raise RuntimeError("official interactsh-client did not emit an allocation within 10 seconds")
        return {"reference": reference, "base_domain": allocated_domain, "client_managed": True}

    def allocate_probe(self, session_reference: str, correlation_token: str) -> dict:
        info = _interactsh_reference(session_reference)
        domain = f"{correlation_token}.{info['domain']}"
        return {"domain": domain, "urls": {"HTTP": f"http://{domain}/", "HTTPS": f"https://{domain}/"}}

    def poll(self, session_reference: str) -> list[OASTInteractionData]:
        output = self._outputs.get(session_reference)
        if output is None:
            output = Path(_interactsh_reference(session_reference)["output"])
        if output is None or not output.is_file():
            return []
        items = []
        for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(row.get("full-id") or row.get("q-name") or row.get("host") or "")
            items.append(OASTInteractionData(
                provider_interaction_id=str(row.get("unique-id") or row.get("id") or ""),
                protocol=str(row.get("protocol") or "").upper(), observed_at=str(row.get("timestamp") or ""),
                hostname=host, remote_address=str(row.get("remote-address") or ""),
                request_method=str(row.get("method") or ""), path=str(row.get("path") or ""), metadata=row,
            ))
        return items

    def close(self, session_reference: str) -> None:
        proc = self._processes.pop(session_reference, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        elif proc is None:
            try:
                os.kill(int(_interactsh_reference(session_reference)["pid"]), 15)
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                pass


class GenericConfiguredProvider(OASTProvider):
    name = "generic"

    def __init__(self, *, base_domain: str, allocate_endpoint: str, poll_endpoint: str, token: str = "") -> None:
        self.base_domain = base_domain
        self.allocate_endpoint = allocate_endpoint
        self.poll_endpoint = poll_endpoint
        self.token = token

    def capabilities(self) -> ProviderCapabilities:
        configured = all((self.base_domain, self.allocate_endpoint, self.poll_endpoint))
        return ProviderCapabilities(self.name, configured, ("DNS", "HTTP", "HTTPS"), True, "configured" if configured else "not configured", self_hosted=True)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def create_session(self, *, expires_in: int) -> dict:
        response = requests.post(self.allocate_endpoint, json={"expires_in": expires_in}, headers=self._headers(), timeout=15)
        response.raise_for_status()
        data = response.json()
        return {"reference": str(data["session_id"]), "base_domain": self.base_domain}

    def allocate_probe(self, session_reference: str, correlation_token: str) -> dict:
        domain = f"{correlation_token}.{self.base_domain}"
        return {"domain": domain, "urls": {"HTTP": f"http://{domain}/", "HTTPS": f"https://{domain}/"}}

    def poll(self, session_reference: str) -> list[OASTInteractionData]:
        response = requests.get(self.poll_endpoint, params={"session_id": session_reference}, headers=self._headers(), timeout=15)
        response.raise_for_status()
        return [OASTInteractionData(**item) for item in response.json().get("interactions", [])]

    def close(self, session_reference: str) -> None:
        return None


__all__ = [
    "OASTProvider", "ProviderCapabilities", "OASTInteractionData", "SyntheticOASTProvider",
    "InteractshProvider", "GenericConfiguredProvider",
]


def _interactsh_reference(value: str) -> dict:
    try:
        result = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid Interactsh provider session reference") from exc
    if not all(key in result for key in ("output", "domain")):
        raise RuntimeError("incomplete Interactsh provider session reference")
    return result
