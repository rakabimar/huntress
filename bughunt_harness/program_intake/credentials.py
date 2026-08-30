"""Global platform credential definitions containing references only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..config import HarnessConfig, get_config
from ..errors import ProgramIntakeError
from ..secrets.manager import SecretManager


class PlatformCredentialStore:
    def __init__(self, config: HarnessConfig | None = None) -> None:
        self.config = config or get_config()
        self.path = self.config.home / "platform_credentials.yaml"

    def _load(self) -> dict[str, dict[str, dict[str, str]]]:
        if not self.path.is_file():
            return {}
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def add(self, platform: str, name: str, *, username_ref: str | None = None,
            token_ref: str) -> None:
        _validate_ref(token_ref)
        if username_ref:
            _validate_ref(username_ref)
        data = self._load()
        entry = {"token_ref": token_ref}
        if username_ref:
            entry["username_ref"] = username_ref
        data.setdefault(platform, {})[name] = entry
        self._save(data)

    def get(self, platform: str, name: str) -> dict[str, str]:
        try:
            return self._load()[platform][name]
        except KeyError as exc:
            raise ProgramIntakeError(f"platform credential {platform}/{name} is not configured") from exc

    def resolve(self, platform: str, name: str | None) -> tuple[str, str] | str | None:
        if not name:
            return None
        entry = self.get(platform, name)
        manager = SecretManager("__platform__", config=self.config)
        token = manager.resolve(entry.get("token_ref"))
        if token is None:
            raise ProgramIntakeError(f"platform credential {platform}/{name} token is not resolvable")
        if platform == "hackerone":
            username = manager.resolve(entry.get("username_ref"))
            if username is None:
                raise ProgramIntakeError("HackerOne credential requires a resolvable username_ref")
            return username, token
        return token

    def list_safe(self) -> list[dict[str, Any]]:
        manager = SecretManager("__platform__", config=self.config)
        rows = []
        for platform, entries in sorted(self._load().items()):
            for name, entry in sorted(entries.items()):
                rows.append({
                    "platform": platform, "name": name,
                    "username": "configured" if entry.get("username_ref") else "not_required",
                    "token": "resolvable" if manager.available(entry.get("token_ref")) else "unavailable",
                    "value": "[REDACTED]",
                })
        return rows


def _validate_ref(value: str) -> None:
    if not isinstance(value, str) or not value.startswith(("env:", "keyring:", "file:")):
        raise ProgramIntakeError("platform credentials must use env:/keyring:/file: references")


__all__ = ["PlatformCredentialStore"]
