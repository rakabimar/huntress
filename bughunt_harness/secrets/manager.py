"""Secret-reference abstraction.

Credentials are NEVER stored in the Git repository or in plaintext YAML.  A
``secret_ref`` points to one of (in preference order):

    env:VARNAME            environment variable
    keyring:SERVICE/USER   OS keyring
    file:NAME              protected file under ~/.bughunt/secrets/<program>/NAME

Only *metadata* (whether a credential is available) is ever surfaced to the
model; the values themselves are resolved only inside the request broker, which
redacts them from logs and evidence previews.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..config import HarnessConfig, get_config
from ..errors import SecretError
from ..engagement.models import AccountModel


def _restrictive_perms(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # non-POSIX filesystem (e.g. WSL /mnt/c) may not support chmod


class SecretManager:
    def __init__(self, program_slug: str, config: HarnessConfig | None = None) -> None:
        self.program_slug = program_slug
        self.config = config or get_config()

    @property
    def secret_dir(self) -> Path:
        return self.config.secrets_dir / self.program_slug

    # -- resolution -------------------------------------------------------
    def resolve(self, ref: str | None) -> str | None:
        """Resolve a secret reference to its value (never logged)."""
        if not ref:
            return None
        if not isinstance(ref, str):
            raise SecretError("secret_ref must be a string reference, not a value")

        if ref.startswith("env:"):
            name = ref[4:].strip()
            if not name:
                raise SecretError("empty env secret reference")
            val = os.environ.get(name)
            if val is None:
                raise SecretError(f"environment variable {name!r} not set")
            return val

        if ref.startswith("keyring:"):
            spec = ref[len("keyring:"):]
            if "/" not in spec:
                raise SecretError("keyring ref must be SERVICE/USER")
            service, user = spec.split("/", 1)
            try:
                import keyring
            except ImportError as exc:
                raise SecretError("keyring backend unavailable") from exc
            val = keyring.get_password(service, user)
            if val is None:
                raise SecretError(f"no keyring credential for {service}/{user}")
            return val

        if ref.startswith("file:"):
            name = ref[len("file:"):].strip()
            if not name or "/" in name or name.startswith("."):
                raise SecretError(f"invalid file secret name: {name!r}")
            path = self.secret_dir / name
            if not path.is_file():
                raise SecretError(f"secret file not found: {name!r}")
            return path.read_text(encoding="utf-8").strip()

        # A bare value is *not* a reference: reject it loudly.
        raise SecretError(
            f"secret_ref {ref!r} is not a reference; use env:/keyring:/file: (plaintext secrets are forbidden)"
        )

    def available(self, ref: str | None) -> bool:
        try:
            return self.resolve(ref) is not None
        except SecretError:
            return False

    # -- storage ----------------------------------------------------------
    def store_file_secret(self, name: str, value: str) -> str:
        """Persist a secret to a protected file and return its ``file:`` ref."""
        if not name or "/" in name or name.startswith(".") or ".." in name:
            raise SecretError(f"invalid secret name {name!r}")
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self.secret_dir / name
        path.write_text(value, encoding="utf-8")
        _restrictive_perms(path)
        return f"file:{name}"

    def delete_file_secret(self, name: str) -> None:
        if not name or "/" in name or name.startswith("."):
            raise SecretError(f"invalid secret name {name!r}")
        try:
            (self.secret_dir / name).unlink()
        except OSError:
            pass

    # -- metadata-only summaries for the agent ----------------------------
    def account_summaries(self, accounts: list[AccountModel]) -> list[dict]:
        """Return model-safe account metadata; NEVER include secret values."""
        summaries = []
        for account in accounts:
            refs = account.auth.secret_refs() if account.auth else []
            if account.secret_ref:
                refs.append(account.secret_ref)
            summaries.append({
                "id": account.id,
                "role": account.role,
                "description": account.description,
                "enabled": account.enabled,
                "auth_type": account.auth.type if account.auth else None,
                "credential_available": bool(refs) and all(self.available(ref) for ref in refs),
            })
        return summaries


__all__ = ["SecretManager"]
