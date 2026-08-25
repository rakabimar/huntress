"""Harness global configuration and path resolution.

All mutable research/secret state lives OUTSIDE the Git-tracked harness
repository, under ``~/.bughunt`` by default.  Every path is overridable via
environment variables so the harness is portable across machines.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ENV_HOME = "BUGHUNT_HOME"
ENV_PROGRAMS_DIR = "BUGHUNT_PROGRAMS_DIR"
ENV_CONFIG = "BUGHUNT_CONFIG"
ENV_ACTIVE_PROGRAM = "BUGHUNT_ACTIVE_PROGRAM"
ENV_BURP_PROXY = "BUGHUNT_BURP_PROXY"


def _default_home() -> Path:
    return Path(os.environ.get(ENV_HOME, Path.home() / ".bughunt"))


@dataclass(frozen=True)
class HarnessConfig:
    """Resolved harness filesystem layout.

    Frozen so a session cannot silently mutate its own paths mid-run.
    """

    home: Path = field(default_factory=_default_home)
    programs_dir: Path | None = None
    config_file: Path | None = None
    burp_proxy: str | None = None

    def __post_init__(self) -> None:
        # Frozen dataclass: resolve lazily via object.__setattr__.
        if self.programs_dir is None:
            object.__setattr__(
                self, "programs_dir", Path(os.environ.get(ENV_PROGRAMS_DIR, self.home / "programs"))
            )
        if self.config_file is None:
            object.__setattr__(self, "config_file", Path(os.environ.get(ENV_CONFIG, self.home / "config.yaml")))
        if self.burp_proxy is None:
            object.__setattr__(self, "burp_proxy", os.environ.get(ENV_BURP_PROXY))

    # -- derived paths ----------------------------------------------------
    @property
    def registry_db(self) -> Path:
        return self.home / "registry.db"

    @property
    def secrets_dir(self) -> Path:
        return self.home / "secrets"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def active_program_file(self) -> Path:
        return self.home / "active_program"

    def ensure_dirs(self) -> None:
        """Create the global home directory tree (idempotent)."""
        for p in (self.home, self.programs_dir, self.secrets_dir, self.logs_dir):
            if p is not None:
                p.mkdir(parents=True, exist_ok=True)


def load_config() -> HarnessConfig:
    """Load and return the (process-wide) harness configuration."""
    cfg = HarnessConfig()
    cfg.ensure_dirs()
    return cfg


_default_config: HarnessConfig | None = None


def get_config() -> HarnessConfig:
    """Return a memoized HarnessConfig (dirs guaranteed to exist)."""
    global _default_config
    if _default_config is None:
        _default_config = load_config()
    return _default_config