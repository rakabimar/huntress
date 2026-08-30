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
ENV_BURP_MCP = "BUGHUNT_BURP_MCP"
ENV_BURP_CA = "BUGHUNT_BURP_CA"
ENV_PLAYWRIGHT_PACKAGE = "BUGHUNT_PLAYWRIGHT_PACKAGE"


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
    burp_mcp: str | None = None
    burp_ca: str | None = None
    playwright_package: str | None = None
    intake_max_age_hours: int = 24
    intake_refresh_before_hunt: bool = True

    def __post_init__(self) -> None:
        # Frozen dataclass: resolve lazily via object.__setattr__.
        if self.programs_dir is None:
            object.__setattr__(
                self, "programs_dir", Path(os.environ.get(ENV_PROGRAMS_DIR, self.home / "programs"))
            )
        if self.config_file is None:
            object.__setattr__(self, "config_file", Path(os.environ.get(ENV_CONFIG, self.home / "config.yaml")))
        config_data: dict = {}
        if self.config_file and self.config_file.is_file():
            try:
                import yaml

                config_data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
            except Exception:
                config_data = {}
        integrations = config_data.get("integrations", {}) if isinstance(config_data, dict) else {}
        burp = integrations.get("burp", {}) if isinstance(integrations, dict) else {}
        playwright = integrations.get("playwright", {}) if isinstance(integrations, dict) else {}
        intake = config_data.get("program_intake", config_data.get("intake", {})) if isinstance(config_data, dict) else {}
        if isinstance(intake, dict):
            object.__setattr__(self, "intake_max_age_hours", max(1, int(intake.get("max_age_hours", self.intake_max_age_hours))))
            object.__setattr__(self, "intake_refresh_before_hunt", bool(intake.get("refresh_before_hunt", self.intake_refresh_before_hunt)))
        # Explicit constructor values win, followed by explicit YAML and then
        # environment overrides.  There is deliberately no port-open fallback.
        if self.burp_proxy is None:
            object.__setattr__(
                self, "burp_proxy",
                burp.get("proxy_url") or burp.get("proxy") or os.environ.get(ENV_BURP_PROXY),
            )
        if self.burp_mcp is None:
            object.__setattr__(
                self, "burp_mcp",
                burp.get("mcp_url") or burp.get("mcp") or os.environ.get(ENV_BURP_MCP)
                or "http://127.0.0.1:9876",
            )
        if self.burp_ca is None:
            object.__setattr__(
                self, "burp_ca",
                burp.get("ca_bundle") or os.environ.get(ENV_BURP_CA),
            )
        if self.playwright_package is None:
            object.__setattr__(
                self, "playwright_package",
                os.environ.get(ENV_PLAYWRIGHT_PACKAGE) or playwright.get("package") or "@playwright/mcp",
            )

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

    def write_default_config(self) -> Path:
        """Create the non-secret canonical integration config if absent."""
        assert self.config_file is not None
        if not self.config_file.exists():
            self.config_file.write_text(
                "integrations:\n"
                "  burp:\n"
                "    mcp_url: http://127.0.0.1:9876\n"
                "    proxy_url: null  # set explicitly; an open 8080 is only a candidate\n"
                "    ca_bundle: null  # e.g. ~/.bughunt/certs/burp-ca.pem\n"
                "  playwright:\n"
                "    package: '@playwright/mcp'\n"
                "    headed: true\n"
                "program_intake:\n"
                "  max_age_hours: 24\n"
                "  refresh_before_hunt: true\n",
                encoding="utf-8",
            )
        return self.config_file


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
