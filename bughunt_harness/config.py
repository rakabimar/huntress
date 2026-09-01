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
ENV_PROJECT_ROOT = "BUGHUNT_PROJECT_ROOT"
ENV_PROGRAMS_DIR = "BUGHUNT_PROGRAMS_DIR"
ENV_CONFIG = "BUGHUNT_CONFIG"
ENV_ACTIVE_PROGRAM = "BUGHUNT_ACTIVE_PROGRAM"
ENV_BURP_PROXY = "BUGHUNT_BURP_PROXY"
ENV_BURP_MCP = "BUGHUNT_BURP_MCP"
ENV_BURP_CA = "BUGHUNT_BURP_CA"
ENV_PLAYWRIGHT_PACKAGE = "BUGHUNT_PLAYWRIGHT_PACKAGE"


def _default_home() -> Path:
    return Path(os.environ.get(ENV_HOME, Path.home() / ".bughunt"))


def _discover_project_root() -> Path:
    """Resolve the installed source/distribution root without CWD assumptions."""
    override = os.environ.get(ENV_PROJECT_ROOT)
    if override:
        return Path(override).expanduser().resolve()
    candidate = Path(__file__).resolve().parents[1]
    if (candidate / "pyproject.toml").is_file() or (candidate / "harness").is_file():
        return candidate
    return Path(__file__).resolve().parent


@dataclass(frozen=True)
class HarnessPaths:
    """Authoritative immutable path layout for source and mutable user state."""

    project_root: Path = field(default_factory=_discover_project_root)
    bughunt_home: Path = field(default_factory=_default_home)
    programs_root: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_root", Path(self.project_root).expanduser().resolve())
        object.__setattr__(self, "bughunt_home", Path(self.bughunt_home).expanduser().resolve())
        if self.programs_root is None:
            value = os.environ.get(ENV_PROGRAMS_DIR)
            object.__setattr__(self, "programs_root", Path(value).expanduser().resolve() if value else self.bughunt_home / "programs")

    @property
    def secrets_root(self) -> Path:
        return self.bughunt_home / "secrets"

    @property
    def cache_root(self) -> Path:
        return self.bughunt_home / "cache"

    @property
    def generated_root(self) -> Path:
        return self.project_root / "generated"

    @property
    def skills_root(self) -> Path:
        return self.project_root / "skills"

    @property
    def agent_specs_root(self) -> Path:
        return self.project_root / "agent-specs"

    @property
    def certs_root(self) -> Path:
        return self.bughunt_home / "certs"

    @property
    def temporary_root(self) -> Path:
        return self.bughunt_home / "tmp"

    @property
    def distribution_root(self) -> Path:
        return self.project_root

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
    paths: HarnessPaths | None = None
    oast_config: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        paths = self.paths or HarnessPaths(bughunt_home=self.home, programs_root=self.programs_dir)
        object.__setattr__(self, "paths", paths)
        object.__setattr__(self, "home", paths.bughunt_home)
        # Frozen dataclass: resolve lazily via object.__setattr__.
        if self.programs_dir is None:
            object.__setattr__(
                self, "programs_dir", Path(os.environ.get(ENV_PROGRAMS_DIR, self.home / "programs"))
            )
        if self.paths is not None and self.paths.programs_root != self.programs_dir:
            object.__setattr__(self, "paths", HarnessPaths(
                project_root=self.paths.project_root, bughunt_home=self.home,
                programs_root=Path(self.programs_dir),
            ))
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
        oast = config_data.get("oast", {}) if isinstance(config_data, dict) else {}
        if not self.oast_config and isinstance(oast, dict):
            object.__setattr__(self, "oast_config", dict(oast))
        intake = config_data.get("program_intake", config_data.get("intake", {})) if isinstance(config_data, dict) else {}
        if isinstance(intake, dict):
            object.__setattr__(self, "intake_max_age_hours", max(1, int(intake.get("max_age_hours", self.intake_max_age_hours))))
            object.__setattr__(self, "intake_refresh_before_hunt", bool(intake.get("refresh_before_hunt", self.intake_refresh_before_hunt)))
        # Explicit constructor values win, followed by explicit YAML and then
        # environment overrides.  There is deliberately no port-open fallback.
        if self.burp_proxy is None:
            object.__setattr__(
                self, "burp_proxy",
                os.environ.get(ENV_BURP_PROXY) or burp.get("proxy_url") or burp.get("proxy"),
            )
        if self.burp_mcp is None:
            object.__setattr__(
                self, "burp_mcp",
                os.environ.get(ENV_BURP_MCP) or burp.get("mcp_url") or burp.get("mcp")
                or "http://127.0.0.1:9876",
            )
        if self.burp_ca is None:
            object.__setattr__(
                self, "burp_ca",
                os.environ.get(ENV_BURP_CA) or burp.get("ca_bundle"),
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
        assert self.paths is not None
        for p in (
            self.home, self.programs_dir, self.secrets_dir, self.logs_dir,
            self.paths.cache_root, self.paths.certs_root, self.paths.temporary_root,
        ):
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
                "oast:\n"
                "  provider: null  # interactsh or generic; third-party use remains policy-gated\n"
                "  interactsh_server: null  # omit for official client defaults\n"
                "  generic: {}  # base_domain, allocate_endpoint, poll_endpoint, token_ref\n"
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


def get_paths() -> HarnessPaths:
    """Return the process path layout used by all adapters and services."""
    cfg = get_config()
    assert cfg.paths is not None
    return cfg.paths


def get_config() -> HarnessConfig:
    """Return a memoized HarnessConfig (dirs guaranteed to exist)."""
    global _default_config
    if _default_config is None:
        _default_config = load_config()
    return _default_config
