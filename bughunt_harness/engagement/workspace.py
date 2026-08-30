"""Program workspace creation and engagement file loading/saving.

A program workspace is a self-contained directory per program, living OUTSIDE
the Git-tracked harness repository (under ``~/.bughunt/programs/<slug>``).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..config import HarnessConfig, get_config
from ..errors import EngagementValidationError, ProgramError
from ..registry import ProgramRecord
from .models import (
    AccountsModel,
    AutonomyModel,
    Engagement,
    HeadersModel,
    ProgramModel,
    ReportingModel,
    ReconModel,
    IntegrationsModel,
    ROEModel,
    ScopeModel,
)

# Valid slug: lowercase letters, digits, dashes; must start with a letter.
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,49}$")

ENGAGEMENT_FILES = (
    "program.yaml",
    "scope.yaml",
    "roe.yaml",
    "headers.yaml",
    "accounts.yaml",
    "reporting.yaml",
    "autonomy.yaml",
    "recon.yaml",
    "integrations.yaml",
)
OPTIONAL_ENGAGEMENT_FILES = frozenset({"autonomy.yaml", "recon.yaml", "integrations.yaml"})

WORKSPACE_SUBDIRS = (
    "intake",
    "knowledge",
    "state",
    "checkpoints",
    "recon",
    "source/repos",
    "source/artifacts",
    "source/analysis",
    "source/indexes",
    "artifacts",
    "evidence",
    "findings",
    "reports",
    "browser",
    "burp",
    "logs",
)

_TEMPLATES: dict[str, str] = {
    "roe.yaml": """\
# Rules of Engagement — program-specific activity constraints.
automation_allowed: false
authentication_testing: false
authorization_testing: true
file_upload: false
race_conditions: false
fuzzing: false
out_of_band_testing: false
state_changing_actions: false
brute_force: false
denial_of_service: false
destructive_testing: false
passive_recon: true
historical_url_recon: true
active_recon: false
crawling: false
bounded_scanning: false

max_rps: 3.0
max_concurrency: 1

# Action names requiring explicit human approval (on top of risk class).
manual_approval_actions: []      # e.g. [race_test, oob_test]
# Action names always forbidden for this program.
forbidden_actions: []            # e.g. [dos, destructive]
# Header names that MUST be present on every request (e.g. a bounty marker).
required_headers: []
notes: ""
""",
    "headers.yaml": """\
# Header metadata.  `secret: true` headers reference a credential, gate never
# stores the plaintext value here; set `value_ref` to e.g. env:BUGHUNT_H1_TOKEN.
headers:
  - name: X-Bug-Bounty
    mandatory: false
    secret: false
    value_ref: null
    note: ""
secret_patterns: []  # optional regular expressions redacted from artifacts
""",
    "accounts.yaml": """\
# Logical accounts (roles), NOT credentials.  Credentials live in the secret
# store (env / keyring / protected file), referenced by `secret_ref`.
accounts:
  - id: account_a
    role: regular_user
    description: ""
    secret_ref: null
    auth: null
    enabled: true
  - id: account_b
    role: second_user
    description: ""
    secret_ref: null
    auth: null
    enabled: true
  - id: admin_test
    role: admin
    description: ""
    secret_ref: null
    auth: null
    enabled: false
""",
    "autonomy.yaml": """\
# Autonomous hunting is opt-in and always bounded by these hard limits.
enabled: false
goal: validated_finding
stop_on_validated_finding: true
max_session_minutes: 180
max_total_requests: 1000
max_leads_per_session: 20
max_leads_per_run: null  # preferred; null uses legacy max_leads_per_session
max_hypotheses_per_lead: 8
max_tests_per_hypothesis: 30
max_requests_per_hypothesis: 30
max_inconclusive_tests_per_hypothesis: 4
max_failed_tests_per_hypothesis: 5
max_redirects: 5
# Deprecated and ignored; use an explicit later goal to orchestrate outputs.
auto_prepare_outputs: false
""",
    "recon.yaml": """\
# Recon freshness and deterministic interest-score overrides.
passive_max_age_hours: 24
light_max_age_hours: 12
standard_max_age_hours: 24
deep_max_age_hours: 168
lead_threshold: 40
interest_weights: {}
""",
    "integrations.yaml": """\
# Optional per-program integration overrides. Explicit values here take
# precedence over global config and environment variables.
burp:
  mcp_url: null
  proxy_url: null
  ca_bundle: null
  https_interception: false
playwright:
  headed: true
""",
    "reporting.yaml": """\
# Reporting / submission preferences (platform profile is auto-detected from
# program.yaml unless overridden here).
platform: null
severity_mechanism: null
required_fields: []
submission_checklist: []
notes: ""
""",
}


def slug_ok(slug: str) -> bool:
    return bool(SLUG_RE.match(slug))


def workspace_path_for(slug: str, config: HarnessConfig | None = None) -> Path:
    if not slug_ok(slug):
        raise ProgramError(
            f"invalid program slug {slug!r}: must be 2-50 chars, lowercase a-z/0-9/-"
        )
    cfg = config or get_config()
    return cfg.programs_dir / slug


def _program_yaml(record: ProgramRecord) -> str:
    """Render program.yaml from the registry record (single source of truth)."""
    return yaml.safe_dump(
        {
            "name": record.name,
            "platform": record.platform,
            "program_url": record.program_url,
            "status": record.status,
            "notes": record.notes or "",
        },
        sort_keys=False,
        allow_unicode=True,
    )


def _scope_yaml(fixture: bool) -> str:
    """Render scope.yaml.

    ``fixture=True`` emits an explicit synthetic ``*.test`` scope for local /
    offline testing.  ``fixture=False`` emits an EMPTY include — a real program
    must be scoped by hand before it can pass engagement validation (P0.2).
    """
    include = (
        "  domains: [example.test]\n"
        "  wildcards: [\"*.example.test\"]\n"
        if fixture
        else "  domains: []\n  wildcards: []\n"
    )
    header = (
        "# Synthetic fixture scope — local/offline testing ONLY (@RFC6761 .test).\n"
        if fixture
        else "# Scope. \"exclude\" ALWAYS wins over \"include\".\n"
        "# Add your in-scope targets below before any testing.\n"
    )
    return (
        header
        + "include:\n"
        + include
        + "  subdomains: []\n"
        + "  urls: []\n"
        + "  path_urls: []\n"
        + "  ipv4: []\n"
        + "  cidr: []\n"
        + "exclude:\n"
        + "  domains: []\n"
        + "  wildcards: []\n"
        + "  subdomains: []\n"
        + "  urls: []\n"
        + "  path_urls: []\n"
        + "  ipv4: []\n"
        + "  cidr: []\n"
        + ('notes: "Fixture scope for local-only tests. Do NOT point at real targets."\n'
           if fixture else 'notes: ""\n')
    )


def create_workspace(record: ProgramRecord, fixture: bool = False) -> Path:
    """Create the on-disk workspace (dirs + template engagement files)."""
    ws = Path(record.workspace_path)
    if ws.exists() and any(ws.iterdir()):
        raise ProgramError(f"workspace already exists and is not empty: {ws}")
    for sub in WORKSPACE_SUBDIRS:
        (ws / sub).mkdir(parents=True, exist_ok=True)
    # program.yaml is generated from the registry record (P0.1); scope.yaml is
    # empty or fixture-scoped (P0.2) — never a fake example.test default.
    (ws / "program.yaml").write_text(_program_yaml(record), encoding="utf-8")
    (ws / "scope.yaml").write_text(_scope_yaml(fixture), encoding="utf-8")
    for fname, content in _TEMPLATES.items():
        path = ws / fname
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    return ws


def write_program_status(record: ProgramRecord) -> None:
    """Reflect the registry status onto program.yaml (keeps the two in sync)."""
    ws = Path(record.workspace_path)
    path = ws / "program.yaml"
    if not path.is_file():
        return
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data["status"] = record.status
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Loading / saving
# --------------------------------------------------------------------------- #
def load_engagement(ws: Path) -> Engagement:
    """Load and validate the engagement files from a workspace."""
    if not ws.is_dir():
        raise EngagementValidationError(f"workspace directory missing: {ws}")
    missing = [
        f for f in ENGAGEMENT_FILES
        if f not in OPTIONAL_ENGAGEMENT_FILES and not (ws / f).is_file()
    ]
    if missing:
        raise EngagementValidationError(f"missing engagement files: {missing}")

    raw = {}
    for fname in ENGAGEMENT_FILES:
        if not (ws / fname).is_file():
            raw[fname] = {}
            continue
        try:
            raw[fname] = yaml.safe_load((ws / fname).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:  # type: ignore[attr-defined]
            raise EngagementValidationError(f"invalid YAML in {fname}: {exc}") from exc

    try:
        engagement = Engagement(
            program=ProgramModel.model_validate(raw["program.yaml"]),
            scope=ScopeModel.model_validate(raw["scope.yaml"]),
            roe=ROEModel.model_validate(raw["roe.yaml"]),
            headers=HeadersModel.model_validate(raw["headers.yaml"]),
            accounts=AccountsModel.model_validate(raw["accounts.yaml"]),
            reporting=ReportingModel.model_validate(raw["reporting.yaml"]),
            autonomy=AutonomyModel.model_validate(raw["autonomy.yaml"]),
            recon=ReconModel.model_validate(raw["recon.yaml"]),
            integrations=IntegrationsModel.model_validate(raw["integrations.yaml"]),
        )
    except Exception as exc:  # pydantic.ValidationError etc.
        raise EngagementValidationError(f"engagement validation failed: {exc}") from exc
    return engagement


def save_engagement(ws: Path, engagement: Engagement) -> None:
    """Serialize an Engagement back to its individual YAML files."""
    dump = lambda model: yaml.safe_dump(
        model.model_dump(mode="json"), sort_keys=False, allow_unicode=True
    ).strip() + "\n"
    (ws / "program.yaml").write_text(dump(engagement.program), encoding="utf-8")
    (ws / "scope.yaml").write_text(dump(engagement.scope), encoding="utf-8")
    (ws / "roe.yaml").write_text(dump(engagement.roe), encoding="utf-8")
    (ws / "headers.yaml").write_text(dump(engagement.headers), encoding="utf-8")
    (ws / "accounts.yaml").write_text(dump(engagement.accounts), encoding="utf-8")
    (ws / "reporting.yaml").write_text(dump(engagement.reporting), encoding="utf-8")
    (ws / "autonomy.yaml").write_text(dump(engagement.autonomy), encoding="utf-8")
    (ws / "recon.yaml").write_text(dump(engagement.recon), encoding="utf-8")
    (ws / "integrations.yaml").write_text(dump(engagement.integrations), encoding="utf-8")


__all__ = [
    "ENGAGEMENT_FILES",
    "OPTIONAL_ENGAGEMENT_FILES",
    "WORKSPACE_SUBDIRS",
    "slug_ok",
    "workspace_path_for",
    "create_workspace",
    "load_engagement",
    "save_engagement",
    "write_program_status",
]
