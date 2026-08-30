"""Action policy taxonomy.

Actions are classified *separately* from raw targets (a target being in scope
does not make every action on it acceptable).  Each action carries a default
risk class; the policy engine overlays program ROE on top.  The model must
never be the thing that decides the class — classification is deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass


class RiskClass:
    R0 = "R0"  # analysis only — no network interaction
    R1 = "R1"  # low-impact active request
    R2 = "R2"  # controlled active mutation
    R3 = "R3"  # explicit human approval required
    R4 = "R4"  # disabled by default


RISK_ORDER = [RiskClass.R0, RiskClass.R1, RiskClass.R2, RiskClass.R3, RiskClass.R4]


@dataclass(frozen=True)
class Action:
    name: str
    risk_class: str
    description: str
    network: bool = True
    group: str = "active"


# name -> Action.  Canonical taxonomy (superset of the spec's §12 list).
ACTIONS: dict[str, Action] = {
    "analyze": Action("analyze", RiskClass.R0, "Pure analysis of already-collected artifacts; no network", network=False, group="analysis"),
    "source_read": Action("source_read", RiskClass.R0, "Read commit-pinned inert source", network=False, group="source"),
    "source_static_analysis": Action("source_static_analysis", RiskClass.R0, "Run a non-executing local static analyzer", network=False, group="source"),
    "source_build": Action("source_build", RiskClass.R3, "Build source inside the disposable network-off sandbox", network=False, group="source"),
    "source_test": Action("source_test", RiskClass.R3, "Run project tests inside the disposable network-off sandbox", network=False, group="source"),
    "source_reproducer": Action("source_reproducer", RiskClass.R3, "Run one bounded reproducer inside the disposable network-off sandbox", network=False, group="source"),
    "source_fuzz": Action("source_fuzz", RiskClass.R3, "Run one time/CPU-bounded local fuzz harness", network=False, group="source"),
    "source_start_local_service": Action("source_start_local_service", RiskClass.R3, "Start a bounded service only inside the local sandbox", network=False, group="source"),
    "source_network": Action("source_network", RiskClass.R4, "Allow repository-controlled outbound network access", group="destructive"),
    "read_http": Action("read_http", RiskClass.R1, "Read-only HTTP GET/HEAD against an in-scope endpoint", group="observe"),
    "replay_http": Action("replay_http", RiskClass.R1, "Re-send a previously observed request unmodified", group="observe"),
    "parameter_mutation": Action("parameter_mutation", RiskClass.R2, "Send a controlled single-request parameter mutation", group="mutate"),
    "authorization_test": Action("authorization_test", RiskClass.R2, "Cross-principal / cross-tenant access-control test", group="identity"),
    "authentication_test": Action("authentication_test", RiskClass.R2, "Login/session/JWT/OAuth authentication testing", group="identity"),
    "session_test": Action("session_test", RiskClass.R2, "Session lifecycle and fixation/invalidation testing", group="identity"),
    "business_logic_test": Action("business_logic_test", RiskClass.R2, "Workflow/state/ordering logic testing", group="logic"),
    "graphql_test": Action("graphql_test", RiskClass.R2, "Bounded GraphQL query and authorization testing", group="mutate"),
    "injection_probe": Action("injection_probe", RiskClass.R2, "Single bounded injection distinguishing probe", group="mutate"),
    "upload_test": Action("upload_test", RiskClass.R2, "Controlled file-upload testing", group="mutate"),
    "csrf_test": Action("csrf_test", RiskClass.R2, "Cross-site request forgery testing", group="identity"),
    "limited_fuzz": Action("limited_fuzz", RiskClass.R2, "Bounded, low-volume fuzzing", group="mutate"),
    "state_changing_request": Action("state_changing_request", RiskClass.R2, "Request that changes application state (POST/PUT/DELETE)", group="mutate"),
    "browser_observe": Action("browser_observe", RiskClass.R1, "Read-only browser navigation, DOM inspection, snapshot, or screenshot", group="browser"),
    "browser_suspicious_navigation": Action("browser_suspicious_navigation", RiskClass.R3, "GET navigation whose path commonly carries a state-changing effect", group="browser"),
    "browser_test_account_mutation": Action("browser_test_account_mutation", RiskClass.R2, "Reversible mutation owned by the configured test account", group="browser"),
    "browser_third_party_communication": Action("browser_third_party_communication", RiskClass.R3, "Browser action that communicates with a third party", group="browser"),
    "browser_financial_operation": Action("browser_financial_operation", RiskClass.R3, "Purchase, redeem, transfer, or other financial/business commitment", group="browser"),
    "browser_credential_change": Action("browser_credential_change", RiskClass.R3, "Password, MFA, recovery, or other credential lifecycle change for a test account", group="browser"),
    "browser_role_change": Action("browser_role_change", RiskClass.R3, "Role, privilege, membership, or invitation change", group="browser"),
    "browser_irreversible_action": Action("browser_irreversible_action", RiskClass.R4, "Irreversible, destructive, persistent, or non-test-account browser action", group="destructive"),
    "passive_recon": Action("passive_recon", RiskClass.R0, "Passive source discovery without target interaction", network=False, group="recon"),
    "historical_url_recon": Action("historical_url_recon", RiskClass.R0, "Query configured historical URL sources", network=False, group="recon"),
    "active_recon": Action("active_recon", RiskClass.R2, "Scope-filtered DNS/HTTP asset validation", group="recon"),
    "crawl": Action("crawl", RiskClass.R2, "Bounded in-scope crawl", group="recon"),
    "bounded_scan": Action("bounded_scan", RiskClass.R3, "Explicitly bounded approved scanning plan", group="recon"),
    "race_test": Action("race_test", RiskClass.R3, "Concurrent/race-condition testing", group="logic"),
    "oob_test": Action("oob_test", RiskClass.R3, "Out-of-band interaction testing (callbacks/burp collaborator)", group="observe"),
    "brute_force": Action("brute_force", RiskClass.R3, "Credential/identifier brute forcing", group="identity"),
    "dos": Action("dos", RiskClass.R4, "Denial-of-service testing", group="destructive"),
    "destructive": Action("destructive", RiskClass.R4, "Destructive / irrecoverable actions", group="destructive"),
}


def get_action(name: str) -> Action:
    try:
        return ACTIONS[name]
    except KeyError:
        from .errors import PolicyError

        raise PolicyError(f"unknown action: {name!r} (legal: {sorted(ACTIONS)})")


def action_names() -> list[str]:
    return sorted(ACTIONS)


def max_risk_class(actions: list[str]) -> str:
    """Highest (most restrictive) risk class among a set of actions."""
    idx = max(RISK_ORDER.index(get_action(a).risk_class) for a in actions)
    return RISK_ORDER[idx]


__all__ = ["Action", "RiskClass", "RISK_ORDER", "ACTIONS", "get_action", "action_names", "max_risk_class"]
