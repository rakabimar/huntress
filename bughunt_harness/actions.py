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
    "read_http": Action("read_http", RiskClass.R1, "Read-only HTTP GET/HEAD against an in-scope endpoint", group="observe"),
    "replay_http": Action("replay_http", RiskClass.R1, "Re-send a previously observed request unmodified", group="observe"),
    "parameter_mutation": Action("parameter_mutation", RiskClass.R2, "Send a controlled single-request parameter mutation", group="mutate"),
    "authorization_test": Action("authorization_test", RiskClass.R2, "Cross-principal / cross-tenant access-control test", group="identity"),
    "authentication_test": Action("authentication_test", RiskClass.R2, "Login/session/JWT/OAuth authentication testing", group="identity"),
    "business_logic_test": Action("business_logic_test", RiskClass.R2, "Workflow/state/ordering logic testing", group="logic"),
    "upload_test": Action("upload_test", RiskClass.R2, "Controlled file-upload testing", group="mutate"),
    "csrf_test": Action("csrf_test", RiskClass.R2, "Cross-site request forgery testing", group="identity"),
    "limited_fuzz": Action("limited_fuzz", RiskClass.R2, "Bounded, low-volume fuzzing", group="mutate"),
    "state_changing_request": Action("state_changing_request", RiskClass.R2, "Request that changes application state (POST/PUT/DELETE)", group="mutate"),
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