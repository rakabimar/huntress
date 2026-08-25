"""Deterministic action-policy engine.

Classifies a proposed action on a target against program scope + ROE and emits
one of three verdicts: allow / approval_required / deny.  The AI model NEVER
decides the class — this engine does, deterministically, from the taxonomy and
the program's Rules of Engagement.

Evaluation order (first match wins):
    1. unknown action          -> error
    2. roe.forbidden_actions   -> deny (forbidden_for_program)
    3. risk class R4           -> deny (disabled_by_default)
    4. target out of scope     -> deny (out_of_scope)
    5. roe activity flag false -> deny (not_allowed_by_roe)
    6. roe.manual_approval     -> approval_required
    7. risk class R3           -> approval_required
    8. network + no automation -> approval_required
    9. otherwise               -> allow
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..actions import RiskClass, get_action
from ..engagement.models import ROEModel, ScopeModel
from ..errors import PolicyError
from ..scope.engine import ScopeDecision, ScopeEngine

ALLOW = "allow"
APPROVAL_REQUIRED = "approval_required"
DENY = "deny"

# Action name -> matching ROE boolean flag gate.
ACTION_ROE_GATE = {
    "authentication_test": "authentication_testing",
    "authorization_test": "authorization_testing",
    "upload_test": "file_upload",
    "race_test": "race_conditions",
    "limited_fuzz": "fuzzing",
    "oob_test": "out_of_band_testing",
    "state_changing_request": "state_changing_actions",
    "brute_force": "brute_force",
    "dos": "denial_of_service",
    "destructive": "destructive_testing",
}


@dataclass
class PolicyDecision:
    action: str
    decision: str
    risk_class: str
    reason: str
    scope: ScopeDecision | None = None
    constraints: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.decision == APPROVAL_REQUIRED

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "decision": self.decision,
            "risk_class": self.risk_class,
            "reason": self.reason,
            "scope": self.scope.as_dict() if self.scope else None,
            "constraints": self.constraints,
        }


class PolicyEngine:
    def __init__(self, scope: ScopeModel, roe: ROEModel) -> None:
        self.scope = ScopeEngine(scope)
        self.roe = roe

    def _constraints(self) -> dict:
        return {
            "max_rps": self.roe.max_rps,
            "max_concurrency": self.roe.max_concurrency,
            "required_headers": list(self.roe.required_headers),
            "automation_allowed": self.roe.automation_allowed,
        }

    def check(self, action: str, target: str | None = None) -> PolicyDecision:
        act = get_action(action)

        # Scope (only when a target is supplied).
        scope_decision = None
        if target is not None:
            scope_decision = self.scope.check(target)

        constraints = self._constraints()

        if action in self.roe.forbidden_actions:
            return PolicyDecision(action, DENY, act.risk_class, "forbidden_for_program", scope_decision, constraints)

        if act.risk_class == RiskClass.R4:
            return PolicyDecision(action, DENY, act.risk_class, "disabled_by_default", scope_decision, constraints)

        if scope_decision is not None and not scope_decision.allowed:
            return PolicyDecision(action, DENY, act.risk_class, f"out_of_scope: {scope_decision.reason}", scope_decision, constraints)

        gate = ACTION_ROE_GATE.get(action)
        if gate is not None and getattr(self.roe, gate) is False:
            return PolicyDecision(action, DENY, act.risk_class, f"not_allowed_by_roe: {gate}=false", scope_decision, constraints)

        if action in self.roe.manual_approval_actions:
            return PolicyDecision(action, APPROVAL_REQUIRED, act.risk_class, "manual_approval_required", scope_decision, constraints)

        if act.risk_class == RiskClass.R3:
            return PolicyDecision(action, APPROVAL_REQUIRED, act.risk_class, "high_risk_requires_approval", scope_decision, constraints)

        if act.network and not self.roe.automation_allowed:
            return PolicyDecision(action, APPROVAL_REQUIRED, act.risk_class, "automation_disabled", scope_decision, constraints)

        return PolicyDecision(action, ALLOW, act.risk_class, "allowed", scope_decision, constraints)

    def require_allow(self, action: str, target: str | None = None) -> PolicyDecision:
        """Return the decision, raising if it is not an unambiguous allow."""
        d = self.check(action, target)
        if d.decision == ALLOW:
            return d
        if d.decision == DENY:
            from ..errors import ActionForbiddenError

            raise ActionForbiddenError(f"action {action!r} denied: {d.reason}")
        from ..errors import ApprovalRequiredError

        raise ApprovalRequiredError(f"action {action!r} requires approval: {d.reason}")
        return d  # pragma: no cover


__all__ = [
    "ALLOW",
    "APPROVAL_REQUIRED",
    "DENY",
    "ACTION_ROE_GATE",
    "PolicyDecision",
    "PolicyEngine",
]