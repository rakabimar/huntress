"""Bounded, one-variable-at-a-time type-aware request mutation plans."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .requests.replay import ReplayService
from .requests.response_diff import ResponseComparator
from .requests.templates import MutationLocation, MutationOperation, RequestMutation


@dataclass
class MutationPlan:
    request_id: int
    parameters: list[dict]
    strategy: str
    max_requests: int
    max_parameters: int = 5
    max_candidates_per_parameter: int = 8
    skill: str = "fuzzing"
    goal: str = "identify differential response clusters"
    multi_field: bool = False

    def __post_init__(self) -> None:
        if self.max_requests < 1 or self.max_requests > 100:
            raise ValueError("max_requests must be explicitly bounded to 1..100")
        if self.max_parameters < 1 or self.max_parameters > 20:
            raise ValueError("max_parameters must be 1..20")
        if self.max_candidates_per_parameter < 1 or self.max_candidates_per_parameter > 20:
            raise ValueError("max_candidates_per_parameter must be 1..20")
        if len(self.parameters) > self.max_parameters:
            raise ValueError("parameter plan exceeds max_parameters")


class MutationEngine:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def candidates(self, parameter: dict) -> list[Any]:
        value, kind = parameter.get("value"), parameter.get("type") or _type(value)
        observed = list(parameter.get("observed_values") or [])
        if kind == "integer":
            values = [0, -1, 1, value, parameter.get("other_owned_id")]
        elif kind == "boolean":
            values = [True, False]
        elif kind == "enum":
            values = observed
        elif kind == "array":
            values = [[], ([value[0]] if value else []), (list(value) + ["benign"] if isinstance(value, list) else ["benign"])]
        else:
            values = ["", None, str(value or ""), *observed]
        out = []
        for item in values:
            if item not in out and item != value:
                out.append(item)
        return out

    def execute(self, plan: MutationPlan, *, session_id: int, research_test_id: int | None = None, hypothesis_id: int | None = None) -> dict:
        replay = ReplayService(self.ctx)
        baseline_parent = self.ctx.db.get_request_record(plan.request_id)
        decision = self.ctx.policy.check("limited_fuzz", baseline_parent.url)
        if decision.decision != "allow":
            return {"requests_used": 0, "decision": decision.decision, "reason": decision.reason, "observation_only": True}
        request_ids = [baseline_parent.public_id]
        observations = []
        used = 0
        for parameter in plan.parameters:
            for candidate in self.candidates(parameter)[:plan.max_candidates_per_parameter]:
                if used >= plan.max_requests:
                    break
                mutation = RequestMutation(
                    location=MutationLocation(parameter.get("location", "query")),
                    field=str(parameter["field"]), operation=MutationOperation.SET,
                    new_value=candidate, reason=plan.goal, source_skill=plan.skill,
                )
                result = replay.replay_request(
                    plan.request_id, mutations=[mutation], session_id=session_id,
                    research_test_id=research_test_id, hypothesis_id=hypothesis_id,
                )
                used += 1
                if result.request_id:
                    request_ids.append(result.request_id)
                    observations.append({"request_id": result.request_id, "field": parameter["field"], "candidate": candidate, "status": result.status_code})
            if used >= plan.max_requests:
                break
        records = [self.ctx.db.get_request_record(_id(item)) for item in request_ids]
        difference = ResponseComparator().compare_records(records, workspace=self.ctx.workspace).as_dict() if len(records) > 1 else {}
        return {"requests_used": used, "request_ids": request_ids, "observations": observations, "response_clusters": difference.get("clusters", []), "differential": difference, "observation_only": True}

    @staticmethod
    def smart_wordlist(*sources: list[str], limit: int = 200) -> list[str]:
        words = []
        for source in sources:
            for value in source:
                for token in str(value).replace("_", "-").split("-"):
                    token = token.strip().lower()
                    if 2 <= len(token) <= 64 and token.isascii() and token not in words:
                        words.append(token)
        return words[:limit]


def _type(value: Any) -> str:
    if isinstance(value, bool): return "boolean"
    if isinstance(value, int): return "integer"
    if isinstance(value, list): return "array"
    return "string"


def _id(value: str) -> int:
    return int(value.rsplit("-", 1)[1])


__all__ = ["MutationPlan", "MutationEngine"]
