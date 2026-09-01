"""Broker-backed replay, auth differential, mutation and bounded concurrency."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..timeutil import utcnow
from .response_diff import ResponseComparator
from .templates import RequestMutation, RequestTemplate

MAX_REPLAY_DEPTH = 12


@dataclass
class DifferentialAuthResult:
    mode: str
    request_ids: list[str]
    contexts: list[str]
    baseline_context: str
    expected_owner_context: str
    statuses: list[int | None]
    response_difference: dict
    errors: list[str] = field(default_factory=list)
    session_refresh_actions: list[str] = field(default_factory=list)
    differential_result_id: int | None = None
    observation_only: bool = True


class ReplayService:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def template_for_request(self, request_id: int) -> RequestTemplate:
        return RequestTemplate.from_request_record(
            self.ctx.db.get_request_record(request_id), workspace=self.ctx.workspace,
        )

    def replay_request(
        self, request_id: int, *, mutations: list[RequestMutation] | None = None,
        auth_context: str | None = None, session_id: int, agent_role: str = "researcher",
        research_test_id: int | None = None, hypothesis_id: int | None = None,
        action: str | None = None,
    ):
        parent = self.ctx.db.get_request_record(request_id)
        if parent.program != self.ctx.slug:
            raise ValueError("request belongs to a different program")
        if parent.replay_depth >= MAX_REPLAY_DEPTH:
            raise ValueError(f"maximum replay depth {MAX_REPLAY_DEPTH} reached")
        changes = list(mutations or [])
        template = self.template_for_request(request_id).mutated(changes)
        effective_action = action or _replay_action(template.method, bool(changes))
        mutation_doc = {"mutations": [item.as_dict() for item in changes]}
        kwargs = template.broker_kwargs()
        return self.ctx.broker.execute(
            **kwargs, action=effective_action, auth_context=auth_context if auth_context is not None else template.auth_context,
            session_id=session_id, agent_role=agent_role, research_test_id=research_test_id,
            hypothesis_id=hypothesis_id, controlled_mutation=mutation_doc,
            baseline_evidence_id=parent.evidence_ref, parent_request_id=parent.id,
            root_request_id=parent.root_request_id or parent.id,
            replay_depth=parent.replay_depth + 1,
            mutation_summary=_mutation_summary(changes),
        )

    def replay_evidence_request(self, evidence_id: str, **kwargs):
        matches = [record for record in self.ctx.db.list_request_records() if record.evidence_ref == evidence_id]
        if len(matches) != 1:
            raise ValueError("evidence must map to exactly one request record")
        return self.replay_request(matches[0].id, **kwargs)

    def compare_across_auth(
        self, request_id: int, *, contexts: list[str], session_id: int,
        mutations: list[RequestMutation] | None = None, mode: str = "ROLE_A_VS_ROLE_B",
        baseline_context: str = "", expected_owner_context: str = "",
        research_test_id: int | None = None, hypothesis_id: int | None = None,
        agent_role: str = "api-authz-specialist",
    ) -> DifferentialAuthResult:
        if not 2 <= len(contexts) <= 4:
            raise ValueError("auth differential requires 2-4 explicit contexts")
        request_ids: list[str] = []
        statuses: list[int | None] = []
        errors: list[str] = []
        for context in contexts:  # deliberately sequential for deterministic baselines
            result = self.replay_request(
                request_id, mutations=mutations, auth_context=context,
                session_id=session_id, agent_role=agent_role,
                research_test_id=research_test_id, hypothesis_id=hypothesis_id,
                action="authorization_test",
            )
            if result.request_id:
                request_ids.append(result.request_id)
            statuses.append(result.status_code)
            if not result.ok:
                errors.append(f"{context}:{result.decision}:{result.reason}")
        records = [self.ctx.db.get_request_record(_numeric_id(item)) for item in request_ids]
        difference = ResponseComparator().compare_records(records, workspace=self.ctx.workspace).as_dict() if len(records) >= 2 else {}
        result_id = self.ctx.db.save_differential_result(
            mode=mode, baseline_request_id=records[0].id if records else None,
            request_ids=[record.id for record in records], result=difference,
            research_test_id=research_test_id, hypothesis_id=hypothesis_id,
        )
        return DifferentialAuthResult(
            mode=mode, request_ids=request_ids, contexts=contexts,
            baseline_context=baseline_context or contexts[0],
            expected_owner_context=expected_owner_context, statuses=statuses,
            response_difference=difference, errors=errors, differential_result_id=result_id,
        )


def _replay_action(method: str, mutated: bool) -> str:
    if mutated:
        return "parameter_mutation"
    return "replay_http" if method.upper() in {"GET", "HEAD", "OPTIONS"} else "state_changing_request"


def _mutation_summary(changes: list[RequestMutation]) -> str:
    return ", ".join(f"{item.location.value}:{item.field}:{item.operation.value}" for item in changes)[:500]


def _numeric_id(value: str) -> int:
    return int(value.rsplit("-", 1)[1])


__all__ = ["ReplayService", "DifferentialAuthResult", "MAX_REPLAY_DEPTH"]
