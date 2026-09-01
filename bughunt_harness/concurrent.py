"""Explicit bounded race testing; barrier synchronization, not single-packet."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .requests.replay import ReplayService
from .requests.response_diff import ResponseComparator


@dataclass
class ConcurrentRequestPlan:
    request_id: int
    count: int
    max_concurrency: int
    mode: str = "PARALLEL"
    auth_context: str = ""
    duration_seconds: int = 30
    post_condition_request_id: int | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"PARALLEL", "BARRIER_SYNCHRONIZED"}:
            raise ValueError("unsupported concurrency mode")
        if not 2 <= self.count <= 20 or not 2 <= self.max_concurrency <= 10:
            raise ValueError("race plan must remain within count 2..20 and concurrency 2..10")
        if self.max_concurrency > self.count:
            raise ValueError("max_concurrency cannot exceed request count")
        if self.mode == "BARRIER_SYNCHRONIZED" and self.max_concurrency != self.count:
            raise ValueError("barrier mode requires max_concurrency equal to count")


class ConcurrentRequestExecutor:
    synchronization_level = "application-thread barrier; not last-byte/single-packet"

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, plan: ConcurrentRequestPlan, *, session_id: int, research_test_id: int | None = None, hypothesis_id: int | None = None) -> dict:
        parent = self.ctx.db.get_request_record(plan.request_id)
        decision = self.ctx.policy.check("race_test", parent.url)
        if decision.decision == "deny":
            return {"ok": False, "decision": decision.decision, "reason": decision.reason, "synchronization": self.synchronization_level}
        if decision.decision == "approval_required":
            from .requests.broker import request_params_hash
            template = ReplayService(self.ctx).template_for_request(plan.request_id)
            kwargs = template.broker_kwargs()
            mutation = {"mutations": []}
            params_hash = request_params_hash(
                template.method, kwargs["target"], kwargs.get("body"), kwargs.get("json_body"),
                kwargs.get("params"), mutation,
            )
            approval = self.ctx.db.find_valid_approval(
                "race_test", kwargs["target"], self.ctx.slug, template.method,
                params_hash, plan.auth_context or template.auth_context,
            )
            if approval is None:
                pending = self.ctx.db.request_approval(
                    "race_test", kwargs["target"], program=self.ctx.slug, method=template.method,
                    params_hash=params_hash, auth_context=plan.auth_context or template.auth_context,
                    session_id=session_id, requested_by="race-condition-specialist",
                    constraints={"max_requests": plan.count, "max_concurrency": plan.max_concurrency,
                                 "duration_seconds": plan.duration_seconds, "targets": [kwargs["target"]]},
                )
                return {"ok": False, "decision": "approval_required", "reason": decision.reason,
                        "approval_id": pending.public_id, "synchronization": self.synchronization_level}
        barrier = threading.Barrier(plan.count) if plan.mode == "BARRIER_SYNCHRONIZED" else None
        replay = ReplayService(self.ctx)

        def one(_index):
            if barrier: barrier.wait(timeout=plan.duration_seconds)
            return replay.replay_request(
                plan.request_id, session_id=session_id, auth_context=plan.auth_context or None,
                research_test_id=research_test_id, hypothesis_id=hypothesis_id, action="race_test",
            )
        with ThreadPoolExecutor(max_workers=plan.max_concurrency) as pool:
            results = list(pool.map(one, range(plan.count)))
        ids = [result.request_id for result in results if result.request_id]
        records = [self.ctx.db.get_request_record(int(item.rsplit("-", 1)[1])) for item in ids]
        diff = ResponseComparator().compare_records(records, workspace=self.ctx.workspace).as_dict() if len(records) > 1 else {}
        post = None
        if plan.post_condition_request_id:
            post = replay.replay_request(plan.post_condition_request_id, session_id=session_id, action="read_http").as_dict()
        return {"ok": all(item.ok for item in results), "request_ids": ids, "clusters": diff.get("clusters", []), "differential": diff, "post_condition": post, "synchronization": self.synchronization_level, "observation_only": True}


__all__ = ["ConcurrentRequestPlan", "ConcurrentRequestExecutor"]
