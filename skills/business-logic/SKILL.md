---
name: business-logic
description: Use for feature-specific security invariants and invalid state transitions across checkout, wallet, coupon, subscription, invite, approval, refund, quota, inventory, credits, and other multi-actor workflows.
maturity: stable
risk_class: R2
category: business-logic
cwe: [840, 841]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [feature-threat-model, workflow-bypass, payment-logic, race-condition, api-authorization]
primary_triggers: [feature invariant, state transition, multi-actor workflow, value conservation]
secondary_triggers: [stale state, replay, alternate endpoint, approval, quota]
negative_triggers: [cosmetic step, client-only calculation with server recomputation]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Business Logic

## Purpose
Hunt the feature's rules rather than a payload class. Model actors, assets, states, transitions, preconditions, postconditions, and invariants; then ask which single transition could violate a security or economic rule.

## When to use
Use for checkout, wallet, coupon, subscription, invite, role management, approvals, refunds/returns, quota, inventory, credits, gift cards, and any workflow where each endpoint may be valid alone but their composition is not.

## Process
1. Use feature-threat-model first for an unfamiliar feature. Write the state machine and identify the authoritative ledger/object.
2. State one invariant: value is conserved; an approval precedes execution; one actor cannot approve its own action; one-time capability is consumed; tenant/identity binding persists; final values equal approved values.
3. Choose one transition experiment: step B before A, replay A, use stale A after state change, actor B triggers A's transition, mutate value after approval, or invoke an alternate endpoint.
4. Establish normal start/end states. Change only sequence, actor, state token, or value and observe the authoritative postcondition—not only the immediate response.
5. Support only when the forbidden transition or inconsistent durable state occurs. If the server recomputes, rejects, idempotently returns the prior result, or repairs before protected effect, reject.

## Evidence
Persist the state diagram fragment, named invariant, actor and prerequisites, baseline transition, controlled deviation, authoritative before/after state, value/quantity ledger where applicable, and why the outcome is forbidden by feature semantics.

## False positives
Cosmetic skipped steps, documented retries, idempotent duplicate responses, eventual consistency without double effect, client values ignored by authoritative calculation, promotional behavior allowed by terms, and test-environment artifacts.

## Stop conditions
Stop before real money, inventory depletion, third-party orders, irreversible approvals/refunds, scale, or unknown business rules. ASK for a single controlled financial/state mutation when required; DENY destructive or availability effects.

Read references/attack-surface.md for domain invariants and decision trees. Use race-condition only when concurrency is essential; use workflow-bypass for order/state gating; use api-authorization for object principal boundaries.
