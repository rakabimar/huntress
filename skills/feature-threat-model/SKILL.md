---
name: feature-threat-model
description: Use to model an unfamiliar product feature through actors, assets, trust boundaries, states, transitions, and invariants before selecting one to three vulnerability skills.
maturity: stable
risk_class: R0
category: core
cwe: []
canonical: true
primary_specialist: hypothesis-architect
related_skills: [business-logic, api-authorization, authentication, race-condition]
primary_triggers: [unfamiliar feature, multi-actor workflow, unclear attack surface]
secondary_triggers: [invite, approval, checkout, recovery, integration]
negative_triggers: [already isolated falsifiable vulnerability hypothesis]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Feature Threat Model

## Purpose
Turn a feature—not a vulnerability name—into a compact map of security boundaries and high-information abuse questions.

## When to use
Use before class-specific testing when a feature has multiple actors, objects, steps, channels, or source components. Skip when the current Lead already states one narrow falsifiable boundary.

## Process
1. Name the feature and authoritative outcome.
2. List real actors and principals, including services/jobs; do not invent roles.
3. List assets/capabilities and their owners/tenants.
4. Draw trust boundaries and identity/authorization establishment.
5. Enumerate states, allowed transitions, preconditions, postconditions, expiry/revocation, and alternate channels.
6. Write invariants: ownership, uniqueness, conservation, separation of duties, binding, monotonicity, and lifecycle invalidation.
7. Ask whether a step can be skipped/replayed/reordered, another actor can trigger it, stale state survives, value changes after approval, another representation bypasses a control, or concurrency changes the result.
8. Rank no more than three candidate skills by one experiment's information gain. Produce Leads/hypotheses, not payload lists.

For an organization invite, model admin/member/invitee/external user; invite token/organization/role/email identity; created/sent/accepted/expired/revoked; then test reuse, tenant/email binding, role mutation, and revocation through business-logic, api-authorization, authentication, or race-condition.

## Evidence
Evidence contract:
Persist the feature map, source/runtime observations supporting it, assumptions, candidate invariant, expected/refuting observations, and one next minimal test.

## False positives
A conceivable abuse without a reachable actor/transition, a product choice documented by the feature, or a violation with no protected asset/action is not a vulnerability Lead.

## Stop conditions
Stop expanding when one narrow experiment dominates, when scope/intent is ambiguous, or after three genuinely related skills. Do not load the entire skill library or test from the threat model without Scope/Policy gates.

## Tool selection
Prefer persistent Leads, hypotheses, and source/runtime context over live tools.
Use `policy_preflight` only after the model produces a single differentiating
experiment; execute an allowed HTTP experiment through the broker.
