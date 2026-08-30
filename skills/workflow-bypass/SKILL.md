---
name: workflow-bypass
description: Use when a feature has a multi-step flow, state transition, approval chain, or wizard that may be skipped, replayed, or jumped to its terminal state.
maturity: stable
risk_class: R2
category: business-logic
cwe: [841]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [business-logic, feature-threat-model, race-condition, api-authorization]
primary_triggers: [multi-step flow, state transition, approval chain, skipped step]
secondary_triggers: [replay, stale state, alternate endpoint, out-of-order action]
negative_triggers: [cosmetic step, idempotent replay, server revalidates prerequisites]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Workflow Bypass

## Purpose
A workflow is any multi-step process whose correctness depends on steps being completed in order and on approvals being recorded before the terminal state. When the server trusts the client to fetch steps honestly instead of re-validating prior state, an attacker can skip verification steps, re-submit completed steps, or navigate directly to the final action. This yields unauthorized state transitions — completing onboarding without verification, approving your own request, or reaching checkout without payment.

## When to use
- Endpoints that accept a `step`, `stage`, `phase`, or `next` parameter and trust a client-supplied value.
- Wizards or multi-page forms where each step POSTs independently to a step endpoint.
- Approval flows (multi-party sign-off, manager review) exposed as per-record action endpoints.
- Features whose final state is reachable by replaying or reordering known request IDs.

## Process
1. Map the workflow: enumerate every step endpoint and the terminal action. Note which steps carry validation weight (KYC, email/phone verification, payment, approval).
2. Shape a falsifiable hypothesis with `create_hypothesis`: "If I POST the terminal step directly as account A without completing step 2, then the server acts on it, crossing the verification boundary." Record the refuting observation (a redirect back to step 2, or a missing-state error).
3. Run the MINIMAL experiment through `send_authorized_http_request` — never raw curl/nmap/sqlmap. Send one controlled request: navigate in one hop to the terminal step, or replay an earlier step ID.
4. Test one variable at a time: skip forward, replay a completed step, jump backward to an already-signed state, and re-order. Compare each against your prediction.
5. Record every observation via `complete_research_test` with a supports/rejects/inconclusive result, and persist `create_evidence` for the durable request/response pairs.
6. If the server acts on the bypassed transition, promote a candidate finding; if it re-validates prior state, reject the hypothesis and move on.

## Evidence
- `request_response`: the raw broker-captured request that skipped a step and the resulting state change — enough for a third party to reproduce.
- `observation`: the before/after state (e.g. account status before and after direct terminal navigation).
- `command_output`: any server log or response header showing the transition succeeded. Redact secrets and PII in all previews.

## False positives
- A missing-state error or redirect back to the skipped step means the server re-validates prior state — not a bypass.
- A step that is cosmetic (no security-relevant state changes) being skipped is a UX gap, not a workflow bypass.
- Replaying an idempotent action that returns identical results is not a transition; confirm a real state change before claiming impact.
- An endpoint reachable only with a higher privilege may be authorization, not workflow logic — name the workflow boundary it crosses.

## Stop conditions
- `scope_preflight` rejects the target or endpoint — stop.
- Demonstrating the jump requires R3/R4 action or an approval that is not recorded — stop and request approval.
- Proof would require a destructive write (deleting, overwriting real records, or moving money) — stop; seek the least-invasive observation that still proves the transition.
- You cannot tell whether a transition is authorized — resolve to no and stop.

## Example
A signup on localhost requires email verification at step 2 before a "create account" terminal step. Hypothesis: POSTing `POST /signup?step=final&verified=1` directly, without having received a token at step 2, creates an active account. The MINIMAL test sends that single request through the broker. If the response shows the account created with a confirmed-email flag, the boundary is crossed; evidence records the request and the resulting account state. A redirect back to `/signup?step=2` refutes the hypothesis.
