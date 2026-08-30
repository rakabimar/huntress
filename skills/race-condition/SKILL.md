---
name: race-condition
description: Use when a resource can be consumed, created, transferred, or credited more than once through concurrent requests, or when rate limits and unique constraints look bypassable by timing.
maturity: stable
risk_class: R2
category: business-logic
cwe: [362]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [business-logic, payment-logic, workflow-bypass]
primary_triggers: [concurrent state mutation, TOCTOU, one-time consumption, read-modify-write]
secondary_triggers: [quota, balance, coupon, uniqueness, idempotency]
negative_triggers: [sequential replay, latency without duplicate state effect, availability-only errors]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Race Conditions / TOCTOU

## Purpose
A race condition occurs when an operation's check (validating balance, uniqueness, quota) and its use (deducting, inserting, granting) are separated by a gap that concurrent requests can both pass through. For bug hunting, this means double-spending credits, duplicate account/referral creation, exceeding rate limits, or TOCTOU on file handling. It matters because the impact is business-logic: one request succeeds, but several slip through before state converges.

## When to use
- Endpoints that check a resource before consuming it: wallet balance, coupon/promo redemption, invite limits, stock quantity.
- Creation flows with uniqueness constraints: signup, referral codes, one-time grants, username/email uniqueness.
- Rate-limiting or throttle logic enforced in-app rather than by infrastructure, or counters read-then-write.
- File handling, session or config swaps, and anything with a visible check-then-act ordering.

## Process
1. Map the read-modify-write ordering from the observed request/response pair, identifying the shared mutable state (balance row, counter, unique index).
2. State a falsifiable hypothesis with `create_hypothesis`: "If I send N concurrent redeem requests for the same coupon, more than one will succeed, crossing the one-time-use boundary."
3. Predict the observation that refutes it (exactly one success) versus supports it (two or more successes), and record both on a planned `create_research_test`.
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — never raw curl/sqlmap. Fire the smallest number of parallel requests (two, where one proves the flaw) with identical payloads.
5. Repeat to check determinism: run the minimal burst a few times at controlled intervals, since races are probabilistic. A single success order is not proof; a reproducible double-spend is.
6. Record the observation and result via `complete_research_test`, then persist `create_evidence` for each distinct request/response that shows the boundary crossed.

## Evidence
- `request_response`: the redacted parallel requests and their distinct successful responses (e.g., two `200` redemptions for one coupon).
- `observation`: the concurrency setup — timing, request count, identical inputs — needed to reproduce the interleaving.
- `command_output`: server logs or counter snapshots showing state diverging from expected. Redact all secrets, tokens, and PII.

## False positives
- Two successes where the application intentionally allows multiple claims (e.g., a coupon with remaining uses) — confirm the intended constraint from the response or docs before calling it.
- Client-side dedup or a browser guard that "prevents" double-click but is absent server-side — the client check alone is not the vulnerability; demonstrate it bypassed via direct request.
- Latency-visible but not state-impacting: concurrent writes that both fail or both no-op carry no boundary crossing, so do not report them.
- Concurrency-only errors (deadlock, 500 under load) without an unauthorized state change — that is availability, not this business-logic weakness.

## Stop conditions
- `scope_preflight` on the target rejects — stop immediately.
- Proof would require R3/R4 action or mass parallel traffic, and no approval is recorded — stop; a two-request proof suffices.
- The clearest demonstration would be destructive or would exhaust a shared resource at scale — switch to the least-invasive two-request form or stop.
- You cannot distinguish "intended concurrent behavior" from "crossed boundary" — treat uncertainty as no.

## Example
On `https://shop.example.test` the `/api/redeem` endpoint reads a coupon's `used` flag and then marks it used. Send two identical redeems for one coupon through the broker in parallel. If the flag update is not atomic, both return success and the coupon is spent twice. Refuting observation: the second request returns `409` already-used. Record both responses as evidence and note the interleaving gap between the balance read and the balance write.
