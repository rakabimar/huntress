---
name: business-logic
description: Use when a feature enforces authorization or a workflow through client-driven steps, order, quantities, or parameters instead of server-side state machines.
maturity: draft
risk_class: R2
category: business-logic
cwe: [840]
---

# Business Logic Flaws

## Purpose
Business logic flaws break a feature's intended state machine: steps skipped, sequences replayed out of order, quantities set to impossible values, or parameters tampered between requests. The server trusts client-supplied flow control rather than enforcing transitions itself. These are high-value because they bypass authorization and financial controls without touching the code that is normally hardened.

## When to use
- Multi-step workflows (checkout, onboarding, password reset, approvals) with a visible step/state parameter.
- Endpoints that accept quantities, prices, discounts, roles, or account identifiers from the client.
- Features that gate an action on an earlier step that is not re-verified server-side.
- Anywhere the intended flow can be drawn as a state diagram with transitions a client controls.

## Process
1. Map the intended state machine first: list states, legal transitions, and which are server-enforced versus client-assumed. Draw it before touching the API.
2. Write a falsifiable hypothesis (`create_hypothesis`): "If I send request X with parameter Y changed, the server will transition to state Z without the prerequisite, crossing boundary W."
3. Predict the observation if true (wrong state reached, negative total accepted) and the observation that refutes it (rejected, unchanged).
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — never raw curl/nmap/sqlmap. Try one mutation at a time (skip a step, invert a quantity, swap an ID, replay an order).
5. Record the result with `complete_research_test` and persist durable proof with `create_evidence`. Reject the hypothesis when the app refuses; do not re-run for the same prediction.
6. Prefer least-invasive proof: a single out-of-sequence transition with one value change beats bulk tampering. Keep every mutation confined to the tested flow.

## Evidence
- `request_response`: full redacted request and response pairs showing the tampered parameter and the unexpected state reached.
- `observation`: the modeled state table with the illegal transition marked and what the server returned.
- `command_output`: only if a harness CLI produced the artifact; redact any secrets/PII before storing.

## False positives
- An endpoint accepting weird input that returns 200 but has no downstream effect is not a flaw; demonstrate the boundary actually crossed (state changed, money moved).
- A field the client can edit but the server re-validates server-side is not tamperable; look for the server recomputing the value.
- A workflow that tolerates out-of-order steps by design (idempotent, self-service) is intended behavior, not logic abuse.
- Rate or validation errors that merely look odd are data; only a supported, reproduced hypothesis counts.

## Stop conditions
- `scope_preflight` rejects the target or endpoint: stop immediately.
- The proof would require R3/R4 impact (destructive writes, mass data change, denial of service) and no approval is recorded: stop.
- The only demonstration available is destructive or irreversible: stop and note the alternative.
- You cannot tell whether a transition is authorized: resolve to no and stop.

## Example
On `https://shop.example.test`, checkout has three steps: review (`state=1`), payment (`state=2`), confirm (`state=3`). The confirm endpoint accepts `state` from the client. Hypothesis: submitting `POST /order/confirm` with `state=3` directly, skipping payment, marks the order paid. Send that single request through the broker from a test account, observe whether the order transitions to `paid` without a payment record, and record the request/response pair plus the state table as evidence.