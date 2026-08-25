---
name: privilege-escalation
description: Use when testing access control — horizontal/vertical privilege escalation, missing function-level access control, or role/tenant confusion
maturity: draft
risk_class: R2
category: authnz
cwe: [269]
---

# Privilege Escalation

## Purpose
Improper access control lets one identity read or mutate resources it should not: a low-privilege user invoking an admin function (vertical), or a user reading another user's objects (horizontal). Function-level authorization is often missing because the check is trusted to the UI or to the client. Because the proof is usually a single read, this is one of the cheapest high-impact classes to demonstrate read-only before any write.

## When to use
- Endpoints keyed by IDs (UUIDs, numeric `id`, `userId`, `accountId`) with no visible ownership check on the response.
- Admin-only features (role management, user list, exports, config) reachable by guessing URL paths or HTTP verbs.
- Multi-tenant or multi-role apps where role/tenant is implied by a header, cookie, or JWT claim you can alter.
- GET endpoints returning objects when the handler assumes the client filtered them.

## Process
1. Enumerate the surface read-only: list routes, parameter names, and roles from the brief and observed traffic.
2. Build a falsifiable hypothesis with `create_hypothesis`: "If I replay user A's request as identity B and change only the object ID, the response contains A's object, crossing the ownership boundary."
3. Predict the observable: the exact field or status that proves the breach (A's data returned, or a `200` on an admin-only route).
4. Run the MINIMAL experiment through `send_authorized_http_request` only — one request, one variable changed (identity or object ID); never raw curl/nmap/sqlmap.
5. `complete_research_test` with the observation; compare to the prediction and reject if results are ambiguous.
6. Prove read-only first (list/GET the admin or foreign resource) before considering any write. Record `create_evidence` for every claim that matters.
7. Only after a read boundary is confirmed, propose — not perform — a write as a follow-up hypothesis for a later approval gate.

## Evidence
- `request_response`: redacted request plus response showing cross-identity data or privileged action result.
- `observation`: side-by-side note that identity B received identity A's object.
- `command_output`: only for broker CLI captures; never raw shell tool output.
- Redact tokens, cookies, PII, and any secret leaked into response bodies.

## False positives
- IDOR that returns only non-sensitive, public-by-design data (profile display names) — not a boundary crossing.
- An endpoint that refuses with `403`/`404`: indistinguishable from not existing; treat absence of error as the signal.
- A self-service "manage my own account" screen that is scoped correctly — confirm the tenant filter, not the URL.
- Same-role behavior differences driven by legitimate per-user configuration, not role logic.

## Stop conditions
- `scope_preflight` rejects the target or route — stop immediately, do not probe.
- The proof would require an R3 write or any destructive mutation with no recorded approval — stop and request approval.
- Credentials or tokens begin appearing in responses — stop and redact before persisting.
- You cannot distinguish "admin successfully read" from "error swallowed" — stop and re-hypothesize rather than claim success.

## Example
On `example.test`, a team app exposes `GET /api/v1/report/<id>`. Logged in as user `bob`, the handler trusts the client to constrain `id`. Hypothesis: re-issuing `GET /api/v1/report/42` as `bob` returns the report owned by user `alice`, which `bob` cannot see in his own list. Predict: response body contains `"owner":"alice"`. Test: one broker request with only `bob`'s session and `id=42`. Observation: body contains `"owner":"alice"`. Read-only proof confirmed; any write is deferred to an approval-gated follow-up.