---
name: mass-assignment
description: Use when endpoints bind client-supplied fields (role, is_admin, balance) or accept nested JSON/array parameters without an allowlist.
maturity: draft
risk_class: R2
category: business-logic
cwe: [915]
---

# Mass Assignment And Parameter Pollution

## Purpose
Mass assignment happens when an endpoint blindly binds client-supplied fields onto
an object, so a field the developer never intended to expose (role, is_admin, balance,
owner_id) can be set by the caller. HTTP parameter pollution is its cousin: duplicated
or conflicting parameters in queries, form bodies, or JSON arrays get merged in
unpredictable ways. Both are privilege/binding bugs that turn harmless payloads into
authorization or integrity failures.

## When to use
- Endpoints accept full objects for create/update (PATCH/PUT/POST) rather than named fields.
- Responses echo back fields that were never submitted, suggesting reflection/binding.
- Nested JSON or arrays are accepted, and a numeric index or repeated key could alter merge.
- Admin-adjacent or payment-adjacent endpoints where role, status, or balance fields exist.

## Process
1. Confirm the target and action pass `scope_preflight` / `policy_preflight`; stop if not.
2. Record a falsifiable `create_hypothesis`, e.g. "If I PATCH the account object adding
   `role: admin`, the server binds it and elevates my account."
3. Predict the observable if true (privilege/state change) and what would refute it
   (field ignored, 4xx response, or unchanged state).
4. Run the MINIMAL controlled test through `send_authorized_http_request` only — never raw
   curl/sqlmap. Send one extra field, or one duplicated/first-vs-last parameter pair.
5. Compare the response and state; `complete_research_test` with the observation and a
   supports/rejects/inconclusive result.
6. Capture `create_evidence` (request_response) for the one field that mattered; redact
   tokens, cookies, and PII before persisting. Prefer read-only proof of binding over writes.

## Evidence
- `request_response`: the exact request adding an unexpected field and the response proving
  it was bound (echoed value, changed role/state) or ignored.
- `observation`: a note on the before/after state (e.g. account object diff).
- Redact Authorization headers, cookies, and any account identifiers.

## False positives
- A field echoed back in the response is not proof it changed state; only a state change matters.
- Extra fields being silently ignored means no mass assignment — confirm by reading state, not response text.
- "Role" set but never consulted by any authorization check is not a privilege escalation.
- Duplicate parameters returning the later value may be intended; verify the sensitive consumer.

## Stop conditions
- `scope_preflight` or `policy_preflight` rejects the target or action — stop immediately.
- The proof would require R3/R4 action or a destructive write and no approval is recorded.
- Demonstrating it needs mass data exfiltration or denial of service — do not proceed.
- The target is not in the active program's scope — never test it.

## Example
On `example.test`, a user profile endpoint `PUT /api/users/me` accepts a JSON object.
The account shows `role: user`. Hypothesis: adding `"role":"admin"` to the same JSON body
binds it. Send the minimal request via `send_authorized_http_request` with the body
`{"email":"u@example.test","role":"admin"}` and observe the response. If the account now
reports `role: admin` and an admin-only endpoint responds, the hypothesis is supported;
record the request_response and promote toward a candidate finding. If the field is ignored
and the account still reads `role: user`, reject the hypothesis and stop.