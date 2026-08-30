---
name: mass-assignment
description: Use when endpoints bind client-supplied fields (role, is_admin, balance) or accept nested JSON/array parameters without an allowlist.
maturity: stable
risk_class: R2
category: business-logic
cwe: [915]
canonical: true
primary_specialist: api-authz-specialist
related_skills: [api-authorization, access-control, business-logic, http-parameter-pollution]
primary_triggers: [object binding, unexpected writable field, DTO serializer input]
secondary_triggers: [nested update, protected property, owner tenant role status]
negative_triggers: [field echoed but ignored, server recomputation, harmless extension field]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Mass Assignment

## Purpose
Mass assignment happens when an endpoint binds client-supplied object properties to
a domain model without a permitted-field boundary, allowing protected fields such as
role, owner, tenant, approval state, or balance to change. Route duplicate-key and
proxy/framework parsing disagreement to `http-parameter-pollution`.

## When to use
- Endpoints accept full objects for create/update (PATCH/PUT/POST) rather than named fields.
- Responses echo back fields that were never submitted, suggesting reflection/binding.
- Nested DTOs, serializers, ORM models, or merge helpers expose more fields than the feature intends.
- Admin-adjacent or payment-adjacent endpoints where role, status, or balance fields exist.

## Process
1. Confirm the target and action pass `scope_preflight` / `policy_preflight`; stop if not.
2. Record a falsifiable `create_hypothesis`, e.g. "If I PATCH the account object adding
   `role: admin`, the server binds it and elevates my account."
3. Predict the observable if true (privilege/state change) and what would refute it
   (field ignored, 4xx response, or unchanged state).
4. Run the MINIMAL controlled test through `send_authorized_http_request` only — never raw
   curl/sqlmap. Send one protected field on a synthetic object.
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
- A documented writable extension/metadata property is not a protected model boundary.

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
