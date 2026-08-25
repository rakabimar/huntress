---
name: api-enumeration
description: Use when enumerating API surface (OpenAPI/Swagger, GraphQL introspection, versioned or undocumented endpoints) and probing API object graphs for BOLA/IDOR.
maturity: draft
risk_class: R1
category: recon
cwe: [200]
---

# API Enumeration and Object Graph Abuse

## Purpose
APIs expose endpoints, schemas, and object relationships that the HTML UI never surfaces. OpenAPI/Swagger specs, GraphQL introspection, and versioned routes can leak undocumented parameters and internal IDs. When authorization checks are missing on nested object routes, enumerated IDs become direct object references an attacker can traverse across tenants (BOLA/IDOR). This skill drives read-only enumeration and hypothesis-driven authorization checks.

## When to use
- The application serves /api, /graphql, /v1, /v2, or a SPA that calls JSON endpoints.
- OpenAPI or Swagger JSON, a GraphQL schema, or API docs are reachable.
- Responses contain numeric or UUID object IDs that reappear in later requests.
- Endpoints accept user-supplied IDs via query, path, or nested body.

## Process
1. Confirm scope first: run scope_preflight on the target before any request. A rejection stops work.
2. Form a falsifiable hypothesis with create_hypothesis, e.g. "GET /api/v1/users/{id} returns user 2's record when I supply id=2, crossing the tenant boundary."
3. Discover surface through the broker using send_authorized_http_request only. Fetch /openapi.json, /swagger.json, /graphql (introspection query), and common versioned prefixes. Never shell out to curl or scanners.
4. Predict both outcomes before testing: what you will observe if true versus what refutes it. Record them via create_research_test.
5. Run the minimal controlled experiment: one request, one changed identifier. Prefer read-only GETs and compare one adjacent ID against your own.
6. Record the observation and result via complete_research_test; attach redacted request_response evidence with create_evidence.

## Evidence
- request_response: full redacted request and response proving an undocumented endpoint or a cross-ID read.
- observation: the discovered schema or endpoint list, with IDs and secrets redacted.
- command_output: only for deterministic local parsing, never for in-situ scanning.
- Redact tokens, cookies, PII, and any data belonging to other users.

## False positives
- A 404 for one ID but 200 for another may be server-side filtering, not IDOR; confirm with a second distinct ID.
- GraphQL introspection returning fields does not itself prove access; authorization is enforced per query, not per schema.
- Publicly documented endpoints returning shared data are intended behavior, not enumeration.
- Verbose errors naming a field are not authorization gaps until another user's data is actually returned.

## Stop conditions
- scope_preflight or policy_preflight rejects the target or action: stop and do not test.
- The proof requires R3/R4 (destructive write, mass extraction) with no approval recorded: stop.
- Any step would enumerate at scale or dump bulk records: stop and seek a narrower read-only proof.
- You cannot tell whether the endpoint is in scope: stop.

## Example
A test app at https://api.example.test serves /swagger.json listing /api/v1/invoices/{id}. Logged in as user 1001, a GET to /api/v1/invoices/1001 returns your own invoice. Hypothesis: "If I GET /api/v1/invoices/1002, then I will receive invoice 1002, another user's record." Predict: a server-side authorization check returns 403 and refutes. You run the single read-only request through the broker, observe a 200 with invoice 1002, and record request_response evidence showing the cross-user read. Then stop and hand the supported hypothesis toward a candidate finding.