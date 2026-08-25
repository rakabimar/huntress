---
name: nosqli
description: Use when a target parses JSON or document-style input (Mongo-style) and you want to test NoSQL operator injection.
maturity: draft
risk_class: R2
category: injection
cwe: [943]
---

# NoSQL Injection

## Purpose
NoSQL injection occurs when an application builds a Mongo-style query from untrusted input without proper sanitization, letting an attacker inject operators such as `$ne`, `$gt`, or `$where`. Unlike SQL injection, there is no single query language or keyword syntax; the vulnerability is usually about manipulating operators in the JSON/BSON document the server passes to the database. It matters because auth bypass and mass data disclosure often require a single tampered parameter.

## When to use
- Endpoints that accept `application/json` bodies or URL-encoded params stored into Mongo-style queries.
- Login/reset flows that look up a user by username/password/email equality.
- APIs that echo database errors or return differing response bodies/lengths based on a filter result.
- Any parameter whose value is later embedded into a document query without type coercion.

## Process
1. Observe the endpoint and record a baseline: a valid request and its exact response size, status, and body. Note where the input maps to a lookup field.
2. Build a falsifiable hypothesis with `create_hypothesis`, e.g. "If I submit a JSON object instead of a string for `username`, then the query will match a broader document set, crossing the auth boundary."
3. Predict the observable for true and for false before sending anything.
4. Run only the minimal controlled experiment through `send_authorized_http_request`. Try a single operator such as `{"$ne": ""}` or `{"$gt": ""}` in place of one value; never fall back to raw curl or sqlmap.
5. Compare the response to the baseline. If it diverges (auth success, more records, different length), record the observation via `complete_research_test`; otherwise vary one field at a time, never a blind payload spray.
6. For boolean vs. error-based proof, prefer boolean first: a change in result when a predicate flips is less invasive than inducing an exception. Avoid `$where` with heavy JavaScript unless strictly necessary to demonstrate the boundary.
7. Persist the matched operator, request, and response as evidence, then stop.

## Evidence
- `request_response`: the redacted request with the injected operator and the full response that proves the effect.
- `observation`: a timestamped note on which field and operator produced divergence.
- `command_output`: any server log excerpt only if it was returned to you; redact tokens, cookies, and PII.

## False positives
- A `200` with an identical body is not injection; it is a benign parse. Diff the response against the baseline.
- Type errors stating "expected string, got object" show input validation working, not a vulnerability.
- Case-insensitive or substring matching can mimic `$ne` success; confirm the operator, not a coincidental match.
- An error you cannot reproduce with a single operator is noise, not a finding.

## Stop conditions
- `scope_preflight` rejects the target: stop immediately.
- The action needs R3/R4 or approval and none is recorded: stop.
- The only proof would be destructive or exfiltrate data at scale: stop and record a checkpoint instead.

## Example
On `http://example.test/login`, an unauthenticated login posts `{"username": "alice", "password": "x"}` and returns a `403`. Hypothesize that `username` is embedded unsanitized. Send one request through the broker with `"username": {"$ne": ""}` and the same password, predicting a `200` plus a session token if the predicate matches any user. If the response flips to success while the false-case control (`{"$ne": "admin"}` with the plain `password`) stays `403`, the boolean proof is demonstrated and recorded without touching real data.