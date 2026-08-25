---
name: ldap-injection
description: Use when testing LDAP-based authentication, directory search, or query builders where filter metacharacters may alter the query logic
maturity: draft
risk_class: R2
category: injection
cwe: [90]
---

# LDAP Injection

## Purpose
LDAP injection occurs when user input is concatenated into an LDAP filter without neutralizing
the metacharacters `* ( ) \` and null. An attacker can alter the filter's boolean structure,
often turning an authentication check into a tautology or widening a directory search. For bug
hunting it matters because auth bypass and information disclosure are frequent, highly-valued
outcomes on directory-integrated apps.

## When to use
- Login forms or password-reset flows that authenticate against AD/LDAP rather than a local DB.
- Search endpoints (user/group/employee lookup) that accept free-text and return directory objects.
- Inputs that flow into attributes like `userPrincipalName`, `sAMAccountName`, or `mail` filters.
- Errors that leak LDAP syntax ("Bad search filter", "Invalid DN") revealing raw filter structure.

## Process
1. Observe the endpoint and map a single input into a filter context. Note where the value sits
   inside the query (attribute value vs. DN vs. filter itself).
2. Record a falsifiable hypothesis with `create_hypothesis`: "If I submit `<input>` as account A,
   then the filter changes in way Y, which crosses boundary Z."
3. Predict the observable if true (e.g. login succeeds, extra records returned) and what would
   refute it (same error/behavior as a normal bad input).
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — never raw
   curl/nmap/sqlmap. Send one metacharacter at a time (`*`, then `(`), then a balanced closure
   such as `)(|(cn=*)` and note the response delta.
5. Escalate only after a neutral baseline fails identically to a valid-but-absent value. Record
   each observation with `complete_research_test` and persist artifacts with `create_evidence`.
6. Prefer least-invasive proof: demonstrate altered filter logic via an anomaly (error change,
   one extra record, bypass of a single check) rather than mass enumeration.

## Evidence
- `request_response`: full redacted request/response pairs showing the injected metacharacters and
  the changed behavior, reproducible by a third party. Redact cookies, tokens, and PII.
- `observation`: side-by-side of baseline vs. injected responses (status codes, error text,
  record counts) captured without secrets.
- `command_output`: any harness/broker output showing the differential result; never store raw
  credential values.

## False positives
- Time-based or length differences caused by network jitter, not filter logic — re-run with a
  control input to confirm the delta is deterministic.
- Input is HTML/JavaScript-escaped on output, not filter-escaped; reflected metacharacters in the
  page prove only lack of output encoding, not an injectable filter.
- A generic "invalid credentials" for both `*` and gorrightous garbage: if the error is identical,
  the input may be compared as a literal value, not parsed as filter syntax.
- Vendor search APIs that sanitize the filter server-side but behave loosely; confirm the backend
  actually parses your syntax before claiming injection.

## Stop conditions
- `scope_preflight` rejects the target or input — stop immediately, the engine is authoritative.
- Any action requires R3/R4 or high-risk validation and no `approved` record exists — stop and
  request approval.
- Proof would be destructive (dumping the directory at scale, locking accounts via bad DN spam,
  or any denial of service) — stop and reformulate to a single read-only mutation.
- You cannot distinguish intended behavior from a genuine filter manipulation — record inconclusive
  and stop rather than asserting a finding.

## Example
On `https://login.example.test`, a portal authenticates against LDAP by building the filter
`(&(uid=<user>)(password=<pass>))`. A tester hypothesizes the `uid` field is concatenated without
escaping and predicts `uid=*)(|(uid=*` will change the boolean structure. Using
`send_authorized_http_request`, the tester first sends a control (`uid=nonexistent`) and captures a
404/denied baseline, then sends `uid=*)(|(uid=*` and observes an altered response — a successful
login or a different error indicating the filter parsed differently. The delta is recorded as
`request_response` evidence; no account exists on `example.test` beyond test fixtures, and no
directory contents are enumerated.