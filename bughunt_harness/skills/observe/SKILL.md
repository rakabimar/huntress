name: observe
description: Build a map of the authorized attack surface before anything else — enumerate endpoints, tech fingerprints, parameters, and assets within scope. Use at the start of any recon or when a new lead appears.
maturity: stable
risk_class: R1
category: core
cwe: []
---

# Observe (Recon/Observer)

## Purpose
Answer the question *"what surface actually exists?"* — in-scope hosts, endpoints,
parameters, technologies, and behaviors — without yet asserting any vulnerability.
Observation is the first and most dangerous-to-skip step of the research loop.

## When to use
- At session start, to seed leads and hypotheses from the injected program brief.
- Whenever a lead is vague: "the login page" or "the API" is not a surface, it is
  a pointer toward one.
- Before choosing any technical skill — you must know what you are looking at first.

## Process
1. Read the program brief (`get_active_engagement`, `get_scope_summary`,
   `get_program_knowledge`).
2. Enumerate the *in-scope* surface only: routes, params, headers, cookies,
   auth flows, third-party integrations, API endpoints.
3. Fingerprint technologies defensively: headers, error pages, static assets,
   framework-specific cookie names. Record what you *inferred* versus what you
   *observed*.
4. Route every HTTP action through `send_authorized_http_request` (scope, policy,
   rate limits, and redaction are enforced there — never via raw curl).
5. Feed each concrete surface into `create_lead` and then a falsifiable hypothesis.

## Evidence
- An `observation` or `request_response` evidence record for each enumerated
  surface; redact secrets and PII before persisting.
- A `lead` (or updated lead) per non-trivial surface, so the axe is recorded,
  not just remembered in-context.

## False positives
- A page existing does not mean a vulnerability exists. Do not promote
  "interesting" into "vulnerable" without a hypothesis.
- Fingerprint mismatches from CDNs / WAFs / load balancers are common; confirm
  before attributing a technology.

## Stop conditions
- `scope_preflight` rejects the target — do not enumerate it.
- You reach the point of "scan everything" without a hypothesis — stop and
  hypothesize instead.

## Example
A brief lists `https://app.example.test` in scope. Use the broker to request
`GET /` and a few documented endpoints, capture the response data, record one
lead per distinct surface (login, API, upload, admin), and move to
`hypothesize`.