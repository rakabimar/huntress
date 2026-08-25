---
name: rate-limit-bypass
description: Use when testing login brute-force, OTP/password-reset flows, or anti-automation controls for rate-limit and IP-rotation bypasses.
maturity: draft
risk_class: R1
category: crypto-config
cwe: [307]
---

# Rate-Limit And Anti-Automation Bypass

## Purpose
Rate limiting is a primary defense against credential brute-force (CWE-307). Applications that trust client-supplied headers (X-Forwarded-For, X-Real-IP) or reset counters on per-account or parameter changes can be tricked into granting unlimited guess attempts. A bypass that defeats login throttling turns a weak credential into full account takeover.

## When to use
- Login, OTP, magic-link, and password-reset endpoints that throttle by IP address.
- Requests pass through reverse proxies or CDNs that may honor forwarded-for headers.
- Flows that reset or scope the counter per-account, per-session, or per-parameter (e.g. a new email address resets the limit).

## Process
1. Confirm the endpoint is in scope with `scope_preflight` and that the action is allowed by `policy_preflight`.
2. Establish a baseline: record the normal rate-limit response (status code, body, headers) for N failed attempts.
3. State a falsifiable hypothesis with `create_hypothesis`, e.g. "If I vary the X-Forwarded-For header per attempt, then the counter resets and the endpoint never returns the throttle response."
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only: a single header variant or parameter tweak per test, keeping all other fields constant. Never use raw curl/nmap/sqlmap.
5. Compare against the predicted observation and record it via `complete_research_test` with `create_evidence`.
6. Test one bypass vector at a time: header rotation, account-scoped reset, or a new parameter value. Prove the boundary crossed before expanding attempt counts.

## Evidence
- `request_response` pairs showing the throttle response before and after the controlled change.
- `observation` records of the counter-reset behavior (e.g. identical response after repeated attempts with rotated headers).
- `command_output` only for local fixture analysis; redact any tokens, session values, and PII.

## False positives
- A proxy that strips or overwrites X-Forwarded-For, so the header has no effect on throttling.
- Throttling that silently drops or delays requests rather than returning an explicit 429/retry-after.
- A per-account lockout that still applies regardless of source IP (the IP is not the reset key).

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` rejects the action — stop.
- The test requires R3/R4 actions or destructive writes and no approval is recorded — stop.
- Proving the bypass would require sustained high-volume attempts beyond what demonstrates the effect — stop at the minimal repro.

## Example
A login form on http://login.example.test returns 429 after 5 failures. Hypothesis: rotating X-Forwarded-For per attempt defeats the counter. Test 1 sends 5 failures with a fixed header (baseline 429). Test 2 sends 6 failures with a fresh X-Forwarded-For on each, predicting no 429. If the 6th attempt still returns 401 instead of 429, the bypass is demonstrated, recorded as request_response evidence.