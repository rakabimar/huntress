---
name: open-redirect
description: Use when a redirect, return, next, or callback parameter controls where the app sends a user
maturity: draft
risk_class: R1
category: web
cwe: [601]
---

# Open Redirect

## Purpose
An open redirect occurs when an application trusts a user-controlled parameter (commonly `redirect`, `return`, `next`, `return_url`, `callback`) and uses it to build an HTTP redirect without validating the destination. On its own it is usually low-to-medium severity, but it becomes valuable when chained: it can deliver phishing through a trusted-looking domain, or leak OAuth authorization codes when a redirect ends up in a token-grant callback.

## When to use
- Login, logout, or signup flows that accept a `next`/`return`/`redirect` parameter to send the user onward.
- OAuth or SSO endpoints with a `redirect_uri` or `callback` parameter.
- Anywhere an HTTP 3xx Location is derived from query-string or path input.

## Process
1. Find an endpoint whose Location header reflects a parameter you control. Confirm with a request to a benign in-scope path first.
2. Write a falsifiable hypothesis with `create_hypothesis`: "If I set `redirect_url` to an absolute URL, the app will return a 302 whose Location is that URL."
3. Predict both outcomes: a 302 to your controlled value supports the hypothesis; a fixed Location (or the value stripped) refutes it.
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only (never raw curl/nmap/sqlmap). Use a single request per candidate value.
5. If the value is restricted, test one allow-list bypass at a time: a URL whose prefix matches the allow-list, percent/hex-encoded characters, or extra slashes that parsers normalize differently.
6. Record every observation with `complete_research_test` and capture the durable request/response with `create_evidence`.
7. Before promoting to a candidate finding, show WHY the redirect matters: identify the downstream consumer (phish delivery target, OAuth `redirect_uri` that would capture an authorization code).

## Evidence
- `request_response`: the full redacted request with the malicious parameter and the resulting 3xx plus Location header, enough to reproduce.
- `observation`: the rendered or captured note that the destination changed in the way predicted.
- Redact any cookie, token, or PII in Location or body before storing.

## False positives
- The app echoes your URL into an HTML link or meta-refresh but the server never issues a 3xx to it — that is reflective output, not an open redirect.
- The redirect is hard-coded to a fixed allow-list and every bypass attempt normalizes back to a whitelisted host.
- A redirect to a same-origin path you supplied, where the host portion is ignored or forced to the app's own domain.
- Redirection that requires an existing authenticated session and cannot be triggered by the attacker merely delivering a link.

## Stop conditions
- `scope_preflight` rejects the target — stop, never test out of scope.
- The proof would require R3/R4 actions (OAuth code capture against a real downstream service, redirecting another user) and no human approval is recorded — stop.
- The only way to demonstrate impact is destructive or involves sending links to real users — stop and record the candidate as inconclusive.

## Example
On `example.test`, the endpoint `https://example.test/logout?next=https://evil.invalid` returns `302 Location: https://evil.invalid`. The hypothesis is supported: the app issues an external redirect based on `next`. Baseline: `next=/home` returns `302 Location: /home`, confirming the parameter is the source. Then test a bypass only if a validator exists — e.g. `next=https://example.test.evil.invalid` when the app is expected to allow-list its own host, to see whether prefix matching is used and can be confused.