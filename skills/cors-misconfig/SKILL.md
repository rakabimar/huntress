---
name: cors-misconfig
description: Use when testing cross-origin endpoints that reflect Origin headers or set Access-Control-Allow-Origin, or when a client-side feature reads cross-origin data.
maturity: draft
risk_class: R1
category: client-side
cwe: [942]
---

# Cross-Origin Resource Sharing Misconfiguration

## Purpose
CORS lets a server relax the browser's same-origin policy so that specific origins may read its responses. A misconfigured policy (reflecting any Origin, accepting the null origin, or wildcarding subdomains) can let an attacker's page read a victim's authenticated data. For bug hunting the key question is not whether CORS looks loose, but whether the target actually returns credentials paired with an attacker-controllable origin.

## When to use
- Endpoints that return Access-Control-Allow-Origin and set Access-Control-Allow-Credentials: true
- APIs that read sensitive data (profile, account, secrets) and echo the request Origin or apply subdomain wildcards
- Endpoints that rely on cookies for session/auth rather than header-only bearer tokens
- Any client-side feature that fetches cross-origin data and assumes the browser protects it

## Process
1. Build a falsifiable hypothesis with create_hypothesis, e.g. "If I send Origin: https://evil.test with an authenticated request, the response reflects evil.test in Access-Control-Allow-Origin and returns Access-Control-Allow-Credentials: true, so an attacker origin could read the response."
2. Run the minimal controlled experiment through send_authorized_http_request only (never raw curl/nmap/sqlmap), varying only the Origin value: an unrelated origin, a sibling subdomain, and the literal string "null".
3. Record each result with complete_research_test and create_evidence; note exactly which origin values are reflected and whether credentials are permitted.
4. Prove exploitability with a single read from an attacker-origin page — one minimal demonstration, not automated exfiltration — then promote a supported hypothesis toward a candidate finding.

## Evidence
- request_response: full redacted request (Origin header) and response headers (Access-Control-Allow-Origin, Access-Control-Allow-Credentials) proving reflection and credential leakage
- observation: notes on which origin values are reflected versus denied, and whether credentials appear with them
- Redact cookies, tokens, and PII from stored previews; never persist session material.

## False positives
- ACAO reflects the Origin but Access-Control-Allow-Credentials is false or absent, so the browser blocks credentialed reads
- Wildcard `*` combined with credentials, which browsers reject outright and is therefore not directly exploitable
- A reflected Origin on a public, unauthenticated endpoint with no sensitive data; this is a config bug, not a vulnerability
- Loose-looking reflection with no credentialed endpoint worth stealing; confirm a real data boundary is crossed before treating it as exploitable

## Stop conditions
- scope_preflight rejects the target; stop.
- Proving the cross-origin read would require R3/R4 action and no approval is recorded; stop.
- Demonstrating exploitation would require real data exfiltration at scale; stop after a single minimal proof instead.

## Example
An API at api.example.test reflects any Origin and returns Access-Control-Allow-Credentials: true while authenticating via a session cookie. A request with Origin: https://evil.test returns Access-Control-Allow-Origin: https://evil.test together with the credential flag, so a page on evil.test can read a logged-in user's account data. Confirm with a small localhost page that performs the fetch and reads the JSON, then stop, without pulling more than one record.