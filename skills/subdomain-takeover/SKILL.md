---
name: subdomain-takeover
description: Use when a subdomain's DNS resolves to a dangling or unclaimed cloud/SaaS service (CNAME, NXDOMAIN, or provider error page) and you want to prove takeover risk without claiming the resource.
maturity: draft
risk_class: R1
category: infra
cwe: [350]
---

# Subdomain Takeover

## Purpose
A subdomain takeover happens when DNS points at a cloud/SaaS resource (a CNAME to S3, GitHub Pages, Heroku, etc.) that no longer exists, so the provider serves a "not found" page while the canonical name still resolves. An attacker who claims the orphaned resource serves content under the victim's trusted origin. For bug hunters, the goal is to fingerprint the provider and demonstrate the dangling pointer without ever claiming it.

## When to use
- A subdomain returns NXDOMAIN, SERVFAIL, or a provider-specific "does not exist" page.
- A `dig`/`host` CNAME record points to a known cloud or SaaS tenant namespace (e.g. `*.s3.amazonaws.com`, `*.github.io`).
- You can reach a host via the broker but it shows a "no such bucket/app" signature.
- A scope item is an application host or wildcard domain under review.

## Process
1. Confirm the target is in scope with `scope_preflight(target)`; halt if it is not.
2. Form a falsifiable hypothesis: "If I resolve `<sub>.example.test` via the broker, the CNAME will point to `<provider>` and the response will carry the provider's unclaimed signature, crossing the authority boundary of that hostname."
3. Record it with `create_hypothesis`, predicting the exact observable if true and what would refute it.
4. Run the minimal controlled probe through `send_authorized_http_request` only (never raw curl/dig/nmap). Request a benign path and capture headers + body.
5. Fingerprint the provider from response headers and body text (`x-amz-`, `github.com`, `heroku`, `azurewebsites`), not from prior expectations.
6. Record the observation and result via `complete_research_test`; mark the hypothesis supported only if the prediction matched.
7. Store proof with `create_evidence` (request_response) showing the canonical name and the unclaimed signature. Stop there — do not register the resource.

## Evidence
- `request_response`: full redacted request/response proving the CNAME target and the provider's unclaimed-service signature.
- `observation`: the DNS resolution chain and provider fingerprint noted in prose.
- `command_output`: a `CNAME` lookup result, if captured through the broker.
- Redact any credentials, tokens, and PII before storing.

## False positives
- A host that resolves but returns the provider's generic 404 for a *registered* service you do not own — the namespace is claimed, so takeover is not possible.
- A CNAME to a provider that auto-denies new registration (or is on your own account) — confirm the namespace is genuinely claimable.
- CDN / wildcard answer pages: the "not found" page may be the platform default, not an orphan. Confirm the canonical name is within a tenant-controllable namespace before reporting.

## Stop conditions
- `scope_preflight` rejects the target — stop immediately.
- Confirming the claim would require registering the resource (R3 action) with no recorded approval — stop.
- Proof would be destructive or would modify the target/provider — stop.
- You cannot distinguish "claimable" from "already claimed" without action — stop and record inconclusive.

## Example
`vpn.example.test` resolves via CNAME to `vpn.example.test.s3.amazonaws.com`, whose response body reads "NoSuchBucket" with `x-amz-request-id`. Scenario: create_hypothesis predicts the exact bucket-namespace signature; `send_authorized_http_request` to `http://vpn.example.test/` returns the unclaimed signature; the observation confirms the dangling pointer but the bucket is never created.