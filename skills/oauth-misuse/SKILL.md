---
name: oauth-misuse
description: Use when a target implements OAuth 2 / OpenID Connect authorization (redirect_uri, state, tokens, PKCE, code vs implicit flows)
maturity: draft
risk_class: R2
category: authnz
cwe: [287]
---

# OAuth 2 / OpenID Connect Misuse

## Purpose
OAuth 2 and OpenID Connect delegate authentication and authorization across parties, so a flaw in redirect validation, state handling, token acceptance, or PKCE can let an attacker impersonate a user or steal creds. For bug hunters this is high-value because the trust boundaries are subtle and the impact (account takeover, token theft) is concrete. Hunting it means following the flow end-to-end and probing each handoff where a parameter is accepted, parsed, or trusted.

## When to use
- The app exposes an `/authorize`, `/token`, `/callback`, `/oauth`, `/oidc`, or similar login/exchange endpoint.
- Login redirects to an identity provider with query parameters like `redirect_uri`, `client_id`, `response_type`, `scope`, `state`, `code_challenge`.
- Tokens (access, refresh, ID) are returned in URLs, logs, headers, or client-side storage.
- The client uses a mobile/native or single-page profile where PKCE or confidential-client assumptions may be missing.

## Process
1. Map the flow. Identify the authorization endpoint, the redirect target, the token endpoint, and what `response_type` (code vs implicit/token) is in play. Record observations.
2. Form a falsifiable hypothesis for a specific handoff, e.g. `create_hypothesis`: "If I pass a modified `redirect_uri` not registered for the client, the authorization server will still redirect the code to my controlled origin."
3. Predict the observable for true vs false on the planned test (`create_research_test`), then run the MINIMAL controlled experiment through `send_authorized_http_request` only — never raw curl/nmap/sqlmap.
4. Probe each candidate weakness one at a time with a single controlled change: unregistered or open `redirect_uri`, a missing or replayed `state`, absent `code_challenge` + `code_verifier`, token/`code` values exposed in URL fragments or logs.
5. Capture the response and transition the hypothesis (supports/rejects/inconclusive); record evidence via `complete_research_test` and `create_evidence`.
6. Prefer read-only demonstration: prove a code redirects to an attacker-controlled origin on a throwaway test client rather than exercising a real victim's token.

## Evidence
- `request_response` records of the authorize/token/callback exchange, with the exact parameter delta that triggered the behavior.
- `observation` notes for parameter comparison (registered vs. tampered `redirect_uri`, `state` present vs. absent).
- Redact any real tokens, authorization codes, and PII from stored previews and artifacts.

## False positives
- An error page on a tampered `redirect_uri` is not a finding — it may mean validation works. Confirm whether the code actually landed on the attacker origin.
- Missing `state` alone is only CSRF-relevant if the attacker can force a login-session bind; distinguish "absent state" from "state accepted but never checked".
- Implicit-flow token leakage is only exploitable when a practical attacker can read the fragment (e.g. referrer, open redirect); an isolated browser is not.
- A bug in a self-hosted IdP you fully control is intended behavior — only count trust-boundary crossing on the tested app.

## Stop conditions
- `scope_preflight` rejects the target or any endpoint — stop.
- The action would need R3/R4 (e.g. mass token harvesting, destructive write) and no approval is recorded — stop; request approval.
- Proving the issue would require exfiltrating or using a real victim's token or destroying data — stop and switch to a local proof-of-concept.
- A response could be legitimate IdP behavior and you cannot distinguish it in scope — stop rather than guess.

## Example
An app on `example.test` redirects to `https://idp.example.test/authorize?client_id=app&redirect_uri=https://app.example.test/callback&response_type=code&state=xyz`. Hypothesis: the IdP does not validate `redirect_uri` against the client registration. Test: send the authorize request with `redirect_uri=https://evil.test/cb` through the broker, keeping `client_id` unchanged. If the IdP redirects the code to `evil.test`, the hypothesis is supported; if it returns `redirect_uri_mismatch`, it is refuted. Demonstrate the redirect landing on a throwaway `evil.test` client you own, never a real user's session.