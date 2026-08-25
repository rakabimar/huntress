---
name: csrf
description: Use when testing state-changing endpoints, missing or forgeable CSRF tokens, SameSite cookie weaknesses, or login-CSRF variants.
maturity: draft
risk_class: R2
category: web
cwe: [352]
---

# Cross-Site Request Forgery

## Purpose
Cross-Site Request Forgery lets an attacker induce an authenticated victim's browser to send a state-changing request the victim never intended. For bug hunting it matters because the flaw lives at the boundary between the browser's automatic cookie attachment and the application's failure to verify that a request was actually authorized by the user. The strongest targets are state changes (password/email/role changes, payments, config writes) that rely solely on cookies for authorization.

## When to use
- State-changing endpoints that accept POST/PUT/DELETE with cookie-only authentication and no token check.
- Forms that use a predictable, reusable, or per-session CSRF token that can be replayed or guessed.
- Endpoints where the token is validated only for some verbs or content types, or disappears entirely over AJAX/JSON.
- Cookies set with `SameSite=None`, `SameSite=Lax` with unsafe methods, or an unset SameSite attribute.

## Process
1. Enumerate state-changing endpoints and record which HTTP verb, content type, and auth mechanism each expects.
2. Build a falsifiable hypothesis with `create_hypothesis`: "If I craft a cross-origin <form> for <endpoint> using victim cookies only, the state change executes, crossing the authorization boundary."
3. State the prediction on the planned test: token present in the baked request but accepted, or token omitted and the server still processes it.
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only (never raw curl/nmap/sqlmap). Replay the endpoint with the victim's session cookies but with the CSRF token removed, blanked, or taken from another session.
5. Compare against the prediction and record the observation and result via `complete_research_test`; persist request/response artifacts with `create_evidence`.
6. Verify the observation is a real state change (e.g. account field modified) rather than an error page — then promote toward a candidate finding only if the boundary was actually crossed.

## Evidence
- `request_response`: the forged request (token absent or replaced) and the server's state-changing response, redacted of session identifiers and PII.
- `observation`: before/after state comparison showing the victim account actually changed.
- `command_output`: same-document proof (e.g. a logged-out browser replay, or a saved harness transcript) that the same request still changes state without a valid token.
- Redact cookies, tokens, and any user-identifying data from all stored evidence and previews.

## False positives
- A 302 to login or a generic "invalid token" body that makes no state change — CSRF requires demonstrated impact, not a rejected request.
- Token accepted only because the test reused the session's own token — that is replay within-user, not cross-site forgery; confirm cross-origin token absence.
- SameSite=Strict/Lax on unsafe methods already blocking a top-level cross-origin navigation — check whether the endpoint is reachable via allowed methods before ruling it in scope.
- Change-password or sensitive flows that require re-authentication (current password) before the state writes.

## Stop conditions
- `scope_preflight` rejects the endpoint or the program — stop immediately.
- The proof would require a destructive or irreversible write, or an R3/R4 action with no recorded `approved` approval — stop.
- The endpoint is out of the active program's scope or belongs to another program's workspace — do not proceed.
- You cannot tell whether the action is authorized — resolve to no and stop.

## Example
An account-settings form at `https://app.example.test/settings/email` accepts POST with cookies and an `csrf_token` hidden field. Testing the hypothesis that the token is not actually validated, the harness replays the POST through `send_authorized_http_request` with the cookie jar intact but the `csrf_token` field removed. If the response returns success and a follow-up GET shows the e-mail rotated to the attacker-supplied value, the boundary was crossed and a CSRF candidate is warranted; if it returns an "invalid token" error with the field unchanged, the hypothesis is rejected.