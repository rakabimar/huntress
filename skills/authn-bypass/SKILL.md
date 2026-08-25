---
name: authn-bypass
description: Use when testing login, session, account access, or MFA flows for ways to reach protected resources without valid authentication
maturity: draft
risk_class: R2
category: authnz
cwe: [287]
---

# Authentication Bypass

## Purpose
Authentication bypass is the class of weakness where a request reaches a protected resource or action without proving the caller's identity. It matters for bug hunting because the boundary crossed is often binary and high impact: an attacker impersonates a user, skips mandatory MFA, or reads another user's data. Common causes include alternate code paths, type-juggling in identity comparisons, and missing server-side re-check of a step the client was trusted to complete.

## When to use
- Endpoints that switch on a role, `admin`, `step`, `verified`, or `authenticated` parameter supplied by the client.
- Login/MFA flows presented as multiple steps, especially when the "second factor" or "already verified" flag is client-controlled.
- Identity values compared loosely (PHP array vs string, `==`, JSON type changes, null bytes in user input).
- Sign-in forms, password-reset, passwordless magic links, "remember me" cookies, and any fixture with default credentials in scope.

## Process
1. Enumerate the protected surface and the auth check boundary (which resource, which account, which result marks success).
2. Write a falsifiable hypothesis with `create_hypothesis` — e.g. "If I omit the MFA step and submit the final request with `verified=true`, I reach the account dashboard, crossing the second-factor boundary."
3. State the observable that would refute it (e.g. a 302 back to the MFA challenge or a 401) alongside the expect-if-true observation.
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — one mutated parameter or one skipped step per request, never a raw curl/nmap/sqlmap sweep.
5. Prefer read-only proof: a 200 vs 302/401 distinction, a changed response length, or a page title proving whose session loaded.
6. Record the result with `complete_research_test` and persist durable artifacts via `create_evidence`.

## Evidence
- `request_response` pairs showing the mutated request and the differing status/body, redacted of session tokens and PII.
- `observation` notes capturing the delta between the baseline (no mutation) and the mutated request.
- `command_output` only where a local fixture response justifies it; strip any secrets before storing.

## False positives
- A 200 response on a page that renders the same shell for everyone — confirm the response leaks per-user data, not a shared layout.
- "Not enforced in the UI" but still enforced server-side — the client hiding a button is not a bypass; the server must accept the skipped step.
- Default credentials that are actually a documented demo account in a local fixture, not a vulnerability.
- A cosmetic flag that looks authoritative but is ignored by the server (e.g. `admin=true` in a cookie that is never read).

## Stop conditions
- `scope_preflight` rejects the target or action — stop, the scope engine is authoritative.
- The proof would require R3/R4 (destructive write, credential stuffing, lockout) and no approval is recorded — stop.
- The only way to demonstrate impact is exfiltration at scale or a destructive write — stop and reconsider a read-only proof.
- Default-credential attempts against a real, non-fixture target — stop; that is credential stuffing.

## Example
On `http://localhost` a two-step login returns to `POST /verify-mfa` after a password check. First submit the password step and record the `Set-Cookie` and redirect as a baseline `request_response`. Then submit `/verify-mfa` directly with `mfa_code` blank and a client-supplied `step=done`, predicting a 302 to `/dashboard`. If instead the server returns 302 back to the MFA challenge, the hypothesis is refuted. If the dashboard renders with a session cookie, the boundary is crossed read-only and becomes a candidate finding on `localhost`.