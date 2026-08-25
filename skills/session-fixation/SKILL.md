---
name: session-fixation
description: Use when auditing login/logout flows, session cookie rotation, or cookie attributes.
maturity: draft
risk_class: R2
category: authnz
cwe: [384]
---

# Session Fixation

## Purpose
Session fixation is an authentication weakness where an attacker pre-establishes a session identifier and tricks a victim into authenticating into it. Because the pre-login session is reused after login without rotation, the attacker's known identifier becomes the victim's authenticated session. For bug hunting it covers a family of session-management flaws: pre-login cookie reuse, missing rotation, predictable session IDs, weak cookie scope/secure flags, and logout not invalidating the session.

## When to use
- A login endpoint accepts a session cookie before authentication and the app may reuse that same ID afterward.
- Session IDs look short, sequential, or predictable rather than random.
- Logout appears not to invalidate the server-side session, or cookies lack Secure/HttpOnly/Path scope.
- Password reset or privilege-elevation flows that should rotate the session token.

## Process
1. Observe the unauthenticated session: capture the Set-Cookie value from a pre-login request.
2. Build a falsifiable hypothesis with create_hypothesis: "If I log in while holding session ID X, then X will remain valid and authenticated afterward."
3. Run the minimal controlled experiment through send_authorized_http_request only: submit the login while presenting the captured pre-login cookie, then replay a request with that same cookie.
4. Record the outcome with complete_research_test and create_evidence, capturing both request_response pairs.
5. Repeat for logout (does the cookie still work afterward?) and for the cookie's scope/flag attributes.
6. Use the least-invasive proof possible: one login and a single replayed request, never mass account access.

## Evidence
- request_response records showing the same session cookie before and after login (proves no rotation).
- request_response showing a replayed cookie succeeding after logout (proves no invalidation).
- observation notes documenting Secure/HttpOnly/Path/Domain flags from Set-Cookie headers.
- Redact any session tokens, usernames, and PII from stored previews.

## False positives
- The app issues a fresh cookie post-login but also sends an unrelated non-auth cookie; only the auth token matters.
- A cookie surviving logout is benign if the session is otherwise re-validated server-side on each request.
- Missing Secure on a cookie set over a non-TLS internal channel may be documented behavior.
- A long random ID that merely looks sequential in one sample is not predictability; correlate multiple samples before claiming a pattern.

## Stop conditions
- scope_preflight rejects the target or endpoint; stop and do not test.
- Proving the flaw would require R3/R4 actions or destructive writes and no approval is recorded; stop.
- Demonstrating it would force mass data access or lock out a shared account; stop and use a controlled test account only.

## Example
Against a localhost app, request `http://localhost:8080/login` with no cookie and record the `Set-Cookie: SESSIONID=abc123` value. Then POST credentials while replaying `SESSIONID=abc123`. If the authenticated dashboard still honors `SESSIONID=abc123`, the session was not rotated and fixation is demonstrated. Confirm the fix by observing a new value in the post-login response.