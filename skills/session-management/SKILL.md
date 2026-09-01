---
name: session-management
description: Use for authenticated session issuance, rotation, fixation, invalidation, refresh, concurrent devices, remember-me, timeout, cookie scope, cross-subdomain confusion, and CSRF relationships.
maturity: stable
risk_class: R2
category: authnz
cwe: [384, 613, 614, 1004]
canonical: true
primary_specialist: auth-identity-specialist
related_skills: [authentication, jwt, csrf]
primary_triggers: [session cookie, refresh lifecycle, logout, invalidation, rotation]
secondary_triggers: [remember-me, device sessions, privilege change, cross-subdomain cookie]
negative_triggers: [login identity binding, JWT verification without session lifecycle]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Session Management

## Purpose
Test the server-maintained lifecycle of an authenticated continuity credential after identity proof: issuance, binding, rotation, use, revocation, expiry, and coexistence.

## When to use
Activate for login/privilege-change rotation, logout/password/MFA-change invalidation, concurrent and device sessions, remember-me, access/refresh pairs, idle/absolute timeout, cookie Domain/Path/Secure/HttpOnly/SameSite, environment or subdomain confusion, and CSRF coupling. Route account recovery to authentication and token signature/claims to JWT.

## Process
1. Read references/mental-model.md. Build a lifecycle table for each credential class: issuer, storage, scope, rotation event, invalidation event, idle/absolute lifetime, and successor/predecessor relationship.
2. Capture metadata for a pre-event session, perform one controlled event, then replay the exact pre-event credential through AuthContext mediation without persisting its value.
3. Test login and privilege elevation for fixation/rotation; test logout, password change, MFA change, role change, and device revocation separately.
4. For refresh rotation, verify one-time family semantics and whether reuse revokes descendants. For concurrent sessions, distinguish intended multi-device support from failure to honor explicit revocation.
5. Cookie attributes matter only in a reachable browser threat model; SameSite is not a replacement for CSRF reasoning and HttpOnly does not prevent session riding.

## Evidence
Credential fingerprints/IDs only, pre/post event timestamps, session/device identity, exact invalidation event, replay response, server-side authenticated identity, and cookie attributes. Prove continued authenticated capability after an event that should revoke or rotate it.

## False positives
Intentionally concurrent sessions, logout that revokes only the current device by design, an old token that parses but cannot access protected data, clock-skew edge behavior within policy, and cookie attribute warnings with no feasible origin/subdomain context.

## Stop conditions
Stop before stealing real sessions, cross-user browsing, guessing credentials, mass revocation, or state changes outside test accounts. ASK when an invalidation event is high-impact; DENY destructive/session-availability tests.

Read references/attack-surface.md for lifecycle/event matrices and deployment-specific cookie boundaries.

## Tool selection
Use Playwright only to establish controlled browser sessions. Use
`policy_preflight` before logout, revocation, or factor changes and the request
broker for the exact replay. Never paste session values into model context.

Inspect `get_auth_session_status` and bounded refresh/rotation/invalidation metadata. Let the lifecycle manager refresh once on confident expiry; MFA/CAPTCHA remains `WAITING_HUMAN`.
