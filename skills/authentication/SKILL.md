---
name: authentication
description: Use for identity establishment and binding across login, registration, verification, reset, magic link, MFA, recovery, account linking, federation, device trust, re-authentication, and step-up flows.
maturity: stable
risk_class: R2
category: authnz
cwe: [287, 288, 290, 307, 640]
canonical: true
primary_specialist: auth-identity-specialist
related_skills: [session-management, jwt, oauth-oidc, saml-sso, rate-limit-bypass]
primary_triggers: [login, password reset, MFA, recovery, magic link, identity binding]
secondary_triggers: [account linking, device trust, fallback auth, step-up, enumeration]
negative_triggers: [post-login permission failure, token-format issue without identity effect]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Authentication

## Purpose
Determine how an asserted identity becomes an authenticated local account and whether every token, channel, factor, and transition remains bound to the intended person and transaction.

## When to use
Use for login, registration, email/phone verification, password reset, magic links, MFA enrollment/challenge/recovery, remember-device, account linking, federated/fallback login, session bootstrap, re-authentication, and step-up. Use session-management after identity is established; JWT/OAuth/SAML for protocol-specific verification.

## Process
1. Read references/mental-model.md. Draw the identity-binding chain: claimed identifier → proof channel/factor → transaction → local account → issued session.
2. Inventory states and alternate channels. For each token record purpose, subject, transaction, audience, expiry, single-use state, and invalidation event without recording its value.
3. Establish a successful owner baseline and a failure baseline. Change one binding: account, browser transaction, factor, channel, endpoint, or lifecycle state.
4. Test whether reset/verification/magic/MFA artifacts replay after use, expiry, password/factor change, or on an alternate endpoint. Use synthetic accounts and the minimum safe transition.
5. Account enumeration is supported only when a stable attacker-useful distinction survives noise/rate controls; identity deviations are findings only when they authenticate or bind the wrong account or materially weaken recovery.

## Evidence
Record state before/after, token metadata not value, issuing and consuming endpoint, intended subject/transaction, alternate principal/channel, expiry/replay controls, and the resulting authenticated identity. Prove the wrong identity or unauthorized session, not merely a response difference.

## False positives
Generic messages with timing noise, tokens rejected after parsing, a link usable only by its intended current session, optional verification with no protected privilege, documented account linking requiring re-authentication, and client-only navigation changes.

## Stop conditions
Stop before credential stuffing, brute force, real-user lockout, third-party mailbox/phone access, changing another user's factors, or R3/R4 without approval. If the only next step is guessing tokens or high-volume enumeration, stop.

Read references/attack-surface.md for lifecycle matrices and multi-channel inconsistencies; load the appropriate protocol skill when applicable.

## Tool selection
Use `policy_preflight` before any lifecycle mutation and the request broker for
the minimal controlled exchange. Use Playwright only when browser transaction
binding is itself under test; never expose token values to the browser model.
