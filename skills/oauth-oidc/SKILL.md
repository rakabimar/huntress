---
name: oauth-oidc
description: Use for OAuth 2.x and OpenID Connect transaction, redirect, PKCE, state, nonce, code, issuer, audience, token substitution, multi-IdP, federation, deep-link, and local-account-linking boundaries.
maturity: stable
risk_class: R2
category: authnz
cwe: [287, 346, 601, 613]
canonical: true
primary_specialist: auth-identity-specialist
related_skills: [authentication, jwt, open-redirect, saml-sso]
primary_triggers: [authorization code, PKCE, state, nonce, redirect URI, IdP]
secondary_triggers: [account linking, mobile deep link, multi-IdP, federation, token substitution]
negative_triggers: [cosmetic spec deviation, safe redirect normalization, protocol metadata only]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# OAuth 2.x and OpenID Connect

## Purpose
Test whether the authorization transaction binds the resource owner, browser, client, redirect URI, code, verifier, issuer, token audience, and IdP identity to the intended local account.

## When to use
Use for Authorization Code, Code+PKCE, OIDC, legacy implicit where deployed, mobile/deep-link flows, multiple IdPs, federation, callbacks, and account linking. Route token verifier internals to JWT and generic recovery/linking logic to authentication.

## Process
1. Read references/mental-model.md. Label resource owner, user agent, client, authorization server, resource server, and IdP. Record exact flow and client type.
2. Build the binding ledger: state↔browser transaction; nonce↔authentication; code↔client and redirect URI; verifier↔challenge; issuer↔client; token↔audience; IdP subject↔local account. Email is an attribute, not necessarily identity.
3. Capture one successful transaction. Change one binding using only controlled accounts/clients: state, nonce, browser session, redirect, verifier, code recipient, issuer, token type/audience, or linking identity.
4. Check multi-IdP collisions, mix-up, token substitution, and account linking only when multiple issuers or linking surfaces exist. Analyze open redirects as a supporting primitive, not automatic takeover.
5. Support only when attacker-controlled input completes authorization, authenticates the wrong local account, links an attacker identity to a victim account, or releases a usable code/token to an attacker-controlled endpoint.

## Evidence
Record client/issuer/redirect identifiers, flow, transaction fingerprints, binding changed, baseline and result, resulting local account, and attacker-controlled endpoint/account. Redact codes, tokens, cookies, emails, and PII.

## False positives
State omitted in a non-browser back-channel with another binding, nonce absent when no ID-token replay threat exists, a redirect rejected after normalization, public-client PKCE deviations without code theft, and spec noncompliance without attacker-controlled outcome.

## Stop conditions
Stop before third-party IdP abuse, real-account linking, code/token interception outside controlled accounts, broad redirect probing, or R3/R4 without approval. If no attacker-controlled security outcome can be stated, reject.

Read references/attack-surface.md for flow-specific branches and account-linking analysis.

## Tool selection
Use Playwright for the controlled browser transaction and the request broker
for protocol-level comparisons. Run `policy_preflight` before account linking,
consent, or any callback mutation. Persist fingerprints, never token values.
