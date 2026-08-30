---
name: jwt
description: Use when a JWT verification boundary may mishandle signature algorithms, keys, JWKS/JWK URLs, issuer, audience, token type, claims, tenant/subject binding, time, replay, or multi-service consistency.
maturity: stable
risk_class: R2
category: authnz
cwe: [287, 345, 347, 613]
canonical: true
primary_specialist: auth-identity-specialist
related_skills: [authentication, session-management, oauth-oidc]
primary_triggers: [JWT bearer, JWKS, kid, issuer, audience, token claims]
secondary_triggers: [service token, refresh token, ID token, multi-service verifier]
negative_triggers: [base64 decoding only, expired token correctly rejected, opaque session]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# JSON Web Token Verification

## Purpose
Infer and test the verifier's trust model. JWT is a container; risk exists only when a relying service accepts attacker-controlled signature/key/claim assumptions and grants a protected identity or capability.

## When to use
Use when compact JWS/JWT artifacts, JWKS discovery, kid/jku/x5u/embedded JWK, issuer/audience/type claims, role/tenant claims, access-vs-ID token boundaries, refresh use, service-to-service tokens, or verifier inconsistencies are observed. Do not activate merely because a token can be decoded.

## Process
1. Read references/mental-model.md. Map issuer, signer, algorithm family, key source, key-selection input, relying service, accepted token types, required claims, and lifecycle.
2. Observe header/claims and public discovery metadata without treating them as trusted. Identify one applicable assumption; do not run a payload checklist.
3. Establish valid and invalid signature baselines. Then test one boundary: algorithm selection, key source/control, kid resolution, issuer, audience, typ/token_use, subject/tenant, role claim, exp/nbf/skew, replay, or service parity.
4. For remote key references, prove only whether an authorized fixture key source is consulted; do not target internal hosts. For claim mutation, a correctly failing signature is the expected control.
5. Support only when a modified/substituted token is accepted as an unauthorized identity, tenant, role, audience, or service operation. Parser errors and differing messages are observations.

## Evidence
Store token fingerprints and redacted header/claim subsets, never reusable tokens. Link the valid baseline, one controlled token mutation/substitution, verifier/service, accepted identity/capability, key provenance, and exact protected effect.

## False positives
Decode without acceptance, algorithm listed but not accepted, kid/jku parsed but constrained to trusted keys, issuer/audience deviation rejected downstream, expired tokens within documented skew, and an access token legitimately accepted by its intended resource server.

## Stop conditions
Stop before forging real users, brute-forcing keys, stealing signing material, OOB/internal fetches outside ROE, or replaying production credentials. ASK for stateful/high-risk token substitution; DENY destructive use.

Load references/attack-surface.md for verifier decision trees and multi-service comparisons; use OAuth/OIDC when token issuance or browser transaction binding is the actual question.
