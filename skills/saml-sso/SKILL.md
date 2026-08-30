---
name: saml-sso
description: Use for SAML SSO identity, signature/certificate, assertion, subject, audience, recipient, destination, InResponseTo, replay, RelayState, IdP confusion, and local-account-linking boundaries.
maturity: stable
risk_class: R2
category: protocol
cwe: [287, 347]
canonical: true
primary_specialist: auth-identity-specialist
related_skills: [authentication, session-management, xxe]
primary_triggers: [saml sso, implementation-specific boundary]
secondary_triggers: [source observation, runtime differential]
negative_triggers: [observation without protected effect, documented safe behavior]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Saml Sso

## Purpose
Test whether an SP binds a signed assertion and browser transaction from the trusted IdP to the intended SP audience, recipient, subject, and local account.

## When to use
Activate only when recon/source/traffic shows this implementation surface. Use related skills for supporting boundaries; do not load unrelated methodology.

## Process
1. Read references/expert-guide.md and identify the exact actors/components, trust boundary, and implementation signals.
2. Establish a controlled safe baseline and state a falsifiable cause→protected-effect hypothesis plus refuting observation.
3. Select the single lowest-impact experiment that distinguishes the parsers/identities/states involved; run Scope and Policy preflight before any live request.
4. Observe the authoritative security postcondition, not a status code, header, parser error, or accepted input.
5. Persist redacted evidence and reject intended/safe behavior. Promote only a supported hypothesis into the normal finding pipeline.

## Evidence
Record exact implementation/version/context, baseline and controlled change, principal/tenant/state, relevant source/runtime mapping, protected postcondition, and negative control. Load references/evidence-and-false-positives.md.

## False positives
Unsigned outer response with correctly signed selected assertion, valid IdP-initiated flow by design, accepted certificate rollover, harmless RelayState, expired/replayed assertions rejected, and XML parser differences without identity effect.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, missing controlled fixtures, third-party effects, or when validation needs R3/R4 without approval. High-volume, destructive, availability, workflow execution, and uncontrolled shared-user effects are denied.

Tool choice and implementation notes are in references/implementation-notes.md.
