---
name: cache-deception
description: Use when a private/dynamic authenticated response may be cached and served cross-user because cache and origin disagree about static-looking paths, extensions, normalization, or authentication variance.
maturity: stable
risk_class: R2
category: infra
cwe: [525]
canonical: true
primary_specialist: recon-specialist
related_skills: [cache-poisoning, authentication, information-disclosure]
primary_triggers: [cache deception, implementation-specific boundary]
secondary_triggers: [source observation, runtime differential]
negative_triggers: [observation without protected effect, documented safe behavior]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Cache Deception

## Purpose
Prove a private response becomes a shared cache object under an attacker-shaped route and is retrievable without the original authority.

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
Browser/private cache, no shared hit, cache key varies on auth/cookie, origin serves public representation, sanitized public shell, status/headers differ without private body, and cache poisoning where attacker alters representation rather than exposes their private response.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, missing controlled fixtures, third-party effects, or when validation needs R3/R4 without approval. High-volume, destructive, availability, workflow execution, and uncontrolled shared-user effects are denied.

Tool choice and implementation notes are in references/implementation-notes.md.

Use request replay for a single path/header change and `compare_responses` for cache/status/body/header behavior. Preserve one-variable causality.
