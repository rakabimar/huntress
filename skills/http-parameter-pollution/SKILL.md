---
name: http-parameter-pollution
description: Use for duplicate query keys, headers, form fields, JSON keys, arrays, encodings, and proxy/framework/backend normalization disagreements; choose tests from implementation signals rather than combinatorial fuzzing.
maturity: stable
risk_class: R2
category: protocol
cwe: [235, 444]
canonical: true
primary_specialist: recon-specialist
related_skills: [request-smuggling, mass-assignment, cache-poisoning]
primary_triggers: [http parameter pollution, implementation-specific boundary]
secondary_triggers: [source observation, runtime differential]
negative_triggers: [observation without protected effect, documented safe behavior]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Http Parameter Pollution

## Purpose
Determine whether two components interpret the same request parameters differently across a security boundary.

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
A single consistent documented first/last/array rule across all components, duplicates rejected, harmless application array semantics, WAF block with no downstream difference, and duplicate JSON impossible from the actual client path.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, missing controlled fixtures, third-party effects, or when validation needs R3/R4 without approval. High-volume, destructive, availability, workflow execution, and uncontrolled shared-user effects are denied.

Tool choice and implementation notes are in references/implementation-notes.md.

Use structured query `ADD` to preserve duplicate parameters, one field at a time, then compare clustered responses. Do not reconstruct the raw request or spray parameter lists.
