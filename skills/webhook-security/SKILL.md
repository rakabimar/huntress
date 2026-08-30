---
name: webhook-security
description: Use for inbound/outbound webhook signature, secret rotation, timestamp, replay, event/object/tenant binding, duplicate delivery, state transitions, provider impersonation, and callback destination security.
maturity: stable
risk_class: R2
category: protocol
cwe: [345, 294, 918]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [authentication, business-logic, ssrf, race-condition]
primary_triggers: [webhook security, implementation-specific boundary]
secondary_triggers: [source observation, runtime differential]
negative_triggers: [observation without protected effect, documented safe behavior]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Webhook Security

## Purpose
Verify that webhook messages and destinations remain bound to the provider, tenant, object, event, time, delivery, and allowed state transition.

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
Duplicate delivery returning 2xx with one state effect, documented retry/order tolerance, invalid signatures parsed but rejected before effect, test-mode events isolated, and outbound callbacks restricted to fixed authorized destinations.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, missing controlled fixtures, third-party effects, or when validation needs R3/R4 without approval. High-volume, destructive, availability, workflow execution, and uncontrolled shared-user effects are denied.

Tool choice and implementation notes are in references/implementation-notes.md.
