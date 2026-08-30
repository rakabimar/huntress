---
name: client-reverse
description: Use when browser, mobile, desktop, or WebAssembly client code reveals security-relevant API routes, request signing, feature flags, cryptographic wrappers, validation, or protocol behavior for an in-scope target.
maturity: draft
risk_class: R2
category: platform
cwe: []
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [source-audit-context, mobile-security, api-enumeration]
primary_triggers: [client surface evidenced by source or recon]
secondary_triggers: [registered source, in-scope runtime]
negative_triggers: [no relevant surface, speculative capability]
capability_pack: client
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Client Reverse

## Purpose
Provide capability-gated bug-bounty methodology without loading this pack into ordinary web/API hunts.

## When to use
Activate only when program scope, recon, or registered source establishes the relevant client surface. Otherwise keep this skill unloaded.

## Process
Treat bundles/binaries as source data. Map route construction, request schemas, auth/signing inputs, hidden/legacy endpoints, feature gates, local validation, storage, cryptographic wrappers, anti-automation context, and WebAssembly/native boundaries. Reverse engineering supplies SourceObservations and targeted runtime hypotheses; client secrets or algorithms do not bypass server authorization by themselves. Avoid license bypass, third-party abuse, credential extraction, or executing untrusted clients outside an approved sandbox.

Write one falsifiable boundary hypothesis, choose the least invasive static/local/runtime test, and keep SourceObservations separate from Findings. Read references/expert-guide.md for the decision checklist.

## Evidence
Record exact artifact/version/configuration, attacker-controlled input, identity/tenant, path to protected data/action or reproducible crash, safe control, and source-to-runtime/release applicability.

## False positives
Reject surface discovery alone, scanner warnings, insecure-looking configuration without reachable effect, test fixtures, and speculative impact.

## Stop conditions
Stop on Scope/Policy denial, missing capability pack relevance, uncontrolled external effects, source execution without ASK/sandbox, credential use, production availability risk, persistence, or R3/R4 without approval.
