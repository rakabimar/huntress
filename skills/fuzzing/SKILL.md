---
name: fuzzing
description: Use primarily for local, in-scope parsers, file formats, protocol handlers, libraries, and native components; production network fuzzing remains ROE/budget gated and is never automatic.
maturity: draft
risk_class: R2
category: platform
cwe: []
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [source-dataflow-analysis, file-upload, optional-native-code]
primary_triggers: [fuzzing surface evidenced by source or recon]
secondary_triggers: [registered source, in-scope runtime]
negative_triggers: [no relevant surface, speculative capability]
capability_pack: fuzzing
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Fuzzing

## Purpose
Provide capability-gated bug-bounty methodology without loading this pack into ordinary web/API hunts.

## When to use
Activate only when program scope, recon, or registered source establishes the relevant fuzzing surface. Otherwise keep this skill unloaded.

## Process
Build a local harness around the narrow parser/API, deterministic seed corpus, coverage signal, sanitizers where applicable, resource/time limits, crash capture, deduplication, minimization, and root-cause/attacker-reachability triage. A crash is an observation until reproducible, reachable, and security-relevant. Repository-controlled builds/harnesses may execute code and therefore require ASK plus an isolated sandbox; do not npm/pip/build/test automatically. Network fuzzing is distinct, policy-gated, low-volume, and never aimed at availability.

Write one falsifiable boundary hypothesis, choose the least invasive static/local/runtime test, and keep SourceObservations separate from Findings. Read references/expert-guide.md for the decision checklist.

## Evidence
Record exact artifact/version/configuration, attacker-controlled input, identity/tenant, path to protected data/action or reproducible crash, safe control, and source-to-runtime/release applicability.

## False positives
Reject surface discovery alone, scanner warnings, insecure-looking configuration without reachable effect, test fixtures, and speculative impact.

## Stop conditions
Stop on Scope/Policy denial, missing capability pack relevance, uncontrolled external effects, source execution without ASK/sandbox, credential use, production availability risk, persistence, or R3/R4 without approval.
