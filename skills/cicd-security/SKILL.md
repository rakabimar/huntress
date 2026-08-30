---
name: cicd-security
description: Use for source-only CI/CD review of GitHub Actions, GitLab CI, release pipelines, untrusted PR inputs, workflow permissions, token/artifact/cache trust, OIDC, third-party actions, and self-hosted runners; never execute workflows.
maturity: stable
risk_class: R2
category: platform
cwe: [829, 269]
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [secret-exposure-analysis, dependency-reachability, source-dataflow-analysis]
primary_triggers: [cicd security, implementation-specific boundary]
secondary_triggers: [source observation, runtime differential]
negative_triggers: [observation without protected effect, documented safe behavior]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Cicd Security

## Purpose
Determine whether untrusted contribution inputs cross a privileged pipeline boundary into code execution, secrets, tokens, artifacts, releases, cloud identity, or trusted runners.

## When to use
Activate only when recon/source/traffic shows this implementation surface. Use related skills for supporting boundaries; do not load unrelated methodology.

## Process
1. Read references/expert-guide.md and identify the exact actors/components, trust boundary, and implementation signals.
2. Establish a controlled safe baseline and state a falsifiable cause→protected-effect hypothesis plus refuting observation.
3. Select the single lowest-impact experiment that distinguishes the parsers/identities/states involved; run Scope and Policy preflight before any live request.
4. Observe the authoritative security postcondition, not a status code, header, parser error, or accepted input.
5. Persist redacted evidence and reject intended/safe behavior. Promote only a supported hypothesis into the normal finding pipeline.

## Evidence
Evidence contract:
Record exact implementation/version/context, baseline and controlled change, principal/tenant/state, relevant source/runtime mapping, protected postcondition, and negative control. Load references/evidence-and-false-positives.md.

## False positives
Read-only PR workflows with least permissions, attacker code never executed in privileged context, secrets unavailable by platform design, immutable action SHAs, and artifacts cryptographically/provenance bound.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, missing controlled fixtures, third-party effects, or when validation needs R3/R4 without approval. High-volume, destructive, availability, workflow execution, and uncontrolled shared-user effects are denied.

## Tool selection
Use source read/search and git history for static workflow evidence. Use the
source sandbox only for a controlled local fixture. Repository workflow
execution is never an automatic broker action and remains ASK-gated; do not
trigger a hosted CI run merely to validate a source observation. Implementation
notes are in references/implementation-notes.md.
