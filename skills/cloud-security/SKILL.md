---
name: cloud-security
description: Use only when source/recon shows AWS, Azure, or GCP application boundaries involving identity, resource policy, storage, signed URLs, metadata, serverless, role assumption, OIDC trust, or cross-account/tenant access.
maturity: draft
risk_class: R2
category: platform
cwe: []
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [ssrf, api-authorization, cicd-security]
primary_triggers: [cloud surface evidenced by source or recon]
secondary_triggers: [registered source, in-scope runtime]
negative_triggers: [no relevant surface, speculative capability]
capability_pack: cloud
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Cloud Security

## Purpose
Provide capability-gated bug-bounty methodology without loading this pack into ordinary web/API hunts.

## When to use
Activate only when program scope, recon, or registered source establishes the relevant cloud surface. Otherwise keep this skill unloaded.

## Process
Model caller identity, cloud principal, resource, policy layers, account/project/tenant, session/role assumption, region, signed request/URL, and application ownership. Review public storage/resource policies, signed URL scope/expiry/content binding, serverless event authorization, OIDC subject/audience trust, cross-account role conditions, and metadata exposure only when surfaced. This is application/cloud boundary research, not cloud post-exploitation. Prove one in-scope read/action with synthetic resources; never enumerate accounts, persist access, or use discovered credentials automatically.

Write one falsifiable boundary hypothesis, choose the least invasive static/local/runtime test, and keep SourceObservations separate from Findings. Read references/expert-guide.md for the decision checklist.

## Evidence
Record exact artifact/version/configuration, attacker-controlled input, identity/tenant, path to protected data/action or reproducible crash, safe control, and source-to-runtime/release applicability.

## False positives
Reject surface discovery alone, scanner warnings, insecure-looking configuration without reachable effect, test fixtures, and speculative impact.

## Stop conditions
Stop on Scope/Policy denial, missing capability pack relevance, uncontrolled external effects, source execution without ASK/sandbox, credential use, production availability risk, persistence, or R3/R4 without approval.
