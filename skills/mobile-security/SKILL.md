---
name: mobile-security
description: Use only for in-scope APK/IPA/mobile surfaces involving static analysis, deep links, WebViews, exported components, local storage/secrets, mobile auth, certificate-pinning context, and backend API parity.
maturity: draft
risk_class: R2
category: platform
cwe: []
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [client-reverse, authentication, api-authorization]
primary_triggers: [mobile surface evidenced by source or recon]
secondary_triggers: [registered source, in-scope runtime]
negative_triggers: [no relevant surface, speculative capability]
capability_pack: mobile
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Mobile Security

## Purpose
Provide capability-gated bug-bounty methodology without loading this pack into ordinary web/API hunts.

## When to use
Activate only when program scope, recon, or registered source establishes the relevant mobile surface. Otherwise keep this skill unloaded.

## Process
Model app identity, deep/universal links, exported components/intents, WebView origin/bridge, local credentials/data, keystore/keychain use, network security config, mobile OAuth, device binding, and mobile/backend API parity. Static package analysis is AUTO when files are registered; installing/running apps or device interaction follows policy/sandbox. Pinning is analysis context, not a vulnerability. Prove protected app/backend effect; avoid device persistence, third-party apps, or unrelated platform exploitation.

Write one falsifiable boundary hypothesis, choose the least invasive static/local/runtime test, and keep SourceObservations separate from Findings. Read references/expert-guide.md for the decision checklist.

## Evidence
Record exact artifact/version/configuration, attacker-controlled input, identity/tenant, path to protected data/action or reproducible crash, safe control, and source-to-runtime/release applicability.

## False positives
Reject surface discovery alone, scanner warnings, insecure-looking configuration without reachable effect, test fixtures, and speculative impact.

## Stop conditions
Stop on Scope/Policy denial, missing capability pack relevance, uncontrolled external effects, source execution without ASK/sandbox, credential use, production availability risk, persistence, or R3/R4 without approval.
