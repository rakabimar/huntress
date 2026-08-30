---
name: grpc-security
description: Use only when recon/source identifies gRPC services, protobufs, reflection, metadata authentication, streaming, or REST/gRPC parity.
maturity: draft
risk_class: R2
category: platform
cwe: []
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [api-authorization, access-control, websocket]
primary_triggers: [grpc surface evidenced by source or recon]
secondary_triggers: [registered source, in-scope runtime]
negative_triggers: [no relevant surface, speculative capability]
capability_pack: grpc
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Grpc Security

## Purpose
Provide capability-gated bug-bounty methodology without loading this pack into ordinary web/API hunts.

## When to use
Activate only when program scope, recon, or registered source establishes the relevant grpc surface. Otherwise keep this skill unloaded.

## Process
Model channel/TLS, service/method, metadata identity, interceptor chain, request message fields, stream lifecycle, backend service, and tenant/object policy. Reflection/protobuf discovery is reconnaissance. Compare unary/streaming methods, per-message and stream-start authorization, metadata normalization, exposed internal methods, input validation, deadlines/limits, and REST parity. Use generated/local descriptors and one bounded semantic call through authorized tooling; never fuzz production streams or infer a flaw from enabled reflection.

Write one falsifiable boundary hypothesis, choose the least invasive static/local/runtime test, and keep SourceObservations separate from Findings. Read references/expert-guide.md for the decision checklist.

## Evidence
Record exact artifact/version/configuration, attacker-controlled input, identity/tenant, path to protected data/action or reproducible crash, safe control, and source-to-runtime/release applicability.

## False positives
Reject surface discovery alone, scanner warnings, insecure-looking configuration without reachable effect, test fixtures, and speculative impact.

## Stop conditions
Stop on Scope/Policy denial, missing capability pack relevance, uncontrolled external effects, source execution without ASK/sandbox, credential use, production availability risk, persistence, or R3/R4 without approval.
