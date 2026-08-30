---
name: graphql
description: Use for GraphQL schema, resolver, field, node/global-ID, nested-object, alias, batching, mutation, subscription, custom scalar, upload, WebSocket, complexity, leakage, and REST-parity analysis.
maturity: stable
risk_class: R2
category: api
cwe: [200, 284, 400, 862]
canonical: true
primary_specialist: api-authz-specialist
related_skills: [api-authorization, access-control, websocket, file-upload]
primary_triggers: [GraphQL endpoint, resolver, query, mutation, subscription]
secondary_triggers: [global node ID, aliases, fragments, batching, complexity, custom scalar]
negative_triggers: [introspection intentionally enabled without sensitive effect]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# GraphQL Security

## Purpose
Treat GraphQL as an execution graph whose security boundary lives at every resolver and field, not at the single HTTP endpoint.

## When to use
Use for schema/introspection context, queries, mutations, subscriptions, node/global IDs, nested traversal, aliases/fragments/batches, field authorization, custom scalars, uploads, GraphQL-over-WebSocket, error leakage, complexity controls, and REST parity.

## Process
1. Read references/mental-model.md. Model root operation → resolver → object loader → nested field resolvers → side effects. Mark which resolver receives identity/tenant context.
2. Obtain only the schema surface allowed by ROE or already observed. Introspection is reconnaissance, not a vulnerability.
3. For authorization, compare the same node/field/mutation under owner and unauthorized principals. Test nested fields independently because parent authorization may not protect child loaders.
4. For aliases/batching, use the smallest two-operation query that tests whether per-item controls and cost accounting survive composition. Do not amplify volume.
5. For subscriptions/WebSockets, test connection authentication, subscribe-time authorization, event-time revalidation, and tenant filtering separately.
6. Support only demonstrated protected field/object/action/event exposure, unsafe scalar interpretation, or bounded cost-control bypass with allowed impact.

## Evidence
Store a minimal redacted operation, variables shape without secrets, operation name, resolver/field path, principal and tenant context, baseline/unauthorized result, GraphQL errors, and durable mutation/event postcondition.

## False positives
Enabled introspection, verbose but nonsensitive type names, global IDs that remain authorized, partial-data errors correctly omitting protected fields, expected alias support, and theoretical depth without measured policy-relevant effect.

## Stop conditions
Stop before deep/alias floods, production DoS, broad enumeration, subscription to real-user events, or R3/R4 without approval. A complexity hypothesis must use a bounded local or explicitly permitted test.

Read references/attack-surface.md for resolver matrices, subscriptions, uploads, and framework notes; compose api-authorization as the primary boundary skill for private objects.

## Tool selection
Use source symbol/reference tools for resolver guards when source is available.
Use `policy_preflight` and the request broker for one bounded GraphQL operation;
use Playwright only for a browser-bound subscription lifecycle. Never use an
unbounded alias/depth scanner.
