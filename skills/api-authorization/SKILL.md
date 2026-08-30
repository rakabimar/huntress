---
name: api-authorization
description: Use for REST or GraphQL object, property, function, tenant, relationship, lifecycle, batch, export, job, and API-version authorization boundaries; do not activate for public resources merely because their identifiers are guessable.
maturity: stable
risk_class: R2
category: authnz
cwe: [639, 862, 863, 284]
canonical: true
primary_specialist: api-authz-specialist
related_skills: [access-control, business-logic, graphql, mass-assignment]
primary_triggers: [object identifiers, tenant identifiers, private API resources, ownership checks]
secondary_triggers: [GraphQL nodes, exports, background jobs, bulk endpoints, API versions]
negative_triggers: [public catalog, intentionally shared object, identifier predictability without protected effect]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# API Authorization

## Purpose
Determine whether the server authorizes a subject to perform an action on the exact object, tenant, property, relationship, and lifecycle state requested. An identifier is only a locator; knowing it neither proves privacy nor grants authority.

## When to use
Activate for object IDs, nested resources, tenant/workspace selectors, role-sensitive operations, writable protected fields, batch/search/export APIs, async jobs, versioned or mobile APIs, and GraphQL nodes/resolvers. Route broader admin/function exposure to access-control; route sequence and invariant flaws to business-logic.

## Process
1. Read references/mental-model.md. Build a principal matrix from available contexts: anonymous, account_a, account_b, manager_a, manager_b, admin_test. Do not invent unavailable roles.
2. Name the tuple subject, object, action, tenant, property, state, version, relationship. Establish intended visibility before mutation.
3. Capture the owner/authorized baseline, then repeat the same operation on the same synthetic object as the unauthorized principal. Change only the principal or one locator.
4. For bulk/search/export/jobs, verify item-by-item filtering, result ownership, and later artifact retrieval—not merely request acceptance.
5. Record confirming and refuting outcomes before one Broker request. Protected data returned or durable protected state changed supports the hypothesis; uniform denial, documented sharing, or equivalent centralized enforcement refutes it.
6. Check sibling methods, nested routes, API versions, REST/GraphQL parity, lifecycle states, and server-generated identifiers only when the first comparison justifies them.

Decision: public/shared/organization-owned by design → reject; only status/existence difference → observation; protected same-object effect under unauthorized principal → supported hypothesis; unclear intended sharing → stop and resolve intent.

## Evidence
Require an authorized baseline and unauthorized comparison for the same object and operation, AuthContext roles, tenant/relationship state, minimal mutation, protected fields or postcondition, and intended-behavior check. Load references/evidence-contract.md before promotion.

## False positives
Public identifiers, public profiles, team sharing, delegated access, organization ownership, feature-defined visibility, stale cache/UI, and predictable IDs without protected impact. Read references/false-positives.md when intent is ambiguous.

## Stop conditions
Stop on Scope/Policy denial, unknown authorization, unavailable controlled principals/objects, third-party data exposure, R3/R4 without approval, or when the next request cannot distinguish the hypothesis. Never enumerate foreign identifiers or promote an existence oracle alone.

Load references/attack-surface.md for batch, jobs, GraphQL, lifecycle, version, and framework-specific analysis; load references/methodology.md for the full matrix and decision tree.
