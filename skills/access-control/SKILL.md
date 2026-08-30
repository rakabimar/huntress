---
name: access-control
description: Use for broad permission, role, administrative function, delegation, impersonation, route-guard, middleware, feature-flag, and organization boundary enforcement; use api-authorization for a specific API object operation.
maturity: stable
risk_class: R2
category: authnz
cwe: [284, 285, 862, 863]
canonical: true
primary_specialist: api-authz-specialist
related_skills: [api-authorization, authentication, business-logic]
primary_triggers: [role enforcement, admin function, permission inheritance, middleware]
secondary_triggers: [impersonation, invites, temporary delegation, hidden routes, feature flags]
negative_triggers: [single private object ownership, UI hiding with correct server denial]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Access Control

## Purpose
Test whether a principal may reach a function or permission capability at all. The unit is a role-action-context boundary, not merely one object ID.

## When to use
Use for admin/support functions, role inheritance, organization/workspace permissions, invite-derived and temporary roles, delegation, impersonation, feature entitlements used as security controls, route guards, backend middleware, method/version alternatives, and bulk functions. Prefer api-authorization when the question is whether this principal may act on this particular resource.

## Process
1. Read references/mental-model.md and construct a role-action matrix: rows are real principals/roles; columns are exact capabilities; cells state allowed, denied, or unknown.
2. Identify the authoritative enforcement layer: gateway, route middleware, decorator, controller, service, or policy engine. Client visibility and feature flags are observations only.
3. Establish one allowed higher-role baseline and one lower-role denial baseline. Replay the exact function with the lower role, changing only method/path/version when testing an alternate enforcement path.
4. Test inheritance, delegation, invite acceptance, permission revocation, and impersonation as explicit state transitions. Verify effective permissions after the transition.
5. Support only when the lower role completes the protected function or acquires a durable capability. A hidden button, discoverable route, different error, or accepted request without protected effect is insufficient.

## Evidence
Persist the role-action matrix cell under test, role provenance, allowed and denied baselines, exact server-side operation, and protected postcondition. For temporary permissions include grant/revoke timestamps and replay result.

## False positives
UI-only exposure with correct backend denial, harmless route discovery, documented permission inheritance, organization-wide ownership, support roles explicitly allowed, feature access without security consequence, and stale role caches that converge before any protected action.

## Stop conditions
Stop on Scope/Policy denial, unconfigured elevated roles, production-user impersonation, ambiguous delegated authority, or any destructive/high-risk admin action lacking approval. One exact matrix cell per hypothesis.

Read references/attack-surface.md for permission lifecycle and implementation layers; use api-authorization as a supporting skill when a function also targets a private object.

## Tool selection
Use `policy_preflight` before the single matrix-cell experiment and
`send_authorized_http_request` for the controlled baseline/replay. Browser-only
workflow observation may use Playwright, but authoritative API effects still go
through the broker.
