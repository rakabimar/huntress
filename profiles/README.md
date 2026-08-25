# Engagement profiles

`profiles/` holds reusable **engagement profiles**: preset operating postures
(target type, recon depth, skill routing, risk ceiling) that a session brief can
reference to bound how deep a given program is chased.

A profile is advisory configuration, not authorization.  The *authoritative*
per-program limits always come from that program's `scope.yaml` + `roe.yaml`
(enforced by `scope_preflight` / `policy_preflight`).  A profile can only be
**more** restrictive than the program's ROE, never more permissive.

## Bundled profiles

- `web-app.yaml` — browser-facing web applications.
- `api-focused.yaml` — REST/GraphQL API and service engagements.

## Schema

```yaml
name: <slug>
description: <one line>
risk_ceiling: R0..R3   # never grant above what the program's ROE allows
skills: [ ... ]        # preferred skill routing (see skills/manifest.yaml)
recon_depth: shallow | medium | deep
notes: <free text>
```