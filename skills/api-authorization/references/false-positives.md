# Authorization false positives

Reject public catalog/profile data, organization/team-owned resources, explicit sharing, delegated manager access, support access defined by the feature, stale UI/cache, sanitized public projections, and identifiers whose predictability exposes no protected data/action.

Batch HTTP 200 may contain only authorized items; a foreign item omitted is enforcement. A 403/404/response-length oracle is not a finding unless the existence itself is sensitive and attacker-useful. A client can alter owner/tenant fields in the request without vulnerability when the server ignores/recomputes them.
