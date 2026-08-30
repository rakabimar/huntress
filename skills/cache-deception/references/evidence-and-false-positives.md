# Evidence, false positives, impact, and remediation

Evidence must prove the exact protected effect and retain a refuting control. False positives: Browser/private cache, no shared hit, cache key varies on auth/cookie, origin serves public representation, sanitized public shell, status/headers differ without private body, and cache poisoning where attacker alters representation rather than exposes their private response.

Impact is limited to the demonstrated boundary. Remediation: Mark authenticated/private responses private/no-store, ensure CDN bypasses on authorization/session cookies, align origin/cache normalization and extension rules, avoid caching unknown rewritten routes, key required representation variants, and test authenticated path mutations at the edge.
