# Evidence, false positives, impact, and remediation

Evidence includes victim AuthContext, cookie attributes/domain, attacker origin, browser request shape, preflight/simple-request behavior, token and Origin/Referer handling, before/after state, and interaction required. False positives: Postman-only requests, CORS read restrictions confused with send protection, SameSite-blocked cookies, no ambient credentials, and harmless actions.

Remediate with synchronizer/double-submit tokens correctly bound, strict Origin validation, SameSite plus narrow cookie domains, re-authentication for sensitive actions, and avoiding state change on GET. Test every alternate content type/method endpoint.
