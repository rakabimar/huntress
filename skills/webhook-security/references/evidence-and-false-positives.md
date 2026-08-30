# Evidence, false positives, impact, and remediation

Evidence must prove the exact protected effect and retain a refuting control. False positives: Duplicate delivery returning 2xx with one state effect, documented retry/order tolerance, invalid signatures parsed but rejected before effect, test-mode events isolated, and outbound callbacks restricted to fixed authorized destinations.

Impact is limited to the demonstrated boundary. Remediation: Verify signatures over exact raw bytes with constant-time comparison and key rotation, enforce timestamp/replay and delivery idempotency, fetch current provider object when needed, bind provider account+tenant+object+event, centralize state transitions, validate outbound URLs/redirects, and rotate secrets safely.
