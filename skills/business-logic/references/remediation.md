# Business-logic remediation

Centralize domain transitions around the authoritative aggregate; validate actor, current state, immutable approved data, and idempotency key atomically. Reconcile external provider events, consume one-time capabilities transactionally, constrain alternate endpoints/jobs to the same service, and test forbidden state edges, retries, stale inputs, and lifecycle revocation.
