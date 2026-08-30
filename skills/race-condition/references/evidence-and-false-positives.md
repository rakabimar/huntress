# Evidence, false positives, impact, and remediation

Evidence requires the invariant, shared resource, sequential control, concurrency count/timing method, every request/response, unique operation IDs, and authoritative final state. False positives include duplicate success messages with one ledger effect, documented multi-use resources, eventual consistency that converges correctly, client retry display, and deadlock/500 without integrity impact.

Impact is the controlled duplicate value/action only. Remediate with atomic transactions/conditional updates, database uniqueness, correct isolation/locking, business-key idempotency, and concurrency regression tests. Never recommend a client double-click guard as the primary fix.
