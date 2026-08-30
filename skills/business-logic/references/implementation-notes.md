# Implementation notes

Whitebox review should locate the authoritative aggregate/ledger, transaction boundary, idempotency keys, state transition methods, event consumers, retry logic, provider webhooks, and alternate controllers/jobs. Compare all ways to invoke the same transition.

High-signal source patterns: state set directly from client input; checks in controllers but not services/jobs; read-check-write without atomic constraint; approval stored separately from the value later executed; idempotency scoped to request rather than business operation; webhook retries applying side effects twice; cancellation/failure paths not releasing reservations.

Remediation should encode transitions in one domain service, validate current state and actor atomically, bind approvals to immutable operation data, enforce idempotency at the business key, reconcile external provider events, and regression-test invalid edges and retries.
