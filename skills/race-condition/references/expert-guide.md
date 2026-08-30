# Expert guide: race conditions

## Mental model
Model one invariant over shared mutable state and the check→use→commit window. Distinguish lost update, duplicate consumption, stale-version write, non-atomic uniqueness, lock-scope error, and idempotency-key race. Concurrency is causal only if sequential controls cannot produce the same forbidden state.

## Attack surface and methodology
Prioritize coupon redemption, balance/credit transfer, inventory reservation, signup/referral uniqueness, rate/quota counters, approval execution, refresh rotation, and file TOCTOU. Establish a sequential baseline, then the smallest concurrent pair. Synchronize at the server boundary only as policy permits; capture both responses and the final authoritative ledger. Repeat minimally because races are probabilistic. Source review traces transaction isolation, unique constraints, compare-and-swap/version fields, locks, and idempotency storage.

Decision tree: two responses but one durable effect → reject; duplicate durable effect under sequential replay too → workflow/idempotency issue, not necessarily race; only concurrent pair violates the invariant reproducibly → support. Race testing is risk-sensitive: Policy ASK may apply; high-volume or availability probes are DENY.
