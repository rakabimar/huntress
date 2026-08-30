# Feature-invariant methodology

Build the feature state machine and authoritative ledger first. Write one invariant and its forbidden edge. Capture normal preconditions and postcondition, then change exactly one actor, sequence, replay state, stale token, alternate endpoint, or approved value. Observe the durable aggregate/provider state.

Separate concurrency, object authorization, and input binding into supporting skills only when necessary. An odd response that is repaired, idempotent, or has no protected/economic postcondition rejects the hypothesis.
