# Feature state-machine model

For a feature, write:

- actors and which transitions each may initiate/approve;
- assets and authoritative ledgers;
- states with entry/exit conditions;
- transitions with preconditions, side effects, and postconditions;
- invariants that must hold under retries, concurrency, alternate channels, and stale state.

Useful invariant families:

- conservation: money, credits, inventory, quota, and entitlements cannot be created by sequence tricks;
- uniqueness: a one-time token/coupon/invite/refund is consumed once;
- separation of duties: proposer, approver, and beneficiary rules persist;
- monotonicity: approved/finalized security state cannot silently regress;
- binding: actor, tenant, object, price/value, and recipient remain the ones authorized;
- correspondence: payment/refund/subscription state matches the external authoritative provider.

The best next test changes one edge in the state graph and observes the authoritative state, not the UI.
