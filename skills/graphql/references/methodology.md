# Resolver-centered methodology

Create a resolver matrix from observed schema/operations. Select one field/mutation/subscription event and exact principal/object/tenant. Compare owner versus unauthorized principal on the same node and field; for nested data, hold parent constant. HTTP 200 and partial errors are interpreted at field level.

Aliases/batches use at most two operations to test per-item policy/cost. Subscriptions separate connection, subscribe, and event delivery. Complexity hypotheses remain local or explicitly approved and bounded. Introspection alone is reconnaissance.
