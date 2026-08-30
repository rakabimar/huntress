# Authorization tuple and principal matrix

Model every decision as `allow(subject, action, object, tenant, property, state, version, relationship)`. A server may correctly authorize the object yet fail on a writable property, nested parent, export artifact, job result, lifecycle state, or older API resolver.

Use only configured contexts:

| principal | same tenant object | foreign same-role object | managed object | foreign tenant object | privileged function |
|---|---|---|---|---|---|
| anonymous | ? | ? | n/a | ? | deny |
| account_a | owner baseline | horizontal test | relationship test | tenant test | deny |
| account_b | foreign test | owner baseline | relationship test | tenant test | deny |
| manager_a | policy baseline | cross-manager test | delegated baseline | tenant test | role-dependent |
| manager_b | cross-manager test | policy baseline | delegated baseline | tenant test | role-dependent |
| admin_test | explicit program role only | explicit program role only | explicit | explicit | baseline |

An ID may be public while the object or action is private. Predictability affects discovery, not authorization. Conversely, an opaque ID does not compensate for a missing check.

Decision tree:

1. Is the resource/action intended to be public, shared, delegated, or organization-owned? If yes, record that policy and reject the private-boundary hypothesis.
2. Is the exact object and operation controlled in both principal contexts? If no, create test fixtures before testing.
3. Does the unauthorized principal receive protected fields or a durable protected postcondition? If no, an error/existence difference remains an observation.
4. Is the behavior consistent across nested/bulk/job/version/resolver surfaces? Search only siblings justified by the same invariant.
