# Expert guide: unsafe object reconstruction

## Mental model
Trace attacker-controlled bytes→format/provenance check→decoder→type resolution/object graph→magic callbacks/gadgets→sink or security-sensitive fields. Dangerous API presence is not enough: require a reachable untrusted source, applicable type/gadget, configuration, and effect.

## Attack surface and methodology
Inspect cookies/tokens, HTTP bodies, file imports, queues, cache/session data crossing trust zones, plugin protocols, Java/PHP/.NET/Python/Ruby native formats, YAML object tags, and JSON polymorphic typing. Source-first analysis is preferred. Establish format/provenance and a safe type/field differential; do not deploy gadget chains against production.

Decision tree: signature/MAC rejects changes → control; data-only safe schema → reject; dangerous library unused/unreachable → observation; attacker-selected type/field instantiated and crosses a boundary → candidate; RCE gadget proof requires isolated approved fixture and policy, never live target. Destructive gadget execution is DENY.
