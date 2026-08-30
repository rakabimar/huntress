# Expert guide: workflow bypass

## Mental model
Represent states, authorized transitions, actor, preconditions, immutable transition data, and terminal postcondition. The flaw is a forbidden edge accepted by the authoritative server—not a skipped screen.

## Attack surface and methodology
Map signup/KYC, invite, approval, checkout, password/security changes, publishing, refunds, and administrative review. Test one edge: final before prerequisite; completed step replay; stale token after revoke/change; backward transition; alternate endpoint/job; actor substitution. Record normal path and current state, then invoke one forbidden transition and read authoritative state.

Decision tree: cosmetic step or redirect only → reject; server rechecks prerequisite → reject; response accepted but state unchanged/idempotent → reject; forbidden durable state reached → support. Race-condition supports only when concurrency is essential; api-authorization supports actor/object boundaries.
