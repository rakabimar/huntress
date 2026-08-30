# Expert guide

Mental model: entrypoint → identity context → object/tenant load → policy → protected action. Attack surface covers GET private resource, CREATE/UPDATE/DELETE, export, invite, role/admin, background jobs, bulk endpoints, GraphQL mutations/resolvers, and alternate API versions. Missing visible middleware is not enough; service/repository predicates or framework-global controls may enforce the invariant.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

## Layer-by-layer method

Start at one sensitive route/resolver/consumer. Record route middleware/decorators, framework-global interceptors, controller, service, object load, tenant predicate, repository/ORM scope and final mutation/read. Classify visible controls as authentication, general authorization, ownership, tenant or role. Record confidence and unknowns per layer. Inheritance, router mounting, dependency injection, Spring interceptors, Django middleware, Rails controller filters, Laravel policies and ORM default scopes are common sources of false "missing check" reports.

Compare semantically equivalent siblings: same resource and effect, not merely a similar pathname. A discrepancy is meaningful when the secure siblings converge on one control and the outlier reaches the same protected operation without an equivalent centralized guarantee. Create a source Observation stating the invariant, outlier, secure sibling, and refuting check. Promote only to a Lead until applicability and protected effect are confirmed.

Decision path: if entry point cannot be resolved, improve route extraction; if handler is resolved but control is UNKNOWN, inspect configuration and direct callees; if a central service/repository guarantees ownership, reject; if the outlier bypasses it and maps to a deployed endpoint, form an A/B hypothesis; then use two Broker requests with named configured principals. A 404 may be secure behavior, but compare response body, timing-insensitive status and protected state without enumeration. Stop after the smallest differential resolves ownership.

Evidence should include source commit, file/symbol, secure sibling, full redacted request/response for Account A and B, runtime mapping confidence, and demonstrated protected data/action. Remediate at the shared service/repository mutation boundary so alternate routes inherit the control.
