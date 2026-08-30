# GraphQL attack surface

- Queries: node/global ID ownership, nested relation traversal, field-level redaction, search/filter tenant predicates.
- Mutations: input object protected fields, resolver/service authorization, alternate mutation parity, idempotency and workflow state.
- Aliases/fragments/batches: per-item policy, rate/cost accounting, error attribution; use two operations, never amplification.
- Subscriptions/WebSockets: upgrade/connection auth, subscribe-time object policy, event-time role/tenant revalidation, channel filtering, logout/revocation.
- Scalars/uploads: URL/file/path/parser semantics, coercion differences, multipart mappings.
- Complexity: depth, breadth, recursive fragments, list cardinality, field weights, persisted/allowlisted queries. Production DoS testing is denied.
- Parity: REST route protected while GraphQL service call omits policy, or vice versa.

Whitebox: find schema/resolver definitions, context construction, loaders, directives/decorators, service calls, and subscription publishers. A schema match is a SourceObservation until resolver reachability and effect are established.
