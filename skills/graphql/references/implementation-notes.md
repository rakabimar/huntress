# Implementation notes

Apollo/GraphQL.js: context authentication, resolver wrappers/directives, DataLoader cache keys including tenant, and subscription transport auth. Graphene/Strawberry/Ariadne: resolver/context permissions and ORM queryset scoping. GraphQL Java/Spring: instrumentation/directives, method security, DataLoader, and WebSocket interceptors. Rails/Laravel equivalents require per-resolver/policy coverage.

Common failures: authorizing only root query, loading by global ID without tenant scope, sharing DataLoader cache across principals, accepting protected input fields, checking subscription at connect but not event delivery, and maintaining a weaker legacy resolver.

Remediate with policy enforcement at service/resolver boundaries, tenant-aware loaders/cache keys, typed input allowlists, per-event filtering, bounded complexity controls, and resolver-matrix tests using multiple principals.
