# Implementation notes

- Express/Nest/Fastify: route middleware may differ from service guards; check loaders that call `findById` before tenant predicates and DTOs exposing protected fields.
- Django/DRF: queryset scoping and object permissions are separate; custom actions, serializers, and `get_object` overrides often diverge.
- Spring: URL rules do not replace method security; proxying/self-invocation and repository calls can bypass annotations.
- Rails/Laravel: policy/scopes must cover custom collection actions, jobs, exports, route-model binding, and mass-assigned attributes.
- Go: middleware commonly authenticates while handlers/services must still enforce tenant/owner predicates.
- GraphQL: root authorization does not automatically cover nested resolvers, loaders, mutations, global nodes, or subscriptions.

Prefer invariant-oriented remediation: centralize object/tenant policy in the service/data access operation, make queries include tenant/ownership predicates, deny protected fields at input schemas, and regression-test every sibling method/version/resolver with the principal matrix.
