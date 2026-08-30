# Expert guide: object binding

## Mental model
Model client input schema→decoder→DTO/serializer→object mapper→domain model→persistence. The security question is which properties the client is authorized to set at this operation/state, not whether arbitrary JSON is accepted.

## Attack surface and methodology
Inventory create/update/patch, nested relationships, GraphQL input objects, form model binding, admin/mobile versions, and serializer read/write asymmetry. Focus on owner/tenant, role/permissions, status/workflow, balance/price, visibility, approval, and server-generated identifiers. Add one protected property to a normal request; then read authoritative state and exercise the capability only if needed. Compare create versus update and sibling DTOs.

Decision tree: echoed only → observation; ignored/recomputed → reject; persisted but unused/harmless → low-signal observation; protected durable property changes and affects a boundary → support. Use http-parameter-pollution only when duplicate-parser semantics, not object binding, cause the issue.
