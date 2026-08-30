# Implementation notes

Inventory route middleware, decorators/annotations, policy engines, service-layer guards, and database row filters. A check at only one layer is fragile when jobs, GraphQL, CLI/admin adapters, or alternate API routes call the service directly.

Framework signals: Express/Nest route guard arrays; Django permissions and queryset scoping; Spring Security URL versus method rules; Rails Pundit/CanCan scopes; Laravel gates/policies/middleware; WordPress `current_user_can` and REST `permission_callback`. In WordPress, nonce verification never substitutes for capability enforcement.

Remediate at the capability's authoritative service boundary, encode deny precedence and explicit inheritance, rotate sessions/tokens on privilege change, and regression-test the role-action matrix including alternate methods and background execution.
