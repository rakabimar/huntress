# Permission model

Represent authorization as a role-action-context matrix. Context includes organization, workspace, feature entitlement, delegation source, invite state, impersonation state, and time. Separate:

- authentication: who the principal is;
- API object authorization: whether it may act on one resource;
- access control: whether it possesses the capability/function at all;
- business logic: whether the capability may be used in the current workflow state.

Trace effective permission provenance: direct role → inherited organization/team role → temporary grant/delegation → feature gate → deny override. Test revocation and expiry at the authoritative server, not the UI.

A route is not a capability until the protected operation occurs. A feature flag may hide or license functionality, but it becomes a security boundary only if it controls protected data/action and the backend trusts it.
