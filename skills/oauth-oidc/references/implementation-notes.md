# Implementation notes

Trace initiation state storage, callback parameter handling, token endpoint client authentication/PKCE, issuer discovery, token verification, UserInfo reconciliation, and local account lookup/link. Server frameworks may hide secure defaults; verify configured redirect patterns, proxy/base URL handling, and multi-tenant client selection.

Account linking deserves a separate state machine: local session recently re-authenticated → external transaction initiated for this account → issuer+subject authenticated → uniqueness checked → link committed → old links/recovery handled. Never select the local target account from attacker-controlled email or callback state.

Remediate with exact registered redirects, transaction-bound state/nonce/PKCE, issuer-aware response handling, strict token audience/type checks, stable issuer+subject identity keys, recent re-authentication for linking, and tests across every IdP/client variant.
