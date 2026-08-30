# Implementation notes

Implementation notes: compare Express/Nest middleware, Django permissions/querysets, Spring URL/method security, Rails/Laravel policies, Go handler/service guards, GraphQL resolver wrappers, and WordPress REST permission_callback/current_user_can. A WordPress nonce is never the capability check. Prefer source authorization analysis for sibling inconsistency, then route to api-authorization or access-control for runtime testing.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
