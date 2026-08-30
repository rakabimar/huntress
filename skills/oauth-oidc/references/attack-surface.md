# Flow and integration attack surface

Authorization Code: redirect URI exactness/registration, state transaction, code recipient, single use. PKCE: challenge creation, verifier binding, downgrade/omission, plain method policy. OIDC: nonce, issuer, audience/azp, token type, UserInfo subject consistency. Legacy implicit: fragment/token leakage and substitution only where still deployed.

Multi-IdP/federation: issuer mix-up, authorization response injection, client confusion, discovery trust, identity collisions, and local-account linking/unlinking. Mobile: custom scheme ownership, universal/app links, browser/session mix-up, and code interception mitigated by PKCE. Open redirects matter when they preserve a code/token or bypass registered redirect rules.

Test one controlled transaction with two synthetic accounts/browsers/IdPs where possible. Do not infer takeover from missing state/nonce or permissive redirect syntax without demonstrating attacker control of the resulting account/code/token.
