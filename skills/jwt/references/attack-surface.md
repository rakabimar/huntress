# JWT verification attack surface

- Algorithm selection: hard allowlist versus header-driven choice; unsigned tokens; asymmetric/symmetric confusion.
- Key trust: local key, issuer JWKS, cache, kid lookup, filesystem/database key IDs, jku/x5u fetch, embedded JWK, certificate chain and hostname policy.
- Semantic validation: exact issuer, audience arrays, authorized party/client, typ/token_use, access versus ID token, user versus service token.
- Claim binding: subject lookup, tenant/workspace, roles/scopes, account state, session/device, delegation.
- Time/lifecycle: exp, nbf, skew, jti/replay, refresh rotation/reuse, logout/revocation.
- Multi-service consistency: gateway verifies but backend re-parses; one service accepts another audience/type; old/mobile API uses different library/config.

Tool choice: decode locally without persisting values; inspect source verifier configuration; query public JWKS/discovery only in scope; use an authorized fixture for remote-key behavior; Broker replay one controlled token differential. Never brute-force signing secrets.
