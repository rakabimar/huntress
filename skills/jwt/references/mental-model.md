# JWT trust model

A relying service performs distinct decisions: parse token → choose allowed algorithm → select trusted key → verify signature → validate issuer/audience/type/time → bind subject/tenant/claims → authorize operation. Passing one stage says nothing about later stages.

Classify controllable material:

- header: alg, kid, jku, x5u, jwk, typ;
- claims: iss, aud, sub, tenant, roles/scopes, token_use, azp, exp, nbf, iat, jti;
- context: endpoint/service, access versus ID token, user versus service token, refresh versus bearer use.

Only test assumptions the implementation exposes. Algorithm confusion needs asymmetric/symmetric verifier ambiguity; kid issues need attacker influence over lookup; jku/x5u/JWK issues need untrusted key provenance; claim issues require a valid signature accepted under the wrong semantic context.

Decision: token merely decodes → no security claim; mutation fails signature → control works; substituted token accepted but grants no protected capability → observation; accepted as wrong subject/tenant/role/audience → supported.
