# Implementation notes

Look for generic `decode` calls used instead of verified parsing, algorithm lists inferred from headers, key callbacks that concatenate kid into paths/queries, remote JWK URLs from token input, and verification options omitting issuer/audience/type. Library defaults change; record exact library/version and configured options.

Node libraries often separate decode and verify; Java/Spring resource servers require issuer/audience configuration beyond signature; Python libraries may require explicit algorithms and claim requirements; Go parsers need method/type assertions; gateway validation does not ensure downstream code uses the validated principal rather than raw claims.

Remediate by configuring the verifier from trusted service policy: fixed algorithms, trusted issuer/key source, bounded kid, exact audiences/token types, required claims, subject/tenant lookup against current server state, short lifetimes, replay/refresh controls, and shared conformance tests across services.
