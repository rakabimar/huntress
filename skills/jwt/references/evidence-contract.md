# JWT evidence contract

Record token fingerprints, redacted header/claim subset, signer/issuer/key provenance, service and intended token type/audience, valid/invalid baselines, one controlled mutation/substitution, verification result, resulting server principal/tenant/roles, and protected operation. Never persist reusable JWTs, signing keys, refresh tokens, or secret JWKS material.
