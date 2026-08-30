# JWT false positives

Decoding is not verification. Reject algorithms advertised but not accepted, unsigned/tampered tokens rejected, kid/jku fields parsed but constrained to trusted keys, claim changes rejected downstream, expected clock skew, public JWKS exposure, and an access token accepted only by its intended audience. Parser errors and response differences without protected identity/capability are not bypasses.
