# JWT verifier methodology

Map trusted verifier configuration before mutation: service, accepted token class, fixed algorithms, issuer, key source, audiences, required claims, and authorization mapping. Capture valid and clearly invalid controls. Select one implementation-supported assumption and change only that header/claim/token context.

Remote key tests use an authorized fixture and prove key provenance, not internal reach. Claim tests require a legitimately signed or otherwise applicable controlled token; editing base64 then observing signature rejection proves enforcement. Compare services only when the same token is presented to distinct relying parties.
