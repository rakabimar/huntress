# Evidence, false positives, impact, and remediation

Evidence must prove the exact protected effect and retain a refuting control. False positives: A single consistent documented first/last/array rule across all components, duplicates rejected, harmless application array semantics, WAF block with no downstream difference, and duplicate JSON impossible from the actual client path.

Impact is limited to the demonstrated boundary. Remediation: Define one canonical parser/normalization contract, reject ambiguous duplicates for security fields, validate/authenticate the exact canonical representation consumed downstream, preserve parameter types, align cache/WAF/backend parsing, and regression-test raw bytes end-to-end.
