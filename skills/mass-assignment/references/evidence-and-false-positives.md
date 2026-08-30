# Evidence, false positives, impact, and remediation

Evidence includes allowed input baseline, one added property, declared versus persisted value, authoritative reread, principal/tenant/state, and protected effect. False positives: response echo, unknown-field preservation in schemaless metadata, server recomputation, admin-only endpoint used by admin, and a field never consulted.

Impact names the exact protected property/capability. Remediate with operation-specific input DTO allowlists, server-derived owner/tenant/role/state, separate read/write schemas, nested policy enforcement, and tests that reject protected fields.
