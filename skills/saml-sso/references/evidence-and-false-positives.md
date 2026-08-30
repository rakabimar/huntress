# Evidence, false positives, impact, and remediation

Evidence must prove the exact protected effect and retain a refuting control. False positives: Unsigned outer response with correctly signed selected assertion, valid IdP-initiated flow by design, accepted certificate rollover, harmless RelayState, expired/replayed assertions rejected, and XML parser differences without identity effect.

Impact is limited to the demonstrated boundary. Remediation: Use maintained SAML libraries, validate signature/reference on the exact assertion consumed, trust configured IdP/certs, require audience/recipient/destination/time and request correlation where applicable, replay prevention, stable issuer+subject mapping, explicit attribute allowlists, and recent auth for linking.
