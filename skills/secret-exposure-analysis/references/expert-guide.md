# Expert guide

## Evidence contract

Store only secret type, location, fingerprint, redacted preview, exposure
history, environment, permission clues, rotation/validity status, and a safe
refuting condition. Never persist or authenticate with the plaintext value.

Mental model: secret-like string → candidate type/fingerprint → real or fixture → live/revoked unknown → environment/service → scope/permissions → public exposure → minimal safe validation → impact. Attack surface includes source/history, CI config/logs, mobile/client bundles, examples/tests, generated artifacts, and leaked cloud/provider credentials. Detector confidence is not validity.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

The model receives type, location, fingerprint, redacted preview and context—never the raw value. Classify test/example fixtures, generated placeholders, public identifiers, encrypted material and detector false matches before considering validity. Then determine current versus historical exposure, public availability, likely environment/service, scope and permission. Do not authenticate, call provider APIs or store plaintext automatically. Any tightly controlled validity check requires policy and the secret-resolution seam.

Use a redacting scanner for breadth, git history for lifetime/public exposure, source context for environment and permission clues, and the Broker only if an explicitly allowed minimal validation exists. Reject obvious fixtures, revoked/rotated history, non-secret public keys/IDs and inaccessible private history. Evidence uses fingerprints and redacted artifacts. Remediation includes revocation/rotation, history cleanup where useful, least privilege and preventing recurrence; removing the string alone does not invalidate a copied credential.
