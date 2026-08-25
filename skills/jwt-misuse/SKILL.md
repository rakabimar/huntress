---
name: jwt-misuse
description: Use when a target issues or accepts JSON Web Tokens (JWT) and you suspect weak signing, alg confusion, or missing verification
maturity: draft
risk_class: R2
category: authnz
cwe: [347]
---

# JWT Misuse

## Purpose
JWTs are signed (and optionally encrypted) tokens whose security depends on the verifier enforcing the algorithm and key the issuer chose. When the verifier trusts the token's own `alg` header, accepts `none`, or a weak/shared HMAC key, an attacker can forge tokens that grant unauthorized access. For bug hunting this is a high-value authn/authz boundary: a forged JWT often escalates privileges or bypasses authentication entirely.

## When to use
- A request carries an `Authorization: Bearer <jwt>` header, or a cookie/blob that decodes as three base64url segments separated by dots.
- Decoding the header shows `alg` values other than a strong asymmetric pair (e.g. `none`, `HS256` where `RS256` is expected, or hard-coded secret hints).
- The service echoes claims (`sub`, `role`, `admin`, `exp`) back in a way that suggests it derives authorization from the token.

## Process
1. Observe: capture a legitimate JWT and decode its header/payload (base64url, no key needed). Note `alg`, `kid`, `typ`, and the claims the app seems to enforce.
2. Form a falsifiable hypothesis with `create_hypothesis`, e.g. "the verifier honors the token's self-declared `alg`, so a token re-signed with `none` on the same header/payload will be accepted."
3. Predict the observable: the forged token returns the same status/data as a valid one, while an unrelated mutation is rejected.
4. Run the minimal controlled experiment through `send_authorized_http_request` only (never raw curl/nmap/sqlmap). Replay the legitimate request, swapping the token for your crafted one.
5. Record the observation and result via `complete_research_test`; persist artifacts with `create_evidence`.
6. Compare against the prediction; promote a supported hypothesis toward a candidate finding only if the forged token demonstrably crossed a boundary.

## Evidence
- `request_response`: the crafted JWT sent and the server's verdict, redacted of session secrets and PII.
- `observation`: decoded header/payload showing the tampered `alg` and the resulting authorization change.
- `command_output`: local token-forging tooling output (e.g. decoded segments or a locally generated token), never a target credential or secret.

## False positives
- A token that decodes with `alg: none` in your tooling but the server still rejects it — the verifier is pinning algorithms; that is secure behavior, not a finding.
- Authz changes that actually arise from an unrelated cookie, session value, or cached state rather than the token itself.
- `alg` in the token is `HS256` and the server still checks a strong shared secret — confusion only works when the key is weak, public, or the verifier treats HMAC and asymmetric keys interchangeably.

## Stop conditions
- `scope_preflight` rejects the target, or `policy_preflight` disallows token crafting against it — stop.
- Proof requires R3/R4 action (mass issuance, destructive writes, forcing a keyset update) and no approval is recorded — stop.
- Demonstrating the effect would require hitting every endpoint or a large token-cracking effort — stop; a single read-only forged token is enough.

## Example
A local API at `http://localhost:3000` accepts `Authorization: Bearer <jwt>` and returns `{"role":"admin"}`. Decode a normal token to confirm `alg: RS256`. Craft a variant with the same payload but header `{"alg":"none","typ":"JWT"}`, strip the signature segment, and send it via `send_authorized_http_request`. If the server still returns the admin resource, the hypothesis is supported; if it rejects, the verifier is pinning algorithms and the lead closes.