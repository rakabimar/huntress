---
name: crypto-misuse
description: Use when an endpoint or feature appears to use cryptography (encryption, tokens, cookies, hashes) and may rely on weak/hardcoded/ECB ciphers, predictable IVs, missing MAC, or a weak PRNG.
maturity: draft
risk_class: R1
category: crypto-config
cwe: [327]
---

# Cryptographic Misuse

## Purpose
Cryptographic misuse is the use of a correct algorithm in a broken way: hardcoded or default keys, ECB mode, reused or predictable IVs/nonces, encryption without authentication (missing MAC), or secrets minted from a weak PRNG. It matters because it often breaks confidentiality or integrity silently while the code "looks encrypted." Detecting it usually requires only observation of behavior or readable artifacts, not cracking ciphertext.

## When to use
- Endpoints return cookies, tokens, or IDs that look base64/hex-encoded and change predictably between requests.
- The app exposes downloadable source, config, or an error trace revealing cipher names, keys, IVs, or seeds.
- Auth or anti-tamper features rely on custom crypto rather than a standard library default.
- Two identical inputs produce identical ciphertext (a sign of ECB or static IV).

## Process
1. Form a falsifiable hypothesis with `create_hypothesis`: e.g. "If I request the same plaintext twice, the token/IV will be identical, so encryption lacks freshness."
2. Confirm scope and policy first; do not proceed otherwise.
3. Run the MINIMAL controlled experiment through `send_authorized_http_request` only, never raw curl/nmap/sqlmap. Prefer read-only requests and a single, small, non-destructive mutation.
4. Predict the observable that would confirm the hypothesis and the observation that would refute it, then record both.
5. Execute and log the result with `complete_research_test`; capture durable artifacts with `create_evidence`.
6. Compare observed vs. predicted; mark the hypothesis supported or rejected rather than forcing a result.

## Evidence
- `request_response`: full redacted request and response showing identical or repeated ciphertext/IV across a controlled input change.
- `observation`: notes on token length, format, entropy, and whether output is stable across requests.
- `command_output`: output from reading static config/source that reveals the cipher, mode, key, or seed.
- Redact all secrets and PII from stored evidence and previews.

## False positives
- Deterministic hashes or HMACs (e.g. session IDs) may be stable by design without being broken — check whether a MAC is present.
- Base64 or hex encoding is not encryption; encoded data alone does not imply weak crypto.
- Reused nonces under GCM are a real flaw, but a single coincidental repeat is not proof — seek reproducible prediction.
- AES-CBC with a proper random IV looks like random keystream; do not claim ECB without block-structural evidence.

## Stop conditions
- `scope_preflight` rejects the target or action — stop immediately.
- The proof would require R3/R4 action or an approval that is not recorded — stop.
- The demonstration would be destructive, denylist-impacting, or require mass exfiltration — stop.
- You cannot tell whether an action is authorized — resolve to no.

## Example
On `https://api.example.test`, a "remember me" cookie is base64 of the user id plus an 8-byte tail. Hypothesis: the tail is a static IV or ECB residue. Predict two logins of the same account yield an identical tail if so. Send two authenticated requests via the broker and compare only the cookie strings; identical non-cookie tail supports the claim, differing tails refute it. Record the two redacted responses as `request_response` evidence and the conclusion as an `observation`.