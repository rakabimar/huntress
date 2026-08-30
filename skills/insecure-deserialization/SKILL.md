---
name: insecure-deserialization
description: Use when a target deserializes untrusted input into native objects (Java/PHP/.NET) or signed/encrypted tokens that can be tampered to trigger type confusion.
maturity: stable
risk_class: R2
category: crypto-config
cwe: [502]
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [source-dataflow-analysis, authentication, command-injection]
primary_triggers: [native object deserialization, polymorphic type, serialized blob]
secondary_triggers: [gadget reachability, signed object, message queue, plugin input]
negative_triggers: [safe data-only parser, rejected signature, dangerous class unreachable]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Insecure Deserialization

## Purpose
Insecure deserialization happens when an application reconstructs objects from attacker-controlled data without validating type or provenance, enabling code execution via gadget chains or logic bypass via tampered tokens. It matters for bug hunting because the same serialized format often appears in cookies, headers, API bodies, and signed blobs, and the flaw frequently hides behind a "trusted" encoding like base64 or a MAC.

## When to use
- Cookies, JWT-like tokens, `__VIEWSTATE`, or base64 blobs that decode into serialized object notation (`O:`, `s:`, `rO0AB`, `Type, Assembly`).
- Endpoints that accept a `Content-Type` like `application/x-java-serialized-object`, `application/octet-stream`, or PHAR/native serialization formats.
- Any place a client-provided value is passed to `unserialize`, `ObjectInputStream.readObject`, `BinaryFormatter`, or a JSON "polymorphic type" resolver.
- Session or pre-auth tokens that are merely signed rather than encrypted, suggesting tamper-and-replay.

## Process
1. Form a falsifiable claim with `create_hypothesis`, e.g. "If I flip the `role` field inside the signed token and resubmit, the app trusts it, crossing an authorization boundary."
2. Capture one baseline response: decode the identifier with a local decoder (never in the target) and note its structure.
3. Predict the observable for both outcomes and record them on a planned test via `create_research_test`.
4. Run the minimal experiment through `send_authorized_http_request` only: resubmit the tampered value and compare response shape or status, avoiding any payload with a real gadget chain.
5. Prove type confusion read-only first (an unexpected class error, stack leak, or reflected class name) before attempting any chain.
6. Record the observation and result with `complete_research_test`, then persist durable artifacts with `create_evidence`.

## Evidence
- `request_response`: the redacted original and tampered request plus the full response proving the parser accepted your modified type or field.
- `observation`: a noted difference in behavior (status code, reflected class name, exception text) between baseline and tampered input.
- `command_output`: output of a local decoder used to confirm structure, with secrets and PII redacted.

## False positives
- A serialized value that decodes but provokes a generic "parse error" means the payload was rejected, not deserialized into an unintended type.
- A reflected class/type name could be an informational error string, not proof the object was instantiated; reproduce with a distinct type to confirm.
- Signed-token tampering that only changes the signature check result is integrity enforcement working as intended, not a deserialization flaw.

## Stop conditions
- `scope_preflight` rejects the target or endpoint — stop before sending anything.
- The experiment requires R3/R4 behavior or approval not recorded as `approved` — stop and wait.
- Proof would require a destructive write, a gadget chain with side effects, or anything that degrades service — stop and report the read-only observation instead.

## Example
A login endpoint on `example.test` returns a cookie that base64-decodes to `O:8:"Session":2:{s:4:"role";s:5:"guest";}`. Baseline: submit the cookie unchanged and record the guest dashboard. Hypothesis: replacing `guest` with `admin` and resubmitting through the broker yields an admin-only response. Tampered request returns the admin panel, demonstrating the boundary was crossed before any gadget chain is attempted.
