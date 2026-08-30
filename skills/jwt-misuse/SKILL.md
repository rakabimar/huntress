---
name: jwt-misuse
description: Compatibility alias for jwt.
maturity: draft
status: deprecated
canonical_skill: jwt
risk_class: R2
category: authnz
cwe: [347]
---

# JWT misuse compatibility alias

## Purpose
Preserve older routing names without duplicating token-verifier methodology.

## When to use
Never load this alias directly; resolve it to `jwt`.

## Process
Load `jwt`, infer the verifier trust model, and test only applicable assumptions.

## Evidence
Use a controlled token mutation that demonstrably changes an authentication or authorization result.

## False positives
Decoding a JWT, or observing a claim, does not prove acceptance or forgery.

## Stop conditions
Apply the canonical skill's policy, replay, and impact limits.
