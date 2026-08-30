---
name: authn-bypass
description: Compatibility alias for authentication.
maturity: draft
status: deprecated
canonical_skill: authentication
risk_class: R2
category: authnz
cwe: [287]
---

# Authentication bypass compatibility alias

## Purpose
Preserve older routing names without duplicating identity-lifecycle methodology.

## When to use
Never load this alias directly; resolve it to `authentication`.

## Process
Load `authentication` and analyze identity binding, tokens, expiry, replay, state transitions, and alternate channels.

## Evidence
Demonstrate protected identity or action access without the required authentication proof.

## False positives
A public shell, client-side hiding, or cosmetic flag is not an authentication bypass.

## Stop conditions
Apply the canonical skill's lockout, victim-account, scope, and policy stops.
