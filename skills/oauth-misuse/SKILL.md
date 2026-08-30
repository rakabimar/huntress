---
name: oauth-misuse
description: Compatibility alias for oauth-oidc.
maturity: draft
status: deprecated
canonical_skill: oauth-oidc
risk_class: R2
category: authnz
cwe: [287]
---

# OAuth misuse compatibility alias

## Purpose
Preserve older routing names without duplicating federation methodology.

## When to use
Never load this alias directly; resolve it to `oauth-oidc`.

## Process
Load `oauth-oidc` and map actors, transaction bindings, client, issuer, redirect, and local-account identity.

## Evidence
Demonstrate an attacker-controlled token, identity, redirect, or account-binding outcome.

## False positives
A protocol deviation without a practical security outcome is not a finding.

## Stop conditions
Apply the canonical skill's victim-token, scope, and approval stops.
