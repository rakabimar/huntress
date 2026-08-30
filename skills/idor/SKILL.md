---
name: idor
description: Compatibility alias for api-authorization.
maturity: draft
status: deprecated
canonical_skill: api-authorization
risk_class: R2
category: authnz
cwe: [639]
---

# IDOR compatibility alias

## Purpose
Preserve older routing names without duplicating authorization methodology.

## When to use
Never load this alias directly; resolve it to `api-authorization`.

## Process
Load `api-authorization` and follow its subject/object/action/tenant decision model.

## Evidence
Use the canonical skill's same-object, same-operation principal comparison.

## False positives
A predictable or known identifier alone is not an authorization flaw.

## Stop conditions
Apply the canonical skill's scope, policy, impact, and intended-visibility stops.
