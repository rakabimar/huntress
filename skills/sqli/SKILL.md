---
name: sqli
description: Compatibility alias for sql-injection.
maturity: draft
status: deprecated
canonical_skill: sql-injection
risk_class: R2
category: injection
cwe: [89]
---

# SQLi compatibility alias

## Purpose
Preserve older routing names without duplicating injection methodology.

## When to use
Never load this alias directly; resolve it to `sql-injection`.

## Process
Load `sql-injection` and reason from input through query construction to a reachable SQL parser boundary.

## Evidence
Use the canonical skill's controlled boolean, error, or timing differential.

## False positives
A syntax error or latency anomaly alone does not demonstrate injection.

## Stop conditions
Apply the canonical skill's policy and minimal read-only proof limits.
