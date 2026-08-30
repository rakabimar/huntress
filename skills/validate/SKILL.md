---
name: validate
description: Take the validator stance — attempt to disprove a candidate finding adversarially (intended behavior? duplicate? excluded by policy? reproducible from evidence?). Use against every candidate before it is called validated.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Validate (Validator stance)

## Purpose
Answer *"can I disprove this?"* — actively argue against a candidate finding:
is it intended behavior, a duplicate, excluded by policy, or not reproducible
from the recorded evidence? Only a finding that survives adversarial review is
promoted to `validated`.

## When to use
- Immediately after the deterministic validation gate passes, on every candid
  finding.
- As a cold re-review before `report` — validation is not a one-time event.

## Process
1. Re-run the deterministic gate (`harness finding validate`).
2. Argue each refutation in turn and record the verdict via
   `findings/validation.assess_finding`:
   - Intended behavior? (check the feature's documented intent)
   - Duplicate? (search existing findings/leads for the same asset+root cause)
   - Excluded by policy/ROE? (re-check `policy_preflight`)
   - Reproducible from evidence? (can a third party follow the stored steps?)
3. Only `validated` findings may advance toward PoC/report.

## Evidence
- A `ValidationVerdict` with the refutations examined and survived (or the
  finding killed/rejected at this gate).

## False positives
- Confirmation bias: assume you are wrong, hunt for the reason the finding is
  not real, and only accept it when you genuinely fail to find one.

## Stop conditions
- Any refutation succeeds → reject/kill the finding; do not paper over it.

## Decision tree and tool selection

If the evidence bundle is incomplete, return `inconclusive`. If a policy,
intended-behavior, duplicate, or reproducibility refutation succeeds, kill the
candidate. Otherwise use the role-bound independent validator launcher and
record its structured verdict. Never use human adjudication from a researcher
or specialist session and never validate a finding created by the same session.
