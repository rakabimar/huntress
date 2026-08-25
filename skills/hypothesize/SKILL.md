---
name: hypothesize
description: Turn a vague lead into a specific, falsifiable cause-to-effect claim with a defined boundary to cross. Use whenever a lead exists but a concrete, testable prediction does not yet.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Hypothesize (hypothesis craft)

## Purpose
Convert *"this is worth a look"* into *"if I do X as account A, then Y will
happen, which crosses boundary Z."* A hypothesis is falsifiable: it states the
observation that would *refute* it, not merely the one that would confirm it.

## When to use
- A lead has been observed but has no concrete cause→effect claim yet.
- You find yourself about to "poke at" a feature without knowing what result you
  expect.

## Process
1. Name the **actor** (`as X`), the **action** (`I do Y`), the **effect**
   (`then Z happens`), and the **boundary** (`which crosses W`).
2. Check the boundary is a real security boundary (authN, authZ, scope,
   confidentiality, integrity, availability), not just "the app behaves oddly."
3. Record it with `create_hypothesis` and attach it to its lead.
4. Push the prediction into the next step: write a planned test with
   `create_research_test` that records the expected-if-true and expected-if-false.

## Evidence
- A hypothesis record linked to a lead.
- A planned research test whose `expected_if_true` and `expected_if_false` are
  both filled in — a hypothesis without an expected-false case is not falsifiable.

## False positives
- Correlations ("the 404 page shows the stack trace") are not yet causal claims.
- A hypothesis that "will be true in every case" has no refuting observation —
  tighten it.

## Stop conditions
- You cannot state how the claim could be disproven → do not record it as a
  hypothesis yet; go back to `observe`.

## Example
"If I submit the `?redirect=` parameter on `https://app.example.test/login` as an
unauthenticated user, then the server will honor an external URL, which crosses
the open-redirect boundary. Refuting observation: the parameter is ignored or
the URL is validated against a strict allow-list."