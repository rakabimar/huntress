---
name: attack
description: Take the attacker stance — for each surface, ask where it would break (injection, authn/authz, business logic, file handling, CSRF, SSRF) and turn the best candidate into a hypothesis. Use after observe and before any test.
maturity: stable
risk_class: R1
category: core
cwe: []
---

# Attack (Attacker stance)

## Purpose
Answer *"where would I break it?"* — enumerate the *plausible* failure modes per
surface and select the one most likely to cross a real boundary, ready to hand
to a falsifiable hypothesis. This is adversarial *thinking*, not exploitation.

## When to use
- After `observe` has produced a concrete surface list.
- When a surface invites a specific technical skill (an upload form → file
  upload; a `/user/{id}` route → IDOR; a search box → injection).

## Process
1. For each surface, list candidate weaknesses using the technical skill library
   (see `manifest.yaml` router to pick the right one).
2. Rank by: likelihood of the bug, reachability (auth required?), and impact of
   the boundary crossed. Prefer the least invasive demonstration.
3. Do **not** run the attack yet; hand the top candidate to `hypothesize` and
   let `research-loop` test it under policy control.

## Evidence
- The reasoning lives in the hypothesis's rationale; the actual test artifacts
  are created by `research-loop`, not by this stance directly.

## False positives
- "This is how I'd break it" is speculation until a hypothesis predicts the
  effect and a test reproduces it.
- Knowing the attack class is not proof the app is vulnerable to it.

## Stop conditions
- The candidate would require an R3/R4 action with no approval → stop at
  hypothesis, never attempt it.

## Example
Surface: login form posting to `/login`. Candidates: SQLi in username, response
flaw in redirect, username enumeration. Choose the one with the best
impact/effort trade-off, and write its hypothesis.