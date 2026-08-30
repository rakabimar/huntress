---
name: research-loop
description: Drive the observe → hypothesize → predict → test → compare → persist cycle with minimal, controlled, evidence-gated experiments. Use continuously; it is the harness's default working cadence.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Research loop (predict / test / compare)

## Purpose
Enforce the harness's default cadence: every claim is predicted, tested with the
*minimal* controlled experiment, compared against the prediction, and persisted.
Observation is data; it becomes a vulnerability only after this loop survives.

## When to use
- Continuously, as the spine connecting every skill. If you are not inside this
  loop you are either scanning-and-shouting or wandering.

## Process
1. **Observe** — read existing evidence, the lead, and `get_hunt_status`.
2. **Hypothesize** — `create_hypothesis` (see `hypothesize`).
3. **Predict** — `create_research_test` with both the confirming and the
   refuting observation recorded.
4. **Test** — run the *least invasive* action that can decide the claim, via the
   broker, and `complete_research_test` with the observation and result
   (`supports` / `rejects` / `inconclusive`).
5. **Compare** — move the hypothesis to `supported`, `rejected`, or
   `inconclusive` via `update_hypothesis`; be willing to reject.
6. **Persist** — `create_evidence` for anything durable; promote only a
   supported hypothesis toward a candidate finding.

## Evidence
Evidence contract:
- A planned test moved to `executed`, with an observation that matches the
  recorded prediction (or an honest mismatch).
- A checkpoint (`save_checkpoint`) after each meaningful step.

## Decision tree

Choose the highest-information permitted next action. If a result refutes the
hypothesis, reject it rather than spending more budget. If repeated results are
inconclusive, rotate to another Lead. If evidence weakens, do not let sunk cost
justify another request. If the next differentiating action is ASK, checkpoint
and pause; if no differentiating action remains, stop.

## False positives
- "I got a weird response" without a prior prediction is not a test result — it
  is an observation waiting for a hypothesis.

## Stop conditions
- Policy requires approval for the action and none is recorded → stop and record
  the request via the approval flow.

## Example
Following `hypothesize`, run the single read-only request that distinguishes
"redirect honored" from "redirect rejected," record the actual response, and set
the hypothesis + test state accordingly.
