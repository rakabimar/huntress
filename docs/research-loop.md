# The research loop

The default working cadence (spec §4) is hypothesis-driven, not scan-and-shout.
Repeat until a lead closes or a checkpoint hands off:

1. **Observe** — read existing knowledge, the lead, and captured evidence. Do
   not mutate anything yet.
2. **Hypothesize** — write a *falsifiable* claim: *"If I do X as account A,
   then Y will happen, which crosses boundary Z."* Record it
   (`hypothesis create`).
3. **Predict** — state the observable you expect *if true* and the observation
   that would *refute* it. Record both on the planned test
   (`test add` with expected-if-true / expected-if-false).
4. **Test** — run the *minimal* controlled experiment through the broker.
   Record the observation and result (`test complete`).
5. **Compare** — does the observation match the prediction, refute it, or land
   in between? Move the hypothesis status accordingly. Be willing to reject.
6. **Persist** — write evidence metadata, the observation, and (only when
   warranted) promote a supported hypothesis toward a *candidate* finding.

Then **stop and record** — a checkpoint after each meaningful step is the
difference between a research record and a memory.

## Why this order matters

- **Prediction before test** makes a result falsifiable instead of
  post-hoc storytelling.
- **Minimal-step tests** keep impact low (prime directive 5).
- **Persist-before-move-on** keeps state durable on disk, so another runtime can
  resume via `checkpoint latest`.

## The specialist stances

Rotate through these roles explicitly; do not collapse into a single "find bugs"
pass:

| Stance | Question it owns | Drives |
|---|---|---|
| Recon/Observer | What surface exists? | enumeration, fingerprinting |
| Attacker | Where would I break it? | injection, authn/authz, business-logic, … |
| Defender | How would I fix/defend it? | hardening, threat-model |
| Triager | Would a platform pay for this? Is it real, in scope, impactful? | triage, severity |
| Validator | Can I *disprove* this candidate? | validation, adversarial review |
| Reporter | Is this writable as a creditable report? | report-writing, QA |

Each stance maps to a specialist agent-spec (see [agent-specs](agent-specs.md)).