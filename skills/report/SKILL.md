---
name: report
description: Write a creditable report that separates demonstrated facts from interpretation, passes deterministic QA, and is ready for human approval. Use after a finding reaches validated/poc_ready.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Report (Reporter stance)

## Purpose
Answer *"is this writable as a creditable report?"* — produce a report a triager
can act on: affected asset, weakness (CWE), severity + CVSS vector,
prerequisites, steps to reproduce, PoC, expected vs. actual, security impact
(what was *demonstrated*), evidence, and remediation.

## When to use
- When a finding reaches `validated` (or later) and is ready to be written up.
- Never before: a report without a validated finding is an opinion.

## Process
1. Structuring rule — always separate **demonstrated facts** from
   **interpretation** (spec §61).
2. Include every required section; base impact only on what was demonstrated,
   not on what "probably" happened.
3. Run `harness report qa`; fix every failing check before considering it ready.
4. Leave the finding at `report_ready` / `qa_passed` — **never** submit. Human
   approval (`human_approved`) is the only state that authorizes submission, and
   you never reach it yourself.

## Evidence
- The report file under the program's `reports/` dir, plus `request_response`
  evidence for every HTTP claim.

## False positives
- Do not fabricate evidence or pad impact to pass QA — that is a termination-
  level violation.
- "Expected vs. actual" must reflect the controlled experiment, not a story.

## Stop conditions
- `harness report qa` fails and cannot be honestly fixed → do not proceed to
  submission; the finding stays gated.
- Any secret or target-PII remains in the report → stop, redact, retry.

## Example
For the validated open-redirect finding, write findings/open-redirect.md with
PoC = the single broker request/response reproducing it, severity from
`harness cvss`, remediation from the `defend` stance, then `report qa`.