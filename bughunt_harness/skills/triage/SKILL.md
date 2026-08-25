name: triage
description: Take the triager stance — decide whether a candidate is real, in scope, reproducible, and impactful enough for a platform to pay for. Use before promoting or reporting any finding.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Triage (Triager stance)

## Purpose
Answer *"would a platform pay for this?"* — apply the filters a real triager
uses: is it real (not intended behavior), in scope, not a known duplicate, and
does the impact actually match the claimed severity?

## When to use
- Before promoting a supported hypothesis to a candidate finding.
- Before writing a report, as the severity reality-check.
- When deciding whether a finding is worth further (possibly riskier) validation.

## Process
1. Verify scope via `scope_preflight` — out-of-scope always loses.
2. Verify the effect is not intended behavior (read the docs/feature intent).
3. Confirm reproducibility from the recorded evidence.
4. Score with `harness cvss` (never your own arithmetic); map to severity and
   note every uncertain metric.
5. State the *worst-case demonstrated* impact and the *prerequisite* attack
   preconditions honestly.

## Evidence
- The deterministic validation gate (`harness finding validate`) and the CVSS
  vector string, both recorded on the finding.

## False positives
- "It looks bad" is not impact. A reflected XSS without a victim/context or an
  IDOR on public data is often a low/no-severity finding.
- Do not inflate severity to make the report pass — that is a reported-violation
  under the harness's never-do list.

## Stop conditions
- `scope_preflight` rejects → drop the candidate, do not report.
- Severity cannot be honestly defended → down-rank or reject, do not fabricate.