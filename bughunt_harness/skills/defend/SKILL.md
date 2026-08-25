name: defend
description: Take the defender stance — explain how a suspected weakness would be fixed or hardened, and use that to sharpen impact and remediation. Use when writing remediation or sanity-checking severity claims.
maturity: stable
risk_class: R0
category: core
cwe: []
---

# Defend (Defender stance)

## Purpose
Answer *"how would I fix or defend it?"* — articulate the countermeasure for a
suspected weakness. A clear statement of the defense forces an honest statement
of the impact; a weakness with no reasonable defense is either trivial or you
have not understood it.

## When to use
- While drafting remediation for a finding.
- To sanity-check a severity claim: if the "high severity" weakness is trivially
  mitigated, the demonstrated impact may be overstated.

## Process
1. State the root cause in one sentence (what code/behavior is wrong, not just
   the symptom).
2. Give the layered fix: input validation, output encoding, authZ check, safe
   deserialization, CSP, etc., at the correct layer.
3. Map the fix back to the CWE and note detection/protection coverage (WAF,
   canary, monitoring) where relevant.

## Evidence
- The remediation section of the report; no separate evidence record is needed
  for the stance itself.

## False positives
- Do not mistake "this is fixable" for "this is not a real finding." Defender is
  a lens, not a triage downgrade.

## Stop conditions
- Remediation would require touching production or sending instructions to the
  target → stop at describing it in the report; never apply it.