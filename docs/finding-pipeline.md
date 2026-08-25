# Finding pipeline

Findings progress through an evidence-gated, human-terminated pipeline. The
transition map is in `bughunt_harness/state/constants.py`; `harness finding`
and the MCP finding tools drive it.

```
candidate (1) → validation (2) → validated (3) → poc_ready (4) → scored (5)
             → report_ready (6) → qa_passed (7) → human_approved (8)
```

1. **candidate** — a supported hypothesis has become a named candidate; you have
   a plausible cause, affected asset, and boundary crossed.
2. **validation** — the deterministic gate (`harness finding validate`) passes;
   now a **finding-validator** attempts to *disprove* it (intended behavior?
   duplicate? excluded by policy? reproducible from evidence?).
3. **validated** — survives adversarial review.
4. **poc_ready → scored** — a minimal PoC is documented; CVSS is computed by the
   maintained calculator (never model arithmetic).
5. **report_ready → qa_passed** — the report is written and passes deterministic
   QA (evidence present, impact *demonstrated*, no secrets, no destructive PoC).
6. **human_approved** — the human decides to submit. **This is the only state
   that authorizes submission.** You never reach it yourself.

At most gates, `rejected` / `killed` are available to stop a bad finding.

## Scoring honestly

The CVSS number comes from `./harness cvss <vector>` (or the broker tool);
select metric *values* with discipline and note uncertainties. Severity is a
consequence of the vector, not of enthusiasm — see
[cvss-and-reporting](cvss-and-reporting.md).