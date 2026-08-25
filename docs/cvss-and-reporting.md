# CVSS & reporting

## Scoring

The *number* is always computed by the official FIRST calculator
(`bughunt_harness/cvss/engine.py` wraps the `cvss` library), never by model
arithmetic. Metric *choices* and their rationale are the skill's job.

```bash
./harness cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

- Supports CVSS **v4.0** and **v3.1** (also accepts `3.0` for scoring).
- Severity bands: `None` (≤0), `Low` (<4), `Medium` (<7), `High` (<9),
  `Critical` (≥9) — identical bands for v3.1 and v4.0 base scores.
- `score_vector` returns base score + severity; `validate_vector` returns a list
  of errors (empty = valid).

**Score honestly.** Severity is a consequence of the vector, not of enthusiasm.
Note uncertainties in the metric rationale; the finding record stores the
CVSS data alongside the report.

## Reports

Reports are generated **only** from structured, validated finding state
(`ReportData`), and their wording explicitly separates demonstrated facts from
interpretation. Required sections:

- affected asset
- weakness (CWE)
- severity + CVSS vector
- prerequisites
- steps to reproduce
- proof-of-concept
- expected vs. actual result
- security impact (what was *demonstrated*)
- evidence
- remediation

`ReportData.render()` emits a markdown document, with an `## Interpretation`
section that prefixes reasoned inferences with an explicit banner distinguishing
them from demonstrated facts (spec §61).

## Deterministic QA (`report qa` / `run_qa`)

A report fails QA if any of:

- no evidence references
- no steps-to-reproduce
- no proof-of-concept
- impact missing or a bare `high`/`critical` label (must be *supported*)
- affected asset missing
- severity claimed without a CVSS vector (warning)
- PoC references destructive / DoS behavior
- prose contains plausible secrets/PII (JWT, `password=`, `api_key=`, …)
- the finding state is unvalidated (`candidate`/`validation`) — a report must
  not precede a validated finding

Fix every failure before considering a report ready. **Never submit** — the
pipeline prepares; the human approves via `human_approved`.