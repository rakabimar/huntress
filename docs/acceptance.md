# Local model acceptance

The deterministic synthetic hunt verifies the control plane. The optional
model smoke additionally proves actual configured model tool selection and
research behavior against a disposable loopback-only program:

```bash
./harness acceptance model-smoke --runtime claude
# or
./harness doctor --program <program> --deep --model-smoke --runtime claude
```

The stricter source-assisted lifecycle is explicit and separately metered:

```bash
./harness acceptance whitebox-model-smoke --runtime claude --timeout 2400
```

If the provider exits only after the independent validator has durably
submitted its review, the deterministic tail can be resumed without another
model invocation:

```bash
./harness acceptance recover-whitebox-model-smoke --program local-whitebox-model-smoke-YYYYMMDD-HHMMSS
```

Recovery refuses non-loopback programs, missing/failed specialists, absent
source provenance, non-supported reviews, and non-independent reviewers. Its
result is explicitly marked `continuation: true`.

It passes only when the real model persists a SourceObservation, promotes and
claims a source-derived Lead, persists a SourceRuntimeMapping after local
recon, confirms the boundary with the two fixture accounts, survives a
separate finding-validator runtime, and reaches the configured `VALIDATED`
smoke goal. PoC/report/QA gates are exercised by the deterministic release
suite instead of spending model budget on formatting. Describing source/runtime
correlation in prose is not sufficient. Its result is stored as
`reports/whitebox-model-smoke-result.json`; doctor reports
`WHITEBOX_MODEL_VERIFIED` only after rechecking the database provenance.

The fixture contains benign/public surfaces, a protected dead end, untrusted
prompt-injection text, two synthetic accounts, and one cross-account
authorization flaw. The production-surface smoke names the object-ownership boundary so it measures
tool/lifecycle integration rather than open-ended discovery; the whitebox run
still requires the role-bound specialist to locate and persist the missing
control. Internet targets are absent from scope and model-process egress remains
loopback-only/Broker-mediated.

Results persist under the uniquely named `local-model-smoke-*` program as
`reports/model-smoke-result.json`, including runtime/model, AutonomyRun,
duration, requests, Leads, hypotheses, tests, finding/validation/report
outcomes, token/cost metadata when supplied, and stop reason. This command can
incur model charges and never runs in pytest. A skipped run is `NOT_RUN`, never
PASS.

The default 40-minute autonomy budget and 2,400-second process timeout leave
room for the separate validator runtime. A shorter caller-supplied timeout is
recorded as FAIL with partial counts and redacted runtime diagnostics; it is
never promoted to MODEL_VERIFIED.
