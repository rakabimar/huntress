# Autonomous hunting

Autonomy is fully automatic only inside the program's pre-authorized envelope.
The deterministic policy maps `allow` to `AUTO`, `approval_required` to `ASK`,
and `deny` to `DENY`. AUTO requests do not create approval rows. ASK creates a
bounded plan and checkpoints before pausing. DENY never reaches the network.

Enable and bound the controller in `autonomy.yaml`:

```yaml
enabled: true
goal: report_ready
stop_on_validated_finding: false
max_session_minutes: 180
max_total_requests: 1000
max_leads_per_session: 20
max_hypotheses_per_lead: 8
max_requests_per_hypothesis: 30
max_inconclusive_tests_per_hypothesis: 4
max_failed_tests_per_hypothesis: 5
max_redirects: 5
auto_prepare_outputs: false  # deprecated/ignored compatibility field
```

Start it with either interface:

```bash
./harness hunt --program acme
./harness start claude --program acme --autonomous --goal report_ready
```

The loop observes, ranks a lead, records a falsifiable hypothesis and both
predictions, executes one minimal brokered test, compares, persists, and
continues. Rejection does not stop the session. Exhausted leads close and the
next ranked lead is selected.

When inventory is absent or all actionable Leads are exhausted, the controller
attempts recon incrementally: passive, then light, then standard, and finally
deep. Each profile is attempted once per inventory cycle; missing tools create
a durable partial run instead of a retry loop. `ASK` checkpoints the bounded
recon escalation and `DENY` skips it.

Supported candidates enter validation and call the Harness MCP tool
`run_independent_finding_validator`, which uses a distinct Claude process and
`finding-validator` session. The equivalent operator command is:

```bash
./harness finding validate-auto FIND-001 --program acme
```

The validator receives only the finding-linked bundle, may perform at most one
linked controlled replay, and submits the structured review. The deterministic
parent finalizer applies its verdict. `finding adjudicate` is human CLI-only and
is rejected from an AI-bound session.

Stop conditions include the goal, any hard budget, no actionable research,
pending ASK, scope/ROE ambiguity, an inactive program, safety invariant failure,
or a critical unavailable integration. Every stop records actual lead,
hypothesis, test, evidence, budget, approval, and next-action state.
## Goal precedence

Goals are ordered pipeline gates: `validated`/legacy `validated_finding`,
`poc_ready`, `scored`, `report_ready`, then `qa_passed`. A later goal never
stops at an earlier gate. The legacy `stop_on_validated_finding` setting is
consulted only for the validated goals and is deprecated for new programs.

Budgets are per `AutonomyRun`, not lifetime database totals. Immutable
`AutonomyActivity` rows record Lead visits, hypothesis/test activity, requests,
recon escalation, approvals, findings, and stop conditions. Releasing a Lead
does not erase its visit, and records from an older run do not consume a new
run's budget. `max_leads_per_run` is preferred; the legacy
`max_leads_per_session` value is used only when the new value is null.

Every run persists program, runtime, goal, configured budget, usage snapshot,
timestamps, status, and stop reason. Submission is never an autonomous goal.
