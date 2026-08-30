# Agent observability

Schema v8 stores lightweight `AgentTurn`, `tool_call`, `skill_usage`, and `SpecialistTask` metadata in the program database. It records role/runtime/model, latency, tokens and cost when exposed, skill names, available/called tool counts, success/error class, entity links and outcome. Raw sensitive tool content is not duplicated.

Runtime hooks persist turn/tool structure immediately. When a provider exposes
usage only in its terminal result, the acceptance/runtime wrapper reconciles
that authoritative token, cache and cost summary into the completed turn; it
does not copy the transcript.

Inspect one run with:

```text
harness metrics --program acme --run RUN-123
```

The compact output emphasizes requests, Leads, hypotheses/tests, candidate and validator outcomes, request ratios, tokens/cost, specialist tasks and tool errors. These metrics feed behavioral and future real-hunt comparisons rather than a vanity dashboard.
