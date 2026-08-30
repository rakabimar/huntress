# Optional model behavioral evaluations

Grading includes a deterministic semantic floor: boundary relevance, a genuinely testable hypothesis, a distinct falsifying observation, minimum experiment, tool choice and forbidden overclaims. Optional `--judge` adds an independent rubric model and stores raw per-dimension score plus rationale; credentials are never included.

Serious comparisons use at least three runs per arm:

```bash
harness skill eval api-authorization --behavioral --runtime claude --runs 3 --judge
harness skill eval variant-analysis --behavioral --runtime claude --runs 3 --ablation --judge
```

Multi-run output includes success rate, mean/median accuracy, variance, and explicit stage-level summaries. Ablation uses identical fixtures with and without the skill and reports provider usage deltas when the runtime exposes them. Paid inference is explicit and excluded from pytest.

Persist a sanitized trajectory and scores for later comparison with `--output`:

```bash
harness skill eval api-authorization --behavioral --runtime claude --runs 3 --judge --output eval-results/api-authz.json
```

Unavailable provider token or cost fields remain null and are labeled `UNAVAILABLE`; they are never estimated.

Behavioral evals measure decisions, not answer style. They score routing,
hypothesis quality, tool choice, evidence discipline, false-positive rejection,
safety, request efficiency, stop correctness, and source/runtime correlation.

They are explicit because they invoke a configured runtime and may cost money:

```bash
./harness skill eval api-authorization --behavioral --runtime claude
./harness skill eval api-authorization --behavioral --runtime codex --ablation
```

`--ablation` runs the same local fixture with and without the canonical skill
instructions and reports per-metric accuracy deltas. The runner disables tools,
uses a structured schema, treats scenarios as data, and never performs a target
request. Default pytest only tests the runner with a mocked model response.
