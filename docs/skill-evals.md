# Deterministic skill evaluations

Each stable technical skill has YAML cases under:

```text
evals/{routing,positive,negative,false-positive,evidence,
       tool-selection,safety,complex-scenario}/
```

`./harness skill eval [slug]` checks case shape, safe fixture targets, route
expectations, false-positive rejection, evidence expectations, tool choice, and
safety/stop behavior. It is deterministic and part of ordinary pytest.

Cases should be difficult enough to require a boundary decision. Prefer batch
filtering, partial evidence, source/runtime version mismatch, unreachable
dependencies, test secrets, or intended sharing over obvious one-line bugs.
Every case must say what supports and refutes the hypothesis and what should not
be tested.
