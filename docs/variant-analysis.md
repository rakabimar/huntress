# Variant and differential security analysis

Persist the RootCause before authoring a rule: provenance, component, violated invariant, exact vulnerable pattern, exact fix, preconditions, dangerous sink/control and a safe sibling. Progress one feature at a time through `v1-exact`, `v2-generalized`, and only then `v3-broad`. Every local Semgrep artifact is syntax-validated before execution and its matches remain SourceObservations. CodeQL is reserved for type-aware/interprocedural variants.

Stop generalizing when results no longer share the invariant, sink or preconditions. Confirm branch/tag/runtime applicability before promoting a surviving variant to a Lead.

Use a known fix, CVE root cause, historical finding, or demonstrated invariant:

1. identify the precise security assumption that changed;
2. identify the exact code construct and secure helper;
3. search exact siblings with ripgrep;
4. expand structurally with Semgrep only when needed;
5. use CodeQL only for justified cross-function dataflow;
6. triage reachability, guards, configuration, and affected version;
7. map the candidate surface to runtime/release;
8. create a Source Lead and minimally validate it.

Generalize patterns gradually. A keyword, CVE, scanner hit, or similar-looking
function is not a finding. On repository update, `source changes` identifies
security-control paths, CI workflows, and dependency manifests for prioritized
differential review instead of rescanning everything.
