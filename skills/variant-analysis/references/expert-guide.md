# Expert guide

Mental model: exact construct → exact siblings → one-step abstraction → broader variants → reachability triage. Attack surface follows the root cause, not the CVE name. Useful tools: ripgrep for exact helpers/fragments, Semgrep for AST patterns, CodeQL for cross-function dataflow. Every expansion consumes a bounded variant budget and must improve coverage enough to justify noise.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

## RootCause contract

Before searching, write the affected component, violated invariant, exact vulnerable construct, exact fix, preconditions, dangerous sink/control, safe sibling, affected versions and source provenance (finding, patch or CVE). A CVE title is not a root cause. Read enough surrounding code and tests to explain why the patch changes security behavior.

Version 1 is an exact match for the vulnerable construct/helper omission. Inspect every result. Version 2 changes one feature—for example the resource type while preserving the same missing ownership transition. Inspect again and record false-positive causes. Version 3 may abstract syntax with Semgrep only if semantic relation is still explainable. Store each rule and its root cause; do not automatically select the broadest rule. Stop generalizing when matches no longer share the invariant, preconditions or sink.

Use ripgrep for exact fragments and sibling controls, AST/symbols for call relationships, Semgrep for structural equivalence, and CodeQL only when the variant depends on cross-function taint/type resolution. Reject tests, dead compatibility code, centralized-safe wrappers, already-fixed branches and inapplicable releases. A surviving match becomes a SourceObservation, then a runtime/release applicability check, then a Lead. Hosted targets normally require Broker confirmation; source/release programs may use an approved sandbox reproducer when ROE permits.

Example: route A's fix moved `requireOwner(record, principal)` into `updateRecord`. Search first for callers still loading then mutating records directly. Generalize from record type A to one sibling type—not to every function lacking the helper. The remediation is central ownership enforcement in the mutation service, not adding a scanner-specific call at one route.
