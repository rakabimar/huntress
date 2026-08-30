# Differential security review

`harness source audit --program acme SRC-001 --analysis differential` pins base/target, classifies authentication, authorization, validation, serialization, networking, file, dependency, crypto and configuration changes, maps changed symbols to callers/callees and entry points, records removed controls, and notes changed or missing tests.

Blast radius is prioritization, not proof. Create a SourceObservation only when a changed invariant and a plausible bypass/regression are explainable. Confirm branch/tag/runtime applicability before a Lead becomes a hosted-runtime hypothesis.
