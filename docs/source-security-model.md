# Source security model

`source context` builds a commit-scoped `SourceSecurityContext`: architecture summary, components, entry points, trust boundaries, reusable controls, sensitive assets, stores, integrations, security invariants and unresolved questions. It persists separately per repository commit; an update never silently reuses old conclusions.

Security-critical `SourceSymbol` rows carry language, source range, kind, assumptions, guarantees, inputs/outputs, controls, callers/callees, side effects, trust boundary and unresolved assumptions. Resolution confidence is `EXACT`, `HIGH`, `MEDIUM`, or `UNKNOWN`. `UNKNOWN` never means a control is absent.

The intended reasoning chain is architecture → control → invariant → outlier → SourceObservation → Lead → runtime/release applicability → hypothesis → minimal test. Static results never enter a separate finding pipeline.
