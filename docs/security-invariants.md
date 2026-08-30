# Security invariants

`SecurityInvariant` records component/scope, description, source evidence, confidence, supporting controls, possible violations and originating skill. Invariants are inferred conservatively from secure sibling patterns and may also be recorded from policy/tests.

Examples include tenant ownership on every mutation, signature verification before webhook state changes, canonical URL validation for every outbound user URL, and archive containment after decoding. An outlier creates an Observation/Lead with a refuting check; it is not a Finding until the normal evidence-gated lifecycle succeeds.
