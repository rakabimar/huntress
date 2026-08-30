# Expert guide

## Evidence contract

Persist base and target commits, exact changed symbols, affected callers and
entry points, control/invariant changes, relevant tests or missing coverage,
release applicability, and the observation that would refute the regression.

Mental model: changed code changes assumptions. Review additions and deletions, call-site coverage, default/config migrations, newly reachable endpoints, and blast radius across shared helpers. Attack surface includes new routes/resolvers/jobs, removed control calls, validation order, parser/library swaps, broadened IAM/workflow permissions, dependency APIs, and CI/release changes.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

## Security blast radius

Pin base and target commits. Classify changes before reading every hunk: authentication, authorization, validation, serialization, networking, file handling, crypto, configuration, dependencies and CI/CD. Identify changed symbols, then examine callers, callees, entry points/resolvers/jobs that reach them, controls/invariants altered, and deployment/release applicability. A one-line shared helper change may have a larger blast radius than a new controller.

Review additions and deletions symmetrically. Removed checks, changed defaults, reordered validation, new error fallbacks, broadened configuration and serializer field changes deserve explicit hypotheses. Compare tests: what security behavior was added, changed or left uncovered? A missing test raises research interest but is not evidence of a vulnerability.

Decision path: no security-sensitive symbol or configuration → deprioritize; changed control with all callers inheriting the new guarantee → document and stop; changed control with a caller bypassing the updated invariant → SourceObservation; applicable deployed/release version → Lead and minimal confirmation. Use `git diff` and blame first, symbol index for blast radius, Semgrep for structural caller variants, CodeQL only for complex flow, and sandbox tests only after ASK. Persist base/target, changed symbols, blast radius, new/violated invariants, tests and candidate Leads.
