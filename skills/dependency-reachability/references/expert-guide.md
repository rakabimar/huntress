# Expert guide

## Evidence contract

Persist the manifest and resolved version, advisory/range, vulnerable API use,
attacker-controlled path, enabling configuration, deployed-version mapping,
mitigations, reachability status, and a refuting condition. An advisory match
without this chain remains a DependencyObservation.

Mental model: affected version? → component shipped? → affected API imported? → vulnerable feature used? → attacker input reaches it? → required configuration? → affected release deployed/in scope? → protected impact? Attack surface spans direct/transitive dependencies and plugins, but dev/test/optional packages and dead code usually reduce reachability.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

Record advisory source, affected/fixed ranges, exact resolved direct/transitive version, manifest/lockfile and ecosystem. Then prove the package is shipped in the relevant artifact, imported or invoked, the vulnerable API/feature is reached, required configuration is present, attacker-controlled data reaches the feature, mitigations do not block it, and the affected release maps to the target. Each unknown lowers confidence; scanner output remains a DependencyObservation.

Use the dependency scanner for inventory, ripgrep/symbols for imports and API use, CodeQL only for complex reachability, git/release metadata for applicability, and an approved sandbox test only when behavior cannot otherwise be resolved. Reject dev/test/optional-only packages, unreachable APIs, disabled vulnerable features, vendor backports, mitigated configuration and undeployed source. Never promote because a CVE exists. Remediation should upgrade or remove the dependency and, where possible, eliminate exposure to the vulnerable feature.
