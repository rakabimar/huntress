# Expert guide

Mental model: architecture precedes bug search. Map components, entrypoints, trust boundaries, identities, sensitive assets, authoritative data stores, background execution, external services, and reusable controls. Attack surface includes HTTP/GraphQL/WebSocket/CLI/queue/plugin/file entrypoints and shared services. Rank components by exposed attacker input plus security-sensitive action, newly changed code, or control concentration; do not rank dangerous-function names alone.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

## Architecture worksheet

Build the commit-specific model before searching for bug classes: component ownership; HTTP, resolver, consumer, job, parser, file and plugin entry points; where identity is established; where authorization is enforced; authoritative stores; external clients; privileged effects; and unresolved framework configuration. For each security-critical function record inputs, outputs, callers, callees, side effects, trust boundary, assumptions and guarantees. Analyze entry points and shared controls, not every utility.

An assumption is something the callee needs ("principal tenant already established"). A guarantee is something it enforces ("loaded invoice belongs to principal tenant"). A comment or type annotation may suggest either, but only executable control flow supports a guarantee. When caller/callee resolution is UNKNOWN because of dependency injection, reflection or generated code, preserve UNKNOWN and inspect configuration; never translate it to "no authorization."

Security invariants connect architecture to hunting. Derive them from repeated secure siblings, central policy, tests and data relationships. Examples: mutations require `record.organization_id == principal.organization_id`; outbound user URLs pass the canonical URL validator after redirects; webhook mutation follows signature verification; archive extraction remains beneath the destination. Persist the evidence and possible outliers, then create an Observation or Lead—not a Finding.

## Insecure defaults and sharp edges

Review missing configuration separately from explicitly unsafe user configuration. High-signal defaults include fail-open authorization, empty-secret fallback, disabled certificate verification, production debug mode, allow-all when a policy cannot load, and legacy compatibility enabled by default. A user who deliberately opts into an insecure mode is usually not a product vulnerability unless the product misrepresents the boundary.

Sharp edges are secure APIs that ordinary callers can easily misuse: optional authorization callbacks, ambiguous booleans, secure verification as an opt-in, errors that silently disable checks, or plugin hooks that bypass the normal policy seam. Compare safe and unsafe siblings and ask whether the API architecture can enforce the invariant centrally.

## Tool decision path

Use ripgrep for an exact helper, route or sibling. Use the symbol/AST index for definitions, decorators and likely callers/callees. Use Semgrep when syntax structure matters across files. Escalate to CodeQL only for type-aware or cross-function flow. Use git for why/when/release applicability. Use the sandbox only when a build, test or reproducer is necessary and ASK is approved. Use the Broker for minimal hosted-runtime confirmation. Stop when the commit is inapplicable, the path is unreachable, a central control proves the invariant, or remaining uncertainty needs an unavailable approval/tool.
