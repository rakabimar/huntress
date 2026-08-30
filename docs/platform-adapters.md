# Platform adapters

Adapters implement a common read-only intake contract: resolve a stable program identity, declare capabilities, fetch official sources, and return a platform-neutral payload. Platform requests use a separate HTTPS-only, GET-only fetcher with adapter host allowlists, bounded retries, redirect validation, independent rate limiting, and pagination guards.

Source quality is reported explicitly: official structured API (100), official researcher JSON (95), official structured HTML (90), official policy prose (80), constrained LLM interpretation (60), and unrelated or target-controlled sources (0 and never authorization evidence).

HackerOne uses the official Hacker API v1 program, structured-scopes, and scope-exclusions resources. Bugcrowd supports its JSON:API program/current-brief/target-group/target relationships when the credential role exposes them; otherwise it reports capability unavailability. Intigriti uses the official researcher API v1 program detail, domains, and rules-of-engagement representations. YesWeHack currently provides an explicit public fallback skeleton rather than depending on undocumented private endpoints. Generic imports require a local file or an explicitly confirmed HTTPS URL and always require review.

Adapters never join programs, accept terms, mutate platform data, create reports, or submit reports.
