# Implementation notes

Node URL/legacy parsers and HTTP clients differ in redirect and proxy defaults; Python `requests`/urllib/httpx, Java URI/URL and clients, Go `net/url`/`http.Client`, Ruby URI/Net::HTTP, and PHP cURL wrappers all require explicit review of canonical host, scheme, DNS, redirects, and proxy use. Record library/version and configured callbacks.

Strong control: parse once with one strict parser; allow only expected schemes/ports; resolve and reject every private/special range for all answers; connect to the validated address while preserving safe TLS hostname semantics; revalidate every redirect; limit bytes/time/redirects; strip credentials and sensitive headers; isolate egress.

Application allowlists can permit known provider hosts, but suffix comparisons must respect label boundaries and redirects. Cloud metadata hardening is defense-in-depth, not proof that the application URL validator is correct.
