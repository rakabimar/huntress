# SSRF request-construction model

Reason about the exact pipeline:

`input bytes → application/framework parse → normalization/canonicalization → allow/deny decision → DNS resolution → connection target → HTTP client/proxy → redirect parse and revalidation → final destination`

Different components may disagree on scheme, hostname, port, userinfo, percent encoding, Unicode/IDNA, trailing dot, IPv4 integer/octal/hex forms, IPv6 brackets/mapped addresses, DNS answers, and redirects. A bypass hypothesis must name the disagreement; do not spray representations.

Separate capabilities: DNS resolution, outbound connect, HTTP request, response read, redirect follow, header/credential forwarding, and non-HTTP scheme. Prove only the minimum authorized capability. Blind/OOB callbacks require a unique per-test token and attribution to the application rather than browser/scanner/resolver.
