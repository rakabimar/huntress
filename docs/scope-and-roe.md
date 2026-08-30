# Scope and ROE

`scope.yaml` is authoritative. Exclusions always win. The engine supports exact
domains, wildcard subdomains, absolute URLs and path prefixes, IPv4, and CIDR.
It normalizes host case, trailing DNS dots, default ports, fragments, and safe
dot segments. Userinfo, encoded path separators, NULs, double encoding, and
ambiguous paths fail closed.

`roe.yaml` controls activity classes, rates, concurrency, required headers,
manual approvals, and forbidden actions. Review the effective envelope with:

```bash
./harness scope check --program acme https://api.example.com/path
./harness policy matrix --program acme
./harness policy check --program acme --action authorization_test --target https://api.example.com/object/1
```

Activation runs full engagement validation. An invalid or empty engagement
cannot activate. `--force` is only an audited administrative override and is
never considered HUNT_READY.

Redirects are never followed automatically: each Location is normalized,
scope checked, policy checked, rate limited, and capped. An out-of-scope hop
stops without being labeled a vulnerability.

