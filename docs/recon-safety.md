# Recon safety

Every active seed and discovered URL passes the normal Scope Engine. Passive
seed derivation is separate and does not grant active authority. Fixed argv
lists, no `shell=True`, timeouts, output bounds, ROE rate/concurrency, and
program policy gates constrain every supported binary.

Out-of-scope redirects may be retained as metadata but are never followed as
new targets. Burp history ownership comes from the request line and Host header;
third-party URLs in an in-scope response are untrusted data, not ownership
signals. Authorization, cookies, tokens, passwords, sensitive query values, and
mandatory bounty-header values are redacted or omitted.

Ordinary crawling uses observational GET navigation and never intentionally
triggers logout, deletion, purchase, redemption, invitations, or financial
operations. Katana is exact-host scoped and excludes mutation-like route names;
the fallback only fetches the seed page and inventories discovered links.
Authenticated discovery remains Playwright → Burp → inventory.
Nuclei, ffuf, naabu, and nmap are deep, policy-gated Lead generators only.
