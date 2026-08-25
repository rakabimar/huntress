---
name: information-disclosure
description: Use when an endpoint leaks verbose errors, stack traces, source maps, git/backup artifacts, or other unintended secrets.
maturity: draft
risk_class: R1
category: crypto-config
cwe: [200]
---

# Information Disclosure

## Purpose
Information disclosure is the unintended exposure of data — secrets, stack traces, source maps, `.git` metadata, backup files, and verbose error output — that helps an attacker advance. It is rarely the final vulnerability, but it is the stepping stone that turns blind guessing into a targeted attack. The bug hunter's job is to tell a *disclosable secret* (a key, token, or directory that crosses a boundary) from an *ignorable detail* (a framework name, a header, a timestamp).

## When to use
- Endpoints return full stack traces, SQL errors, or framework debug pages when fed malformed input.
- Static assets expose `.map`, `.git/`, `.bak`, `.swp`, `.old`, or archived source (`.zip`, `.tar.gz`).
- Responses contain identifiers that resemble secrets: `AKIA...`, `ghp_...`, `sk-...`, `-----BEGIN ... KEY-----`, JWT with a discoverable path.
- Error messages or headers leak internal paths, versions, usernames, or infrastructure details.

## Process
1. **Observe** the endpoint's normal response and any debug/error path. Do not mutate anything yet.
2. **Hypothesize** a *falsifiable* claim with `create_hypothesis`: "If I request `GET /.git/config` on this in-scope target, the response will return repository metadata, crossing the intended exposure boundary."
3. **Predict** the observable if true (a 200 with `.git` content) and the refuting observation (a 404 or generic handler).
4. **Test** with the *minimal* controlled request through `send_authorized_http_request` — never raw curl/nmap/sqlmap. One endpoint, one probing input at a time, read-only.
5. **Compare** the response against the prediction and record via `complete_research_test`. A single successful disclosure is usually enough; do not enumerate the whole filesystem.
6. **Persist** `create_evidence` for anything that matters, redacting any secret values in previews.

## Evidence
- `request_response`: the exact redacted request and response proving the disclosure is reproducible.
- `observation`: a note capturing whether the leaked item is a secret (key/token) versus a non-secret detail (server version).
- `command_output`: only for harness CLI output; never raw shell scans. Redact secrets and PII before storing.

## False positives
- Server banners, `X-Powered-By`, and framework names are *fingerprints*, not disclosures, unless they reveal an exploitable, unpatched version.
- A stack trace on a local/dev-only endpoint looks like disclosure but may be intended; check scope and whether a real boundary is crossed.
- A `.git/config` response that returns only a remote URL with no credentials is often low value; the secret must actually be exposed, not merely inferred.
- Generic 404/403 handlers that echo paths are usually not disclosure unless they confirm the existence of a sensitive resource.

## Stop conditions
- `scope_preflight` rejects the target or resource — stop.
- The proof would require an R3/R4 action (mass exfiltration, destructive read) and no approval is recorded — stop.
- Confirming the leak would require writing to or enumerating beyond one controlled request — stop and request approval.
- You cannot tell where a captured secret came from or whether it is genuinely sensitive — do not store it.

## Example
A tester hypothesizes that `https://api.example.test` ships its frontend source map. They send one `GET /app.js.map` through the broker. The response returns 200 with minified source that reveals a hard-coded `sk-` API key in the client bundle. The hypothesis is supported, one `request_response` evidence record is captured with the key redacted, and the candidate is promoted. No files were enumerated and no key was used.