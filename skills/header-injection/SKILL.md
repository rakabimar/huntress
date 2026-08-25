---
name: header-injection
description: Use when a target reflects user-controlled input into HTTP response headers, cookies, or redirect targets, or accepts Host/X-Forwarded-* style headers
maturity: draft
risk_class: R2
category: injection
cwe: [113]
---

# HTTP Header / CRLF Injection

## Purpose
Header injection happens when user-controlled input flows into HTTP response headers (or meta-areas like cookies, redirect `Location`, or `Set-Cookie`) without stripping CR (`\r`) and LF (`\n`) characters. An attacker can forge additional headers or split responses, enabling HTTP response splitting, cookie-setting, content sniffing, and log forgery via CRLF. In bug hunting it is a low-cost, high-signal weakness because the effect is often directly observable in the reflected response.

## When to use
- Inputs that are reflected into response headers: redirect parameters, `Location` / `Content-Type` / `Set-Cookie` (CWE-113).
- Sign-up / password-reset flows that set cookies, or any endpoint echoing a `Host`, `X-Forwarded-For`, or `X-Forwarded-Host` header (Host header injection).
- Values that reach server-side logs (user-agent, referer, username) — CRLF there is log injection.
- Download endpoints that derive a filename or content type from a query parameter.

## Process
1. Identify a parameter or header whose value appears in any response header, cookie, or logged string. Confirm the endpoint is in scope with `scope_preflight`.
2. Record a falsifiable hypothesis with `create_hypothesis`: e.g. "If I send `%0d%0a` in parameter P, a new `Set-Cookie`/`X-Injected` header will appear in the response."
3. State the expected observation (an injected header) and the refuting observation (value is neutralized, encoded, or stripped).
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — never raw curl/nmap/sqlmap. Send one payload that ends in `%0d%0a` plus a single harmless header, e.g. `name=x%0d%0aX-Injected:%20probe`.
5. Inspect the raw response header block for the injected line; note whether it appeared as a real header or was percent-encoded in the body.
6. Record the observation and result with `complete_research_test`, then persist `request_response` evidence via `create_evidence`.

## Evidence
- `request_response`: full redacted request and raw response headers showing the injected header line (the single most load-bearing record).
- `observation`: written note of which header/input reflected the value and where.
- `command_output`: only if a harness CLI call produced output worth keeping.
- Always redact cookies, tokens, and PII before storing evidence or previews.

## False positives
- The value appears encoded (e.g. `%0d%0a` echoed literally in the body or a header) rather than decoded into a new header line — that is correct neutralization, not the bug.
- A header that merely contains your input on one line (no CRLF, no new header formed) is reflection, not injection.
- The injected characters land only in the HTML body or a `Content-Type` that a browser/MIME parser ignores — confirm a distinct new header line actually formed.
- A duplicate `Location`/`Set-Cookie` produced by app logic (not by your line break) may be a normal redirect chain.

## Stop conditions
- `scope_preflight` rejects the target or endpoint — stop immediately, no testing.
- The proof would require R3/R4 or destructive action (mass cookie-setting, response-splitting a cache for real users, DOS) and no approval is recorded — stop.
- The only way to demonstrate the effect is a destructive write or cache poisoning with real impact — stop and record an inconclusive result instead.
- Confirmation of which program/scope you are in is uncertain — stop.

## Example
A sign-up endpoint on `example.test` echoes a `redirect` query parameter into a `Location` header. Hypothesis: `redirect=/home%0d%0aX-Injected:%20probe` will produce a second header. Send one request through the broker and inspect the raw response; a new `X-Injected: probe` line confirms CRLF injection, while the value `%0d%0a` appearing untouched in the header confirms neutralization.