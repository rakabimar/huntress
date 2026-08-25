---
name: host-header
description: Use when testing how a web app trusts the Host or X-Forwarded-Host header (password reset poisoning, cache poisoning, web-cache deception).
maturity: draft
risk_class: R2
category: infra
cwe: [807]
---

# Host Header Trust

## Purpose
Many applications build absolute URLs, generate links, or key their cache from the `Host` value sent by the client, optionally trusting `X-Forwarded-Host` when a proxy is present. An attacker who controls that value can poison password reset links, inject attacker-controlled absolute URLs into shared responses, or trick a cache into storing a poisoned or authenticated page. Because these bugs cross trust boundaries with a single header and no credentials, they are a high-value target for bug hunting.

## When to use
- The app sends password reset, email verification, or other self-service emails containing absolute URLs.
- Responses reflect the `Host` header in links, redirects (`Location`), scripts, or CDN/cache keys, or change when `X-Forwarded-Host` / `X-Forwarded-Proto` is supplied.
- The app sits behind a proxy, CDN, or cache and treats forwarded headers as trusted without validating an `X-Forwarded-*` allowlist.

## Process
1. **Observe** the target's link generation: request the same path with a modified `Host` and a leading `X-Forwarded-Host`, and diff the absolute URLs in the response and in any outbound email or redirect.
2. **Hypothesize** a falsifiable claim via `create_hypothesis` — e.g. "If I set `Host: attacker.test` on the reset request, then the reset link in the email will point at `attacker.test`, crossing the account-takeover boundary Z."
3. **Predict** both outcomes on the planned test (`create_research_test`): what you see in body/email/`Location` if true, and what would refute it (link unchanged or ignored).
4. **Test** the MINIMAL experiment through `send_authorized_http_request` only — never raw curl/sqlmap. Send one request changing only the header under test; keep everything else identical. For reset poisoning, trigger one reset to your own test account and inspect the delivered link.
5. **Compare** and record via `complete_research_test`; persist `create_evidence` for any mutation you observed. Never demo with a victim account or scrape a real user's mailbox.
6. **Promote** only a hypothesis that a validator cannot disprove toward a candidate finding.

## Evidence
- `request_response`: redacted pair showing the request with the forged header and the response reflecting it in `Location`, `<script src>`, or `Link`; for reset poisoning, the excerpt of the delivered email URL.
- `observation`: note that the reflected value is attacker-controlled and reached an email or a cacheable response.
- `command_output`: optional diff of baseline vs. forged-header responses.
- Redact tokens, reset `token=` values, and any PII from every record.

## False positives
- The app reflects `Host` in a page body but only uses it cosmetically and never in an email or cache key — reflection alone is not a finding.
- A load balancer normalizes or validates `Host` and rejects unknown values; a "changed URL" in a single response does not prove a poisoned *shared* artifact.
- `X-Forwarded-Host` is honored only when `X-Forwarded-For` comes from a trusted proxy, so a straight request with the header is ignored.
- A reset link that does reach your mailbox but was already valid behavior for your own account — confirm the target is actually derived from the forged value.

## Stop conditions
- `scope_preflight` rejects the target or action — stop immediately.
- The proof requires R3/R4 (massing accounts, destructive writes, DoS) and no approval is recorded — stop.
- Demonstrating the effect would poison a production cache or email real users — stop and switch to a read-only or single self-account demonstration.

## Example
A lab app at `https://accounts.example.test/auth/reset` echoes the `Host` into reset emails sent only to the requester. Hypothesis: supplying `X-Forwarded-Host: evil.test` will make the reset link use `https://evil.test/reset?token=...`. Predict true or false, then send one `POST /auth/reset` to your own test account with that header attached. If the delivered link resolves to `evil.test`, record the `request_response` and the email excerpt as evidence; if the link ignores the header, record the refutation and reject the hypothesis.