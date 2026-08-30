---
name: cache-poisoning
description: Use when attacker-controlled unkeyed input may alter a shared cached response; route private-response path confusion to cache-deception.
maturity: stable
risk_class: R2
category: infra
cwe: [345]
canonical: true
primary_specialist: recon-specialist
related_skills: [cache-deception, host-header, xss, request-smuggling]
primary_triggers: [shared cache, unkeyed input, cache key mismatch, poisoned variant]
secondary_triggers: [CDN, normalization, headers, query, cache status]
negative_triggers: [uncached reflection, correctly keyed variant, private cache]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Web Cache Poisoning

## Purpose
Web cache poisoning makes a shared cache store attacker-controlled content and later serve it to other users. The weakness is that the cache's key ignores inputs that actually change the response, so a single request contaminates a view every other visitor shares. It matters for bug hunting because the impact is reflected to an entire audience, not only the attacker, while requiring only harmless request shaping to prove.

## When to use
- Endpoints whose response includes or reflects values from headers (e.g. `X-Forwarded-Host`, `X-Forwarded-Scheme`, `Host`) or cookies.
- Pages with dynamic content that some inputs do and do not change, suggesting a partial cache key.
- Responses carrying cache hints (`Age`, `X-Cache`, `Cache-Control`), CDNs, or reverse proxies in the stack.
- Suspected cache key confusion where a header on the key list is not what the application actually trusts.

Use `cache-deception` instead when the proposed effect is caching a victim's
private dynamic response under a static-looking path. Poisoning changes shared
content through an unkeyed input; deception stores the wrong private response.

## Process
1. Observe the target surface and note which inputs vary the response but are absent from the cache key.
2. Build a falsifiable hypothesis with create_hypothesis: "If I send `X-Header: poison` and the poison value persists in a second, innocent request, then the cache stored an unkeyed-input variant."
3. Predict the observable that would confirm (the poisoned value served to a request without the header) and the observation that would refute it (a clean, header-independent response).
4. Run the MINIMAL controlled experiment through send_authorized_http_request only: add one unkeyed header, then re-request the same URL without it.
5. Record the observation and result via complete_research_test, and capture the paired request/response as evidence with create_evidence.
6. Confirm the cache stores the poisonous variant on a local fixture cache rather than against a real, untrusted target, and prefer read-only probes over injecting content victims would actually consume.

## Evidence
- `request_response` pairs showing the poisoned request and the later innocent request that still returned the injected value.
- `observation` records noting cache headers (`X-Cache: hit`, `Age`) and the byte-level delta between poisoned and clean responses.
- Redact any secrets, tokens, or PII before storing; never persist a victim-serving payload as a live proof.

## False positives
- Response headers echoed without ever being cached — verify with a second cache-hit request that the value persists.
- A cache that keys on the input correctly (the header is not "unkeyed") — the value must survive even when the header is removed.
- Reflections that are per-user or per-session, not shared, so no other visitor is served the poisoned copy.
- CDN revalidation or origin fallback that masks a hit; confirm the hit signature rather than assuming first-request storage.

## Stop conditions
- scope_preflight rejects the target — stop immediately and never proceed.
- The proof would require R3/R4 action (destructive write, scale exfiltration) and no human approval is recorded.
- Demonstrating the impact would deliver malicious content to a real end-user — stop and record the observation instead.

## Example
On `https://cache.example.test/home`, a hypothesis: an unkeyed `X-Forwarded-Host` header rewrites asset links. First request via send_authorized_http_request adds `X-Forwarded-Host: attacker.test`; the response links to `attacker.test`. A second request to the same URL with no such header, hitting the same fixture cache, still returns links to `attacker.test`. That persistent mismatch is the poisoning proof, recorded as `request_response` evidence with the payload pointed at `attacker.test` only.
