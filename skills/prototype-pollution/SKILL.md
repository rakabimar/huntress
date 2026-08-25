---
name: prototype-pollution
description: Use when testing client-side merge, extend, or clone operations for __proto__ and constructor prototype pollution.
maturity: draft
risk_class: R2
category: client-side
cwe: [1321]
---

# Prototype Pollution (Client-Side)

## Purpose
Client-side prototype pollution occurs when user-controlled input is merged into an object without stripping dangerous keys like `__proto__` or `constructor`, so an attacker mutates `Object.prototype` at runtime. The mutation can persist into sinks ("gadgets") spread across the page, escalating to XSS or property tampering. It matters for bug hunting because one vulnerable merge can influence unrelated code paths and third-party scripts the target did not write.

## When to use
- Input (query string, fragment, JSON body, `postMessage`) flows into a recursive merge, extend, deep-extend, clone, or spread helper.
- The page loads a config via deep-merge of parsed URL parameters or a framework state object.
- Known-gadget libraries are present, or the page reads polluted properties such as `Object.prototype.status`, `innerHTML`, or `transport_url`.

## Process
1. Trace user input into a recursive merge, extend, or clone sink and record the candidate property name.
2. Build a falsifiable hypothesis with `create_hypothesis`: "If I set `__proto__.polluted=true` in parameter P, then `({}).polluted` will be `true`, crossing the Object.prototype boundary."
3. Predict the refuting observation: the key appears as an own property on the merged object, or a fresh object stays unpolluted.
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only — plant one harmless key and observe object state; never raw curl/nmap/sqlmap.
5. Record via `complete_research_test`, and on a match capture `create_evidence` with a before/after state dump.
6. If pollution holds, test one known gadget (e.g. `status` on XHR, a script-src field) using a harmless payload.

## Evidence
- `request_response`: the exact redacted request that planted the key plus the response showing `Object.prototype` changed.
- `observation`: before/after comparison of `({}).polluted` or the reflected own-vs-prototype property.
- `command_output`: an inert in-page `Object.prototype` enumeration captured as artifact. Redact secrets and PII.

## False positives
- The key lands as an own property on the merged object rather than on `Object.prototype` — not pollution.
- The value is set but no gadget ever reads it; pollution with no sink is a latent bug, not an exploit.
- A server that merely echoes `__proto__` back in JSON is reflection, not client-side pollution.

## Stop conditions
- `scope_preflight` rejects the target or parameter — stop and do not bypass.
- Proving the effect would require R3/R4 action or destructive writes with no recorded approval — stop.
- The demonstration would need data exfiltration at scale or a denial of service — stop.

## Example
A SPA at `https://app.example.test/` deep-merges `location.search` parsed by a query helper into a config object. Sending `?__proto__[status]=42` makes `Object.prototype.status` equal `42`, and a later XHR observes its `status` property polluted. The test calls `send_authorized_http_request` once with that query, confirms via an inert in-page property check, and records `request_response` evidence.