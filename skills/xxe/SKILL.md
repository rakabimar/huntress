---
name: xxe
description: Use when an endpoint accepts or returns XML, or reveals XML parsing errors or echoed entity values.
maturity: draft
risk_class: R2
category: injection
cwe: [611]
---

# XML External Entity Injection

## Purpose
XXE happens when an XML parser resolves external entities, letting an attacker read local files, reach internal endpoints (SSRF), or exfiltrate data out-of-band. It matters for bug hunting because a single accepted XML document can turn a low-value parser into a file-read or SSRF primitive, and because the parser often announces itself in error messages.

## When to use
- A request sends `Content-Type: application/xml`, `text/xml`, or an XML body inside SOAP/API payloads, PDF, SVG, or DOCX/XLSX uploads.
- A file upload or import feature hands untrusted content to an XML parser (SVG avatars, document converters, config import).
- Responses echo back an XML value, or error text leaks parser names and entity-resolution details.

## Process
1. Confirm the input reaches an XML parser before touching entities: send the smallest well-formed document through `send_authorized_http_request` and note the response. Record a `create_evidence` request_response.
2. Write a falsifiable hypothesis: "If I send a `SYSTEM` entity against a local file I control, the parser resolves it and echoes the content, crossing the file-read boundary." Record it with `create_hypothesis`.
3. Prove parsing with a harmless internal entity first: define `<!ENTITY x "pwn">` and reference `&x;` in echoed output. This confirms entity resolution without reading any system file.
4. Escalate minimally: introduce an external entity targeting a file whose expected content you can predict (e.g. `file:///etc/hostname`). Only one `system` read per test; capture what is echoed or reflected.
5. Distinguish the three outcomes: content reflected in the response = direct file read; content absent but a network callback from an internal address = SSRF; nothing in-body but retrievable via a DTD you host on a `*.test` host = blind/exfil (external DTD + parameter entities).
6. Record each result with `complete_research_test`. Stop at the least-invasive proof that demonstrates the boundary crossing; do not extend to directory listing or bulk file reads.

## Evidence
- `request_response`: the redacted XML payload and the full response, including any echoed entity output or parser error.
- `observation`: a network callback from the target to a `.test` exfil DTD host, with the retried path noted.
- `command_output`: any server log or `.test` host access log line showing the out-of-band request.
- Redact secrets and PII from any reflected file content before persisting.

## False positives
- An entity name echoed back literally (`&x;` unchanged) is not resolution; it means the parser escaped or did not process the entity.
- An error naming a DTD or entity syntax is parser gossip, not a confirmed read; you need echoed content or a callback to claim impact.
- A `file:///` reference that returns a generic empty response could be a blocked scheme, not successful SSRF or file read.
- A callback to your host may be routine outbound traffic from the application, not XXE; confirm the request path or body correlates to your injected entity.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` blocks the action: stop immediately.
- The proof would need R3/R4 (destructive writes, mass exfiltration, DoS) or approval that is not recorded as approved: stop.
- The only way to demonstrate the effect is destructive or noisy: stop and report the parsing signal without the impact step.
- Entity resolution is disabled (parse errors or escaped echoes): stop; the parser is not vulnerable.

## Example
An internal API at `https://service.example.test/parse` accepts an XML body and echoes the `note` field. Send `<?xml version="1.0"?><!DOCTYPE n [<!ENTITY e "test">]><n><note>&e;</note></n>` and observe `test` returned, confirming resolution. Then hypothesize a file read and send `<!DOCTYPE n [<!ENTITY e SYSTEM "file:///etc/hostname">]>` with `&e;` in the echoed field. If the hostname is reflected verbatim, a direct file read is demonstrated; if only a callback to `https://exfil.example.test/?x=` arrives after an external DTD payload, classify it as blind XXE.

For blind validation, use one policy-approved OAST probe and exact request linkage. A provider callback without the probe/test/request correlation tuple is not evidence.
