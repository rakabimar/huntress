---
name: ssrf
description: Use when testing URL fields, webhooks, import-from-URL, or callback features for server-side request forgery
maturity: draft
risk_class: R2
category: web
cwe: [918]
---

# Server-Side Request Forgery

## Purpose
SSRF occurs when a server fetches a URL supplied by an attacker, letting the request originate from the server's own network position. This matters for bug hunting because it can reach internal services, cloud instance metadata, or bypass network controls that direct external requests cannot. It is demonstrable through the least invasive read-only requests rather than exploitation.

## When to use
- Endpoints that accept a URL and fetch it: image import, PDF/HTML rendering, webhooks, link previews, RSS import.
- Parameters whose value is rendered after a server hop (callback/notify URLs, redirect targets, file download by URL).
- Features that proxy a resource through the application rather than returning a client-side redirect.

## Process
1. Confirm the target and action pass `scope_preflight` and `policy_preflight`; stop if either rejects.
2. Identify which input is fetched server-side by observing an out-of-band only marker against a permitted fixture host.
3. Write a falsifiable hypothesis with `create_hypothesis`: "If I set the URL to X, the server will issue a request to X, observable as Y."
4. Run the MINIMAL controlled experiment through `send_authorized_http_request` only (never raw curl/nmap/sqlmap). Point the URL at your fixture (e.g. `http://127.0.0.1:<port>/` or a `*.test` host) to see the request arrive.
5. Record the observation and result with `complete_research_test`, and persist the request/response with `create_evidence`.
6. Only after the fixture proves server-side fetch, probe one internal address or metadata path at a time, keeping each step read-only.

## Evidence
- `request_response` records of the SSRF vector and the resulting back-end response.
- `observation` records noting a request reached your fixture or callback host.
- `command_output` from the local fixture service showing the inbound request. Redact secrets and PII from every stored record and preview.

## False positives
- The client's own browser makes the request (client-side fetch) rather than the server — check the source IP hitting your fixture; a browser IP is not SSRF.
- A plain open redirect: the server returns a Location header and the browser follows it; no server-side fetch occurs.
- A request to your callback host triggered by a DNS resolver or monitor rather than the application — correlate timing and a unique per-test token.

## Stop conditions
- `scope_preflight` or `policy_preflight` rejects the target or action — stop.
- The proof path would require an R3/R4 action (or destructive write/exfiltration) and no recorded approval exists — stop and request approval.
- The only way to demonstrate reachability is a destructive mutation or repeated high-volume callback — stop; find a read-only indicator.

## Example
An application at `http://example.test` offers "Import image from URL" and fetches the supplied value. You configure a fixture listener on `127.0.0.1:8080` and hypothesize the server will contact it. Through `send_authorized_http_request` you submit the import field set to `http://127.0.0.1:8080/probe?token=abc123`; your fixture logs an inbound request carrying `token=abc123`, demonstrating server-side fetch. You then point the field at a local metadata fixture on `http://127.0.0.1:8080/meta` and observe that the server fetches it, recording each step as evidence.