---
name: request-smuggling
description: Use when a target runs a frontend proxy in front of a backend, and you need to test for desynchronized HTTP parsing between them.
maturity: stable
risk_class: R2
category: infra
cwe: [444]
canonical: true
primary_specialist: recon-specialist
related_skills: [http-parameter-pollution, cache-poisoning]
primary_triggers: [frontend backend parser disagreement, HTTP framing, CL TE, connection desynchronization]
secondary_triggers: [HTTP2 downgrade, proxy chain, request queue]
negative_triggers: [single parser rejection, ordinary keepalive timeout, no proxy hop]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# HTTP Request Smuggling

## Purpose
Request smuggling exploits a mismatch in how two HTTP handlers — usually a frontend proxy and a backend server — delimit request bodies (Content-Length "CL" versus Transfer-Encoding: chunked "TE"). When the frontend and backend disagree, one request can be smuggled inside another, causing the backend to attach a following victim's request to the wrong connection. It is a high-impact but high-risk amplifier: a confirmed discrepancy can enable request queue poisoning, cache manipulation, or authorization bypass, but a wrong probe can poison shared infrastructure.

## When to use
- A frontend proxy (CDN, load balancer, WAF, reverse proxy) forwards to a distinct backend, visible via distinct Server headers or version-independent behavior.
- The stack supports both Content-Length and Transfer-Encoding: chunked, and the target is reachable over a persistent (keep-alive) connection.
- Endpoints normalize or reject ambiguous framing headers differently than upstream, or the app appears behind a shared gateway where a desync would affect other tenants.

## Process
1. Build a falsifiable hypothesis with `create_hypothesis` naming the exact framing discrepancy and the observable. Example: "The frontend honors Content-Length while the backend honors Transfer-Encoding, so a request with both headers smuggles a trailing chunk."
2. Confirm scope and policy first: `scope_preflight` on the target host and `policy_preflight` on the probing action. Decide whether CL.TE or TE.CL is the likely mismatch before sending anything.
3. Send the MINIMAL probe through `send_authorized_http_request` only — never raw curl/nmap/sqlmap. A CL.TE probe sends one request with both headers plus a trailing "0\r\n\r\n" chunk payload; a TE.CL probe sets both headers with a discrepancy in the other direction.
4. Predicate the observable: if true, a harmless follow-up GET returns a non-standard status (e.g. 301 from the smuggled path) or a timeout; if false, the second response is absent and the timing is normal. Record both predictions on the planned test.
5. Run the single controlled probe, then immediately send one benign follow-up request and observe the response. Record observation and result via `complete_research_test`; capture `request_response` and `observation` evidence via `create_evidence`.
6. Avoid multiple rounds: a desync that matches is demonstrated once, redacted, and escalated — repeated probing risks poisoning a shared frontend for other users.

## Evidence
- `request_response`: the probe request showing the raw CL and TE header values, and the full response, with any credentials or tokens redacted.
- `observation`: the timing and boundary result — normal response vs. smuggled-response echo vs. connection hang.
- `command_output` (only if produced by the harness broker): the harness-issued probe log confirming exactly one request was sent per attempt. Never persist raw packet captures that contain third-party traffic.

## False positives
- A lone 400 or "Content-Length and Transfer-Encoding both present" rejection is not a desync; it is one parser rejecting ambiguity outright.
- A slow or timed-out response from backend idle timeouts resembles a smuggle but is ordinary keep-alive behavior — retest once, at controlled timing.
- Same-process handling where both frontend and backend are the same server (no real proxy hop) cannot desync; verify there are actually two hop behaviors first.
- A cache hit or old response can mimic a smuggled echo — clear state and contrive a unique marker in your own second request to confirm attribution.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` rejects the probing action — stop, do not proceed.
- The target is shared infrastructure and demonstrating the effect would affect other tenants; if the proof needs R3 action or would be destructive, request explicit approval and stop until it is recorded as `approved`.
- The only way to confirm is repeated desync rounds against a real, non-isolated frontend — stop; one controlled, harmless proof is the ceiling.
- You observe response content you cannot attribute to your own requests — stop and record; capture without continuing.

## Example
On `https://example.test`, the frontend reverse proxy terminates TLS and forwards to a backend with distinct Server headers. Hypothesis: frontend honors Content-Length while backend honors Transfer-Encoding: chunked (CL.TE). You send through the broker a single POST to `/login` with `Content-Length: 6` and `Transfer-Encoding: chunked`, body `0\r\n\r\nX`, then a benign GET. If the GET returns the response of a smuggled request (for example a 302 to a path you embedded), the mismatch is confirmed; you record the request_response evidence and escalate — with approval secured before any further propagation on shared infra.
