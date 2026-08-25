---
name: websocket
description: Use when an app opens WebSocket connections whose upgrade is unauthenticated, whose handshake lacks CSRF/Origin protection, or when WS message content is trustingly processed
maturity: draft
risk_class: R2
category: client-side
cwe: [306]
---

# WebSocket Authentication and Message Handling

## Purpose
WebSocket upgrades ride an HTTP handshake but often skip the origin and session checks the rest of the app enforces, and once a socket is open it bypasses many HTTP-layer controls. For bug hunting the three high-value seams are: an upgrade endpoint that does not authenticate the connecting client, a handshake that accepts cross-site connections (cross-site WebSocket hijacking), and server-side or client-side handlers that trust message content without validation. Any of these can become account takeover, data theft, or arbitrary state change.

## When to use
- A `ws://` or `wss://` endpoint is reached directly from JavaScript with no auth token in the query or a `Sec-WebSocket-Protocol`/`Authorization` header.
- The server's upgrade handler never validates the `Origin` header, or the client binds to attacker-influenced message content without an origin check.
- WS frames carry commands, IDs, actions, or tokens that the handler acts on — especially when the same data would be validated on the HTTP path.
- The app relies on the socket for authentication, presence, or real-time state (chat, dashboards, notifications, trading).

## Process
1. Observe — enumerate every WebSocket endpoint, its handshake (query params, headers, `Origin`), and each `send`/`onmessage` handler in the target's JavaScript and server behaviour.
2. Hypothesize — record a falsifiable claim via `create_hypothesis`, e.g. "If I open a connection to `wss://example.test/ws` from a different origin with no valid session, the server accepts the upgrade, crossing an unauthenticated boundary."
3. Predict — on the planned test, state the observation that supports the claim (upgrade returns `101` and messages are processed) and the one that refutes it (upgrade rejected with a handshake error).
4. Test — run the MINIMAL controlled experiment through `send_authorized_http_request` only (never raw curl/nmap/sqlmap). Send a single inert frame that demonstrates acceptance — e.g. an echo message or a read query — from an origin you control.
5. Compare — does the observation match the prediction? Record the result and observation via `complete_research_test` and move the hypothesis status accordingly.
6. Persist — capture the handshake and frame exchange with `create_evidence`. Promote toward a candidate finding only when the missing check is demonstrated, never inferred from an odd-looking response.

## Evidence
- `request_response` — the upgrade handshake (headers including `Origin`, `Sec-WebSocket-Key`, `Sec-WebSocket-Protocol`) and the `101 Switching Protocols` reply, redacted of tokens and PII.
- `observation` — the exact frame delivered and the returned message/state change, quoted under an "untrusted input" banner.
- `command_output` — only broker-sanctioned tool output; redact secrets and PII from every stored record and preview.

## False positives
- An open `ws://` endpoint that accepts only authenticated, same-origin clients, with `Origin` validated and a per-connection token — verify the full handshake, not one header.
- Message content that reaches a handler but is structurally validated or normalized before use — distinguish untrusted data from untrusted and unvalidated data.
- A `Sec-WebSocket-Protocol` value the server merely echoes, with no action taken on it — missing validation matters only where attacker data is trusted downstream.

## Stop conditions
- `scope_preflight(target)` rejects the endpoint or host — stop immediately.
- The proof requires an R3/R4 action (a destructive write, persistent implant, or message flood) and no `approved` approval is recorded — stop.
- Demonstrating the flaw would damage the target's data or availability — degrade to a single, read-only, inert frame or stop.
- You cannot tell whether the connection or frame is authorized — resolve to no and stop.

## Example
A chat app at `wss://example.test/chat` upgrades from any origin and its server sends subscribed messages before any auth token is verified. Hypothesis: an attacker page on `evil.invalid` can open the socket and receive a victim's messages, since no `Origin` or session check runs at upgrade. Minimal test: through the broker, initiate the upgrade from `Origin: https://evil.invalid` with no credentials, then send one inert `{"type":"echo"}` frame. If the server returns `101` and echoes the message (or streams conversation data), the unauthenticated/cross-origin boundary is crossed; if the handshake is rejected, the hypothesis is refuted.