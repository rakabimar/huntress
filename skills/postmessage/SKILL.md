---
name: postmessage
description: Use when a page uses window.postMessage / onmessage across iframes, embeds, or cross-origin frames, or trusts a message's content without an origin check
maturity: draft
risk_class: R2
category: client-side
cwe: [345]
---

# PostMessage Origin-Check Misconfiguration

## Purpose
`window.postMessage` lets separate browsing contexts (iframes, embeds, popups, workers) exchange data across origins. A receiver that accepts events without validating `event.origin`, or a sender that omits a concrete `targetOrigin`, lets an attacker-controlled page exchange forged messages with the victim page. This frequently becomes account takeover, data theft, or state manipulation when the message content is trusted (e.g. an auth token, an ID, or an action command).

## When to use
- The app embeds third-party or attacker-influenced content in an iframe and sends messages to it (or listens from it).
- A script registers `window.addEventListener('message', …)` and acts on `event.data` — especially token, ID, config, or action payloads.
- `postMessage` is invoked with `targetOrigin: '*'`, or an `onmessage` handler never checks `event.origin` or `event.source`.
- The page is loaded inside a parent frame and the parent/child pair relies on message passing for auth or state.

## Process
1. Observe — enumerate every `postMessage` call and `onmessage` listener in the target's JavaScript. Note the payload shape, the `targetOrigin` value, and whether `origin`/`source` are validated.
2. Hypothesize — write a falsifiable claim via `create_hypothesis`, e.g. "If a page on example.test sends message {action:'setToken', token:'x'} to the listener with no origin check, then the listener will accept it and apply the token, crossing a missing-origin boundary."
3. Predict — record on the planned test the observable that supports the claim (listener applies attacker data) and the observation that refutes it (listener rejects on origin mismatch).
4. Test — run the MINIMAL controlled experiment through `send_authorized_http_request` only. Do not use raw curl, a headless scraper, or a scanner. Load the vulnerable frame and deliver a single, inert message proving acceptance (e.g. a harmless string echoed into the DOM).
5. Compare — does the observation match the prediction? Mark the hypothesis supported or rejected via `complete_research_test` and move its status accordingly.
6. Persist — write a `create_evidence` record for the captured response and message payload. Promote to a candidate finding only when the boundary crossing is demonstrated, never inferred.

## Evidence
- `request_response` — the frame/page response plus any visible reflection of the injected message, enough to reproduce.
- `observation` — the exact `event.data` payload delivered and the resulting DOM/behavior change, quoted under an "untrusted input" banner.
- `command_output` — only if a broker-sanctioned tool produced it; redact secrets and PII from every stored record and preview.

## False positives
- A listener receives and acts on a message but the messages can only originate from a same-origin or tightly allow-listed origin — verify the whole `origin` comparison, not one branch.
- The message payload is validated structurally, so crafted fields are rejected or normalized before use — distinguish untrusted data from untrusted *and unvalidated* data.
- The `targetOrigin` callback is `'*'` but the receiving context is a same-origin child that gains no attacker advantage — confirm an actual second origin is reachable.

## Stop conditions
- `scope_preflight(target)` rejects the frame, host, or endpoint — stop immediately.
- The proof requires an R3/R4 action (write, destructive, or mass exfiltration) and no approval is recorded as approved — stop.
- Demonstrating the flaw would damage the target's data or availability — degrade to a read-only, single-message proof or stop.
- The message channel cannot be reached outside a same-origin context you are not authorized to simulate — stop.

## Example
A page on `example.test/app` renders an iframe from `widget.invalid` and sends `parent.postMessage({action:'grant', role:'admin'}, '*')` on load. The parent's `onmessage` handler checks no `event.origin` and applies `event.data.role`. Hypothesis: any page embedding `example.test/app` can forge that message. Minimal test: from another `*.test` page, dispatch `window.postMessage({action:'grant', role:'admin'}, 'https://example.test')`; predict the parent applies the role. If it does while no origin whitelist exists, record the acceptance and the listener source as evidence.