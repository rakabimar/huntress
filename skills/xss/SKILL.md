---
name: xss
description: Use when testing reflected, stored, or DOM inputs that may render attacker-controlled script in a browser.
maturity: draft
risk_class: R2
category: injection
cwe: [79]
---

# Cross-Site Scripting

## Purpose
Cross-site scripting (XSS) occurs when attacker-controlled data is rendered into a page and executed as script in a victim's browser. The weakness matters for bug hunting because it converts a read-only input sink into arbitrary client-side code execution, often leading to session impersonation or account-adjacent impact. Proving it requires demonstrating script execution in a specific HTML, attribute, JS, or URL context while staying strictly read-only.

## When to use
- Query parameters, form fields, path segments, or headers are echoed into the response body or DOM.
- Search, profile, comment, and error features where stored content is later rendered to other users.
- Client-side sinks (`innerHTML`, `eval`, `document.write`, `location`, jQuery selectors) consume attacker-influenced values.
- A template or JSON/API response appears to reflect input without encoding, or a page uses a CSP you need to analyze.

## Process
1. Identify an input and the context it lands in: raw HTML, an attribute value, a script block, or a URL/`javascript:` sink. This determines the payload shape.
2. Record a falsifiable hypothesis with `create_hypothesis`, e.g. "the `q` parameter is echoed unencoded into a tag and `<>` is preserved."
3. Confirm the target with `scope_preflight` and the action risk with `policy_preflight` before sending anything.
4. Run the minimal controlled experiment through `send_authorized_http_request` only, never raw `curl`/`nmap`. Echo a harmless string and observe exactly where and how it is reflected, then inject one structural character (`<`, `"`, `'`, `)`) at a time.
5. Choose a proof payload that shows execution with the least possible effect: a marker like `"><img src=x onerror=alert(document.domain)>` is fine, but prefer a non-exfiltrating sink such as a visible DOM mutation or `alert(`XSS`)`. Never redirect, never read cookies, never phone home.
6. For DOM XSS, source and sink may differ; follow the value from source (URL, hash, message event) to the sink across a `complete_research_test`, and note a CSP that would block the sink.
7. Persist redacted `request_response` evidence via `create_evidence` and mark the hypothesis supported only when execution was actually observed.

## Evidence
- `request_response` showing the reflected/rendered payload and any `CSP` headers that constrain it.
- `observation` noting the exact context (HTML, attribute, JS, URL) and the revealed encoding behavior.
- `command_output` only for broker results, with secrets, cookies, and any PII redacted.

## False positives
- Input echoed but HTML-encoded (`&lt;` appears in source) is output encoding, not an execution sink.
- A payload accepted into a form field but never rendered to another viewer is not stored XSS.
- A `javascript:` URL echoed into an attribute that never becomes clickable or executable.
- A browser extension, WAF, or sandboxed frame that swallows the event is not the app executing your script.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` denies the action — stop immediately.
- The proof would read session cookies, spawn exfiltration, or hit another user's session — stop.
- Demonstrating impact requires R3/R4 behavior (destructive writes, persistence, mass harvesting) with no recorded approval.
- The sink is only reachable through a destructive or self-infecting write — stop and report the minimal proof.

## Example
On `http://example.test/search?q=test`, hypothesize `q` is echoed raw. Send `q=test` and confirm it appears in body HTML. Send `q=<i>mark</i>` and observe, via the response, whether the tag is preserved (HTML context) or encoded. If preserved, send `q="><i id=x>x</i>` and confirm the attribute boundary closed; then prove execution with `q="><img src=x onerror=document.body.dataset.x=1>` and verify the mutation in the response/DOM. Record both, mark the hypothesis supported, and stop without touching cookies or sessions.