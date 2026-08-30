---
name: ssti
description: Use when a target reflects user input into a server-side template (Jinja2, Twig, FreeMarker, Velocity, ERB) and may evaluate template syntax
maturity: stable
risk_class: R2
category: injection
cwe: [1336]
canonical: true
primary_specialist: whitebox-audit-specialist
related_skills: [xss, command-injection, source-dataflow-analysis]
primary_triggers: [server template, render string, expression evaluation]
secondary_triggers: [email PDF template, sandbox escape, engine fingerprint]
negative_triggers: [literal reflection, client template, fixed trusted template with data binding]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Server-Side Template Injection

## Purpose
Server-side template injection (SSTI) occurs when a target embeds attacker-controlled input into a template and evaluates it as template code rather than data. Depending on the engine, this can escalate from harmless expression evaluation ({{7*7}}) to arbitrary file read and command execution. The goal is to first identify the engine non-destructively, then prove evaluation with a safe arithmetic probe, and treat any RCE escalation as a gated, approval-only step.

## When to use
- Inputs reflected back in rendered HTML, error pages, emails, PDFs, or CSV exports (e.g. name, search term, header values).
- Endpoints that mention templates, `render`, `view`, `theme`, or a `{{...}}`-style or `${...}`-style syntax in docs, params, or defaults.
- Error messages that leak a front-end library (Jinja2, Twig, Django, Freemarker, Velocity, Handlebars) or its version.
- Any parameter whose value appears verbatim inside output that is likely computed server-side before being returned.

## Process
1. Form a falsifiable hypothesis with `create_hypothesis`: state which field you believe is reflected, the exact probe string, and the observable that proves evaluation (e.g. "if X is evaluated, the response will contain `49`, not the literal `{{7*7}}`").
2. Run `scope_preflight` on the target and `policy_preflight` on the action before sending anything.
3. Send the single minimal probe through `send_authorized_http_request` — never raw curl/nmap/sqlmap. Start with a harmless arithmetic probe such as `{{7*7}}` or `${7*7}` and record the exact request and response.
4. Compare the response to the prediction. `49` (or `7777` depending on engine) supports evaluation; the literal string echoes back and rejects it. If a template engine is implicated but the syntax is unknown, send a benign polyglot (e.g. `${{7*7}}` / `<%= 7*7 %>` / `#{7*7}`) to fingerprint the engine — still read-only.
5. Record the outcome with `complete_research_test` and persist redacted request/response via `create_evidence`.
6. Escalate to file read or RCE only as a hypothesis after basic evaluation is confirmed, and only when `policy_preflight` authorizes it and any required human approval is recorded as approved. Prefer a read-only proof (engine version, a known safe identifier) over command execution.

## Evidence
- `request_response`: full redacted request and response showing the probe string and the evaluated result (the difference between `{{7*7}}` sent and `49` returned is the load-bearing artifact).
- `observation`: the predicted-vs-observed comparison and the engine identified.
- `command_output`: only for a sanctioned, read-only confirmation, with engine/version output redacted of secrets and PII.

## False positives
- Client-side templating (Handlebars, Angular, Vue) that evaluates in the browser, not on the server — confirm by checking whether the evaluation result appears in the raw HTML body from a direct request, not in the rendered DOM.
- Literal echo of the probe with no evaluation (the `{{...}}` is shown verbatim), indicating the input is escaped or treated as plain text.
- A reflected `49` that comes from application math or a coincidental match rather than the template engine — vary the arithmetic (e.g. `{{7*6}}`) and confirm the result tracks the expression.
- WAF/encoding quirks that strip or mangle braces, making a real reflection look inert — retry with equivalent syntax before concluding.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` rejects the action — stop and record, do not retry.
- Escalating to RCE would require an R3/R4 action and no approval is recorded as approved — stop and request it, do not assume it.
- The only way to prove the effect is destructive or writes data — stop; report what read-only probes showed instead.

## Example
A profile page on `example.test` reflects the `name` query parameter inside the response body. Hypothesis: the value is passed unescaped into a server template. Send `GET /profile?name={{7*7}}` through the controlled broker. The response body contains `49` where the name should appear, supporting the hypothesis and identifying a numeric-evaluation engine. An engine-version probe is then recorded as evidence, while any command-execution proof is withheld pending recorded human approval.
