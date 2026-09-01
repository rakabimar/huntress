---
name: command-injection
description: Use when an input flows into a shell, exec, eval, or OS command and you need to prove execution
maturity: draft
risk_class: R2
category: injection
cwe: [77, 78]
---

# OS Command Injection

## Purpose
OS command injection happens when untrusted input reaches a shell or command interpreter (exec, system, eval, subprocess) without safe argument separation. It lets an attacker run arbitrary commands with the privilege of the host process. For bug hunters it is one of the highest-severity injection classes: reliable, often low-privilege, and directly demonstrable once found.

## When to use
- Endpoints that echo a "ping", "dig", "nslookup", or other host utility back to the user.
- Parameters that influence a filename, a command flag, or a value passed to `system()`, `exec()`, `subprocess`, `Runtime.exec`, or an eval of a template.
- URLs with query values that appear in error text or timing that resembles a system tool's output.
- File-conversion, image-processing, or report-generation features that shell out to an external binary.

## Process
1. Record a falsifiable hypothesis with create_hypothesis: "As account A, input X arrives at the shell, so a `sleep`-style marker Y appears in response Z, crossing the process-execution boundary."
2. Identify whether the sink is argument-injection (adds your own flag, e.g. `-T` after a filename) or command-injection (metacharacters `;`, `|`, `&&`, `$()`, backticks, newline) are concatenated into a single command string.
3. Write the predicted refutation: an unchanged or sanitized response with no timing difference would reject the hypothesis.
4. Run the MINIMAL controlled experiment through send_authorized_http_request only. Prefer a single time-based marker (e.g. `sleep 3`) or a DNS callback to a scope-approved resolver — never a write, delete, or output-redirect.
5. Compare the response timing or callback to the prediction and record the result with complete_research_test; create_evidence for the request/response pair.

## Evidence
- request_response: the exact injected payload and the full, redacted response (including timing) so a third party can reproduce.
- observation: measured elapsed time against a baseline of the same request without the marker.
- command_output: captured server-side output only if the harness exposes it; redact secrets, tokens, and internal paths.

## False positives
- Argument injection returns extra tool output (e.g. extra `ping` results) but never runs arbitrary commands — it is a weaker finding, not command execution.
- A reflected parameter echoed in the page is not execution; the metacharacters must reach an interpreter, not merely be printed back.
- Latency can come from network jitter: always compare against a control request without the marker before claiming a timing delta.

## Stop conditions
- scope_preflight returns out-of-scope for the target or reparse path — stop immediately.
- The proof would require R3/R4 action (write, delete, exfiltration, persistence, destructive) with no recorded approval — stop.
- Demonstrating the bug would crash or degrade the host process (fork bomb, resource exhaustion) — choose the read-only timing marker instead.

## Example
On http://example.test/tools/lookup, the `host` parameter is passed to the OS. A tester hypothesizes it is executed by a shell, predicts a 3-second delay from an injected marker, and sends `host=example.test; sleep 3` through the broker against localhost. The response returns after roughly 3 seconds versus a near-instant baseline, supporting the hypothesis without any destructive action.

Use OAST only when in-band output and a safe timing discriminator are unavailable and ROE explicitly permits external callbacks. Exact probe correlation demonstrates a callback, not arbitrary command impact.
