---
name: lfi
description: Use when an endpoint loads a file/resource path from user input (file, template, language, page params) and you suspect local file inclusion
maturity: draft
risk_class: R2
category: file
cwe: [98]
---

# Local File Inclusion

## Purpose
Local file inclusion (LFI) occurs when a server resolves a filesystem path from user input and reads the resolved file into the response. It matters to bug hunting because a single undisclosed-file read can leak source, config, or credentials, and because the weaker read posture can sometimes be turned into code execution. Track the read-to-RCE escalation chain (PHP filters/wrappers, log poisoning) as a separate, explicitly gated goal.

## When to use
- Endpoints with path-like parameters: `file=`, `page=`, `template=`, `lang=`, `view=`, `doc=`.
- Request bodies or headers whose value looks like a filename, include path, or directory.
- Responses that echo file contents, render templates, or embed an error naming the local path.
- PHP-style applications where filters (`php://filter`) and wrappers are likely in play.

## Process
1. Observe the parameter's behavior without mutating configured state: note whether a traversal like `../../` changes the output, using `scope_preflight` before any request.
2. Build a falsifiable hypothesis with `create_hypothesis`, e.g. "If I pass `page=../../../../etc/passwd`, the response will return the file, crossing the confidentiality boundary."
3. Predict both outcomes ahead of time: which observable would confirm local read, and which would refute it.
4. Run the minimal controlled experiment through `send_authorized_http_request` only — never raw curl, nmap, or sqlmap — with one path at a time, read-only.
5. Record via `complete_research_test` and `create_evidence`. Prefer the least invasive proof that reaches a single file; do not enumerate the filesystem at scale.
6. Treat RCE conversion (filters, wrappers, log poisoning) as a new hypothesis that requires explicit, recorded policy approval before any write or code-execution step.

## Evidence
- `request_response`: full redacted request and response showing the included file's bytes.
- `observation`: notes on what changed between the baseline request and the traversal request.
- `command_output` for harness CLI checks only. Redact secrets, credentials, and PII from every stored record.

## False positives
- Static headers or an error message that echoes the path string back without reading the file — verify actual file bytes appear, not the parameter itself.
- A default page rendered on any input (silent fall-through) — confirm the output actually varies with the chosen path.
- A whitelist that accepts only known filenames — test whether unknown paths are rejected before claiming arbitrary read.
- A reflected path in a redirect or log line, which is not a file read at all.

## Stop conditions
- `scope_preflight` rejects the target or the action — stop immediately.
- The proof would require R3/R4 or destructive behavior and no approval is recorded — stop and request it.
- Showing the effect would overwrite files, poison a shared log, or degrade service — do not proceed.
- You cannot distinguish an arbitrary read from intended file access — uncertainty resolves to no.

## Example
On `http://example.test/article.php`, a `page=` parameter is passed to the harness broker. Requesting `page=../../../../etc/passwd` returns `root:x:0:0:...` in the response, confirming disclosed-file read. The RCE escalation — feeding `php://filter/convert.base64-encode/resource=...` or poisoning an access log at `http://127.0.0.1` — is then raised as a separate hypothesis and stalled until policy approval is recorded.