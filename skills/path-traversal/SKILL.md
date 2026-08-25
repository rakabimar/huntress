---
name: path-traversal
description: Use when a request parameter or header appears to name a file or path on the server (download, export, image/render, template, or archive endpoints) and may be honored without sanitization.
maturity: draft
risk_class: R2
category: file
cwe: [22]
---

# Path Traversal

## Purpose
Path traversal (CWE-22) occurs when user input is used to construct a filesystem path without neutralizing `../`, encoded variants, or absolute-path prefixes. It lets an attacker read (and sometimes write) files outside the intended directory. For bug hunting it is an easy-to-demonstrate, read-only proof using a known static file, so it rarely needs to touch sensitive paths.

## When to use
- Parameters that look like `file=`, `path=`, `name=`, `template=`, `img=`, `download=`, `lang=`, or headers like `X-Filename` feeding a filesystem read.
- Endpoints that serve, render, export, or extract resources: image/PDF renderers, "download report" handlers, config/backup exports, archive unpacking (zip/tar slip).
- Applications in PHP/Node/Ruby/Go that concatenate the parameter into a path with insufficient normalization.
- Anywhere a file's *content* is echoed back (template include, image bytes, JSON key), not where the ID is merely a database key.

## Process
1. **Observe.** Map the parameter and how its value is reflected. Note the framework/traces if available; never mutate yet.
2. **Hypothesize.** Write a falsifiable claim with `create_hypothesis`, e.g. "A `../` sequence in `file=` escapes the intended directory and returns a known static file."
3. **Predict.** Record both outcomes on the planned test via `create_research_test`: if true, the static file's content returns unchanged; if the value is neutralized or the request 4xx/empty, the claim is refuted.
4. **Test minimally.** Send exactly one controlled request through `send_authorized_http_request` (never raw curl/nmap/sqlmap), preferring a harmless, known file as the target. Proof of *reading* is reading e.g. a static asset one directory up — never `/etc/shadow` or credentials.
5. **Vary only one thing at a time** across follow-ups: plain `../`, then `..%2f` / `%2e%2e` (double-encoding), then an absolute path like `/etc/hostname` or a Windows `C:\` style prefix, then archive entries in uploaded zips. Each is a separate planned test.
6. **Compare and record.** Store the observation with `complete_research_test`, attach `create_evidence` records, then advance or reject the hypothesis. Promote toward a candidate finding only if a reproducible boundary crossing holds.

## Evidence
- `request_response` — full redacted request and response showing the traversal payload and the file content leaked; enough for a third party to reproduce.
- `observation` — note that the returned bytes match the known static file exactly (content hash or unique marker).
- `command_output` — only for harness-side actions (e.g. hashing the file you expected), never for raw recon shelling.
- Redact secrets, tokens, and PII from previews; never store the contents of sensitive files.

## False positives
- A parameter that maps to a database key or ID and returns the *same* record regardless of `../` is not a traversal.
- A `/../` in a URL path normalized by the web server before it reaches the app returns a normal 200/redirect — that is routing, not a vulnerability.
- Response includes the filename or error but never the *content* — that is message disclosure, not traversal; confirm the actual bytes are returned.
- The file resolves to the app's own expected directory because a `realpath`/allowlist check rewrote it — confirm the *actual* path, not the payload string, escaped.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` denies the action — stop immediately.
- Any proof would require R3/R4 (write/delete, data exfiltration at scale, DOS) or a destructive overwrite — stop and request approval rather than proceeding.
- The only way to demonstrate impact is reading a sensitive/credential file — do not; a read-only proof on a known harmless file is sufficient and non-invasive.
- You cannot tell whether the payload would alter server state — resolve that uncertainty to "no" and stop.

## Example
On `http://app.example.test`, a "Download invoice" button calls `GET /download?file=invoice-2026-01.pdf`. Hypothesize: `../` escapes the invoice directory. Test one request: `GET /download?file=../app.log` (a known static file). If the response body matches `app.log` byte-for-byte, the boundary is crossed read-only; then vary encoding (`..%2f`) and an absolute path like `/etc/hostname` on localhost only. Confirm each step reproduces before promoting a candidate finding.