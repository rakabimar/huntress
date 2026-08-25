---
name: unrestricted-download
description: Use when testing for direct file access, directory listing, or missing authorization on static and sensitive files such as backups, .git, and configuration files.
maturity: draft
risk_class: R1
category: file
cwe: [494]
---

# Unrestricted File Download and Forced Browsing

## Purpose
Forced browsing and unrestricted download occur when a server serves files directly without an authorization check: directory indexes, __backups, VCS metadata, environment/config files, and other artifacts are reachable by guessing predictable URLs. Because these files are often missed by asset-based scanners, mapping every discovered path back to a static-location guess is a high-yield reconnaissance-and-disclosure exercise. The boundary crossed is confidentiality: an unauthenticated or low-privilege actor reads data the application never meant to expose over HTTP.

## When to use
- Direct file references in URLs (e.g. `/download?file=`, `/static/`, `/uploads/`) with no visible access control.
- Content discovery surfaced directories that return a listing rather than a 403/404.
- Predictable artifacts exist in the stack: `.git/`, `.env`, `.bak`, `.DS_Store`, `web.config`, `backup.zip`, editor swap files.
- Same-origin static resources that appear sensitive on inspection (server banners, version files, logs).

## Process
1. Run `scope_preflight` on the candidate URL and `policy_preflight` on the intended read action; proceed only if both allow it.
2. Write a falsifiable claim with `create_hypothesis`: "Requesting `<path>` unauthenticated on `example.test` returns the file body rather than the authenticated/403 baseline, crossing the confidentiality boundary."
3. Record the controlled change: fetch a known-public file first as baseline, then fetch the guessed sensitive path once.
4. Run only the minimal single request through `send_authorized_http_request` (never raw curl/wget/nmap). Compare status code, content-type, and body against the baseline.
5. Log the observation and result with `complete_research_test` (supports/rejects/inconclusive), then persist durable evidence via `create_evidence`.
6. Prefer the least-invasive proof: presence of a 200 with the expected body is enough; do not chase exfiltration at scale.

## Evidence
- `request_response`: full redacted request and response showing the unauthenticated GET, status, and body proving the file is served.
- `observation`: notes on content-type/headers that distinguish real disclosure from a generic 200.
- `command_output`: only if a harness CLI call was needed to reproduce; otherwise omit.
- Redact any secrets, tokens, or PII recovered from the file before storing previews.

## False positives
- A 200 on a public, intentionally-exposed asset (logos, static JS/CSS, robots.txt) is not a finding.
- An error page that returns 200 with a generic body HTML is not disclosure; verify the actual sensitive content is present.
- Directory listing alone without a protected thing on it: confirm the listed file is sensitive before promoting.
- Localhost/developer-only exposures you cannot reach from an unauthenticated context are not demonstrated.

## Stop conditions
- `scope_preflight` rejects the URL: stop, do not test.
- The action requires anything above R1 (e.g. destructive or DOS) and no approval is recorded: stop.
- Proving the issue would require mass download or destructive write: stop and request guidance.
- You cannot distinguish whether the action is authorized: resolve to no and stop.

## Example
An application on `example.test` references `/srv/reports/report_2026.pdf` with no auth. You hypothesize the sibling backup `report_2026.pdf.bak` is served from the same static directory. Baseline: `GET /srv/reports/report_2026.pdf` returns 200. Controlled change: `GET /srv/reports/report_2026.pdf.bak` returns 200 with recognizable PDF/backup bytes. You record `request_response` evidence for both and mark the hypothesis supported, then promote a candidate finding only after a validator fails to disprove it.