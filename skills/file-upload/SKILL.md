---
name: file-upload
description: Use when testing endpoints that accept file uploads, avatars, attachments, or imports for unrestricted file upload weaknesses.
maturity: draft
risk_class: R2
category: file
cwe: [434]
---

# Unrestricted File Upload

## Purpose
Unrestricted file upload arises when an application accepts a user-supplied file without adequately validating its extension, MIME type, or content, and serves it back from a predictable or executable location. For bug hunting it matters because every upload field — an avatar, an attachment, an import form — is a candidate gateway for stored content and, in the worst case, code execution. Proving it requires demonstrating that a malicious or disallowed file is actually stored and retrievable, not merely accepted.

## When to use
- Endpoints with `multipart/form-data` upload fields (avatars, logos, documents, batch import).
- Features that reflect or re-serve uploaded content (image preview, download link, profile display).
- Apps whose validation is purely client-side or that check only the filename extension or a caller-supplied MIME type.
- Uploads placed into web-accessible directories (e.g. `/uploads`, `/media`, `/static`).

## Process
1. Enumerate the upload surface and its response: does it echo a URL, an ID, or the stored path? Record what is observable.
2. Build a falsifiable hypothesis with `create_hypothesis`: "If I upload a file whose extension is whitelisted but whose content is not, then the server stores and later serves it as the disallowed type, crossing a content-type boundary."
3. Predict the observable if true (retrieved file retains the disallowed content on a second GET) and what would refute it (re-encoding, rename, blocked storage).
4. Run the minimal controlled experiment through `send_authorized_http_request` only — never raw curl/nmap/sqlmap. Start with a harmless marker file (plain text, a benign payload) whose content is safe regardless of interpretation.
5. Vary one control at a time: extension case/alternates, MIME header spoofing, double extension, polyglot content, and path/null-byte truncation in the filename.
6. Retrieve the stored file via a second request and compare against the prediction. Record via `complete_research_test` and `create_evidence`.
7. Prefer least-invasive proof: show storage + retrieval of content, or confirmation the file lands in an executable path, rather than uploading a live webshell.

## Evidence
- `request_response` of the upload and the follow-up retrieval, showing the stored file and its served content type.
- `observation` noting the server's disposition of the filename, path, and content.
- `command_output` only where a read-side check (e.g. a file listing) was authorized; redact any secrets or PII in filenames or bodies.

## False positives
- Content appears accepted but is renamed, re-encoded, or returned as `application/octet-stream` — not an execution path; verify a second GET returns the original content.
- Validation rejected the file but the app merely renders an error message; rejection is not bypass.
- Stored to an inaccessible or non-web directory; no retrieval path means no impact.

## Stop conditions
- `scope_preflight` rejects the target or a host outside the program — stop.
- Demonstrating impact would require an R3/R4 action (destructive overwrite, data exfiltration at scale, DOS) and no approval is recorded — stop.
- Proof would require running or weaponizing an uploaded executable rather than showing inert content — stop.

## Example
On `http://uploads.test` a profile page lets a user set an avatar and returns `/uploads/avatar.<id>`. Hypothesis: a file uploaded with an allowed extension but script content is stored unchanged under an executable path. Upload via the broker a harmless `.txt` whose body is a short marker string, then GET the returned URL and observe whether the marker is served verbatim. If it is, iterate the extension and content-type controls; do not upload a live webshell.