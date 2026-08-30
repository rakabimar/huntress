# XSS false positives

Reject HTML-encoded/textContent output, inert JSON, sanitizer removal, raw source that never reaches an executable DOM sink, self-XSS without credible delivery, javascript URLs requiring impossible interaction, browser-extension injection, uploaded active content isolated on another origin/attachment, and execution blocked by deployed CSP/Trusted Types with no demonstrated bypass.
