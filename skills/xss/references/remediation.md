# XSS remediation

Use final-context output encoding and safe DOM APIs, remove raw HTML/eval escape hatches, sanitize maintained allowlists immediately before insertion, validate URL schemes, isolate active uploads, and deploy strict CSP/Trusted Types as defense-in-depth. Regression-test the exact source-transform-sink path and viewer context.
