# SSRF false positives

Reject browser-originated requests, DNS-only lookups, link-security previews, monitoring/scanner callbacks, open redirects, accepted but unfetched URLs, fixed server-selected destinations, and asynchronous callbacks without unique attribution. A server fetching an explicitly intended public URL is not necessarily a boundary flaw.
