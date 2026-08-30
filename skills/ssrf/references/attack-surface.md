# SSRF attack surface and decision tree

Sources: webhook/callback URL, import by URL, link preview, avatar/image proxy, RSS, remote file, PDF/HTML render, screenshot, media transcoding, repository/package fetch, integration health check, URL validation endpoint.

Decision tree:

1. Does a server-side component fetch? Use authorized callback attribution; if browser-only, reject SSRF.
2. Is destination fixed/enum-selected? If attacker cannot affect network identity, reject.
3. What component validates and what client connects? Inspect source/errors/redirect behavior.
4. Is validation before or after canonicalization/DNS? Does every redirect revalidate? Does the connection use the validated IP?
5. What capability is permitted to prove? Prefer a controlled internal fixture; cloud metadata/internal service probes are ASK and only if ROE allows.

Source signals: raw HTTP client call with tainted URL; allowlist checks only string prefix/suffix; DNS check then later re-resolution; redirect enabled after initial validation; proxy/environment behavior; credentials forwarded across origin.
