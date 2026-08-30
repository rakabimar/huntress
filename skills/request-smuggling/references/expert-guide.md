# Expert guide: HTTP desynchronization

## Mental model
A vulnerability requires at least two HTTP parsers on one connection that disagree about message boundaries. Model client→CDN/WAF/proxy→gateway→origin, protocol conversions, connection reuse, and which hop honors Content-Length, Transfer-Encoding, HTTP/2 length, trailers, or malformed header normalization.

## Attack surface and methodology
Infer the chain from architecture/source and safe errors. Choose one discrepancy (CL.TE, TE.CL, TE.TE, H2 downgrade, header-name/value normalization) rather than spraying probes. Use a dedicated harmless endpoint/connection and a self-attributable follow-up. A 400, timeout, or connection close alone is not proof. Confirmation requires the second parser to consume bytes as another request or misassociate a response.

Decision tree: one parser rejects ambiguity → control; no reusable downstream connection → no queue desync; repeatable self-response misalignment → candidate; any third-party response/content → stop immediately. Shared-front-end desync is risk-sensitive and normally ASK; poisoning other users or repeated queue manipulation is DENY.
