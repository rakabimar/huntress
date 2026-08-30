# Expert guide

Model channel/TLS, service/method, metadata identity, interceptor chain, request message fields, stream lifecycle, backend service, and tenant/object policy. Reflection/protobuf discovery is reconnaissance. Compare unary/streaming methods, per-message and stream-start authorization, metadata normalization, exposed internal methods, input validation, deadlines/limits, and REST parity. Use generated/local descriptors and one bounded semantic call through authorized tooling; never fuzz production streams or infer a flaw from enabled reflection.

Tool choice follows the cheapest sufficient observation: source search/read before structural analysis, structural analysis before deep dataflow, and authorized Broker/browser/local sandbox only when the hypothesis requires it. Evidence and remediation address the root trust boundary; false positives are rejected before Lead promotion.
