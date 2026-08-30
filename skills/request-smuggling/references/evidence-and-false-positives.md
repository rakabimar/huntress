# Evidence, false positives, impact, and remediation

Evidence preserves exact byte framing, protocols/hops, connection reuse, timing, benign follow-up marker, and self-attributed response sequence. False positives: idle timeout, frontend rejection, backend slowness, cache response, scanner interference, and same-parser handling. Never retain third-party traffic.

Impact is limited to demonstrated response/request misassociation. Remediate by normalizing/rejecting ambiguous framing at the edge, using consistent parsers/protocols, disabling risky downgrades/reuse where needed, and adding byte-level regression tests across the actual proxy chain.
