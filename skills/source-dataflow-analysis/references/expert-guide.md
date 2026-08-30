# Expert guide

Mental model: SOURCE → TRANSFORMS → VALIDATION/SANITIZATION → SINK, with explicit reachability and path predicates. Sources include request/query/JSON/GraphQL/WebSocket/file/queue/plugin data. Sinks include SQL, filesystem, templates, OS process, HTTP client, native deserializer, XML, authorization fields, cloud APIs, and email/document rendering. Attack surface analysis asks whether sanitization matches the final sink and occurs after the last transform.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

## Path proof

Label the exact attacker-controlled field and the conditions under which it is controlled. Follow assignments, decoding, normalization, concatenation, object construction and wrapper calls to the sink argument. A source and sink in the same function are only a candidate until argument correspondence is established. Validation must be evaluated for the final sink: SQL parameterization does not make a shell command safe; URL parsing before redirects does not constrain the final destination; filename extension checks do not constrain archive member paths.

For SQL, distinguish prepared parameters from identifier/order fragments. For filesystem, normalize after decoding and resolve against the intended root, including symlink/archive semantics. For process execution, distinguish argv arrays from shell interpretation and option injection. For network clients, analyze schemes, DNS/IP classes, redirects and proxy behavior. For deserialization, identify format, type activation and attacker reachability. For mass assignment/cloud API sinks, identify privilege-bearing fields and downstream authorization.

Tool path: exact source/sink wrapper → ripgrep; syntax variants → AST/Semgrep; cross-service/callback/interprocedural correspondence → CodeQL; environment-dependent behavior → approved sandbox reproducer; hosted protected effect → Broker. Reject when input is fixed by an enum/allowlist after canonicalization, the sink receives a constant or safe wrapper output, the code is unreachable, or the source commit is not deployed. If path feasibility remains UNKNOWN, keep an Observation and state the missing edge.
