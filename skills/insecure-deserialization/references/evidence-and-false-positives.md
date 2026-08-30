# Evidence, false positives, impact, and remediation

Evidence includes source entrypoint, format, provenance/authentication, exact deserializer/config, allowed type resolution, reachable callbacks/gadget, safe controlled object/field, and observed effect. False positives: base64 alone, parse errors, signed tamper rejection, test-only code, vulnerable library without reachable API, and harmless serialization.

Remediate with data-only schemas, no native object deserialization across trust boundaries, strict type allowlists, authenticated provenance plus replay/lifecycle controls, safe parsers, gadget dependency removal, process isolation, and source/runtime tests.
