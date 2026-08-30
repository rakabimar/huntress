# Evidence, false positives, impact, and remediation

Evidence includes input field, rendering feature, raw request/output, server-versus-browser timing, suspected engine/version, two safe expression controls, template source/data boundary, and sandbox behavior. False positives: client templating, literal braces, application math, syntax normalization, and fixed-template data escaping.

Impact starts with attacker-controlled server expression evaluation and only includes further capabilities actually demonstrated under policy. Remediate by never treating untrusted input as template source, using fixed precompiled templates with data binding, removing dynamic evaluation, sandboxing/isolation, and context-specific output encoding.
