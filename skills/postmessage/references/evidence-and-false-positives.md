# Evidence, false positives, impact, and remediation

Evidence includes sender/receiver origins and window relationship, targetOrigin, event.origin/source checks, message schema and transaction ID, source-to-sink trace, minimal controlled message, and protected outcome. False positives: unreachable attacker window, exact allowlist, public broadcast, structurally rejected message, and wildcard without sensitive data/action.

Remediate with exact targetOrigin, exact origin allowlist plus expected source window, strict schemas and transaction nonces, least data, server authorization for resulting actions, and safe DOM sinks.
