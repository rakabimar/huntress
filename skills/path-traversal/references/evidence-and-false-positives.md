# Evidence, false positives, impact, and remediation

Evidence includes input encoding, decode stages, intended root, canonical path reasoning, operation type, harmless target hash/marker, baseline and traversed result, platform/framework, and containment boundary. False positives: database IDs, routing normalization, error messages, expected parent references resolved inside root, and symlink behavior not attacker-controllable.

Remediate with server-generated identifiers or strict mappings, canonicalize once, resolve against a fixed root, enforce path-component containment after symlink policy, safe archive extraction, least filesystem privileges, and regression tests for separators/encoding/platform.
