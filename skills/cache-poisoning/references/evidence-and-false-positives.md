# Evidence, false positives, impact, and remediation

Evidence includes cache key hypothesis, cache-buster, influencing request, clean follow-up, Age/X-Cache/Vary/cache headers, byte-level marker, cache layer/TTL, and cross-context result. False positives: origin reflection, local browser cache, correctly keyed variants, stale deploy artifacts, and no shared recipient.

Remediate by keying every response-varying input or removing its influence, canonicalizing consistently, setting correct private/no-store/Vary controls, rejecting untrusted forwarding headers, separating authenticated content, and testing origin/cache normalization pairs.
