# Evidence, false positives, impact, and remediation

Evidence must prove the exact protected effect and retain a refuting control. False positives: Read-only PR workflows with least permissions, attacker code never executed in privileged context, secrets unavailable by platform design, immutable action SHAs, and artifacts cryptographically/provenance bound.

Impact is limited to the demonstrated boundary. Remediation: Use least workflow/job permissions, separate untrusted build from privileged release, never checkout attacker code under privileged triggers, quote/parameterize shell inputs, pin action SHAs, bind artifacts/caches/OIDC claims, approve environments, and isolate ephemeral runners.
