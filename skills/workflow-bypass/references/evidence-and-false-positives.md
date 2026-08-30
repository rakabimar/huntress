# Evidence, false positives, impact, and remediation

Evidence includes state diagram fragment, current state, expected allowed transitions, actor, prerequisite artifact fingerprint, normal transition, forbidden request, and authoritative postcondition. False positives: bookmarkable screens, idempotent replays, draft creation without activation, eventually rejected async jobs, and optional steps.

Impact is the exact verification/approval/payment/role gate bypassed. Remediate by centralized server-side transition methods that atomically validate state, actor, prerequisite, immutable approved data, and one-time artifacts across every endpoint/job.
