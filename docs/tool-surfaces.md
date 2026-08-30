# Role and capability tool surfaces

The default orchestrator receives only engagement/scope/policy, hunt/recon summaries, Lead/Hypothesis/Test, Broker/evidence, approval/checkpoint and handoff tools. Detailed whitebox, validation, reporting, browser and recon primitives are specialist/capability groups.

Subprocess sessions can add a comma-separated `BUGHUNT_CAPABILITIES` set: `whitebox`, `validation`, `reporting`, `browser`, or `recon`. This is presentation/routing, not authorization; every underlying tool retains deterministic program, scope, ROE, approval and provenance gates.
