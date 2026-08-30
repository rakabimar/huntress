# Skill authoring

A skill encodes judgment, not a payload encyclopedia. Keep `SKILL.md` compact:
purpose, activation boundary, mental model, decision workflow, deeper-reference
routing, evidence, false positives, and stop conditions. Put class-specific
depth in `references/`.

Stable technical skills require routing metadata (`primary_triggers`,
`secondary_triggers`, `negative_triggers`, related skills, specialist), a
distinct mental model and attack surface, implementation guidance, a false-
positive model, an evidence contract, remediation, and all eight deterministic
eval groups. A behavioral fixture must exist, though running a model is never a
normal build requirement.

Use a new top-level skill only for a distinct trust boundary, method, surface,
evidence model, or reasoning process. Otherwise extend a canonical reference.
Optional cloud, AI, mobile, client-reverse, gRPC, and fuzzing knowledge belongs
to capability packs and is not routed by default.

Deprecated aliases contain only `canonical_skill` routing and the six required
sections. They never duplicate methodology.

Validation:

```bash
./harness skill validate
./harness skill eval
```

The validator also warns on near-identical expert/methodology references across
unrelated stable skills and on missing negative routing or evidence guidance.
