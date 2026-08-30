# Skill library

The library contains 77 directories: 72 active canonical skills and five thin
deprecated aliases. Maturity is 47 stable and 30 draft. Skill count is not the
objective—the router chooses one primary plus at most two supporting skills so
the model receives the smallest relevant decision context.

## Taxonomy

- Core methodology includes the research stances, `research-loop`,
  `feature-threat-model`, and `exploit-chain-analysis`.
- Web/API contains the canonical authorization, identity, injection, browser,
  business-logic, file, protocol, and infrastructure skills.
- White-box contains `source-audit-context`, `source-dataflow-analysis`,
  `source-authorization-analysis`, `git-history-security`,
  `differential-security-review`, `variant-analysis`,
  `dependency-reachability`, and `secret-exposure-analysis`.
- Platform/protocol additions include `cicd-security`, `saml-sso`,
  `webhook-security`, `http-parameter-pollution`, and `cache-deception`.
- Cloud, AI, client reverse, mobile, gRPC, and fuzzing are optional draft
  capability packs.

The deepest canonical skills are `api-authorization`, `access-control`,
`authentication`, `session-management`, `jwt`, `oauth-oidc`, `business-logic`,
`graphql`, `file-upload`, `ssrf`, `xss`, and `sql-injection`. Their compact entry
files progressively route into vulnerability-specific mental models, attack
surfaces, implementation notes, decision methods, false positives, evidence,
impact, remediation, and public-report patterns.

## Routing and aliases

Frontmatter declares primary/secondary/negative triggers, related skills,
specialist, black-box/white-box applicability, tools, capability pack, and
behavioral fixture status. Capability packs remain dormant without an explicit
signal. `idor`, `sqli`, `authn-bypass`, `jwt-misuse`, and `oauth-misuse` resolve
to their canonical replacements and never load duplicate prose.

## Stable maturity gate

A stable technical skill must have distinct technical methodology, routing
boundaries, implementation guidance, false-positive reasoning, evidence and
remediation guidance, stop conditions, all eight deterministic eval groups, and
a behavioral fixture. The validator warns about highly similar references
across unrelated categories.

```bash
./harness skill list
./harness skill validate
./harness skill eval [slug]
./harness skill eval api-authorization --behavioral --runtime claude --ablation
```

Structural evaluation and pytest never invoke a model. See
[skill authoring](skill-authoring.md), [deterministic evals](skill-evals.md), and
[behavioral evals](behavioral-evals.md).
