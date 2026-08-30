# Skill quality audit matrix

This implementation-time matrix records the complete routed library after the
enhancement. `Refs` counts progressive reference files; `evals` counts populated
deterministic groups out of the mature eight-group standard. Core methodology
and optional draft packs intentionally use smaller suites.

| Skill | Category | Maturity | Refs | Evals | Depth | Overlap | Action |
|---|---|---:|---:|---:|---|---|---|
| access-control | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| api-authorization | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| api-enumeration | recon | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| attack | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| authentication | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| authn-bypass | authnz | draft/deprecated | 0 | 0/8 | alias | canonicalized | Route to authentication |
| business-logic | business-logic | stable | 9 | 8/8 | expert | distinct | Deepened |
| cache-deception | infra | stable | 3 | 8/8 | expert | distinct | Added stable |
| cache-poisoning | infra | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| cicd-security | platform | stable | 3 | 8/8 | expert | distinct | Added stable |
| client-reverse | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| cloud-security | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| command-injection | injection | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| cors-misconfig | client-side | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| crypto-misuse | crypto-config | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| csrf | web | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| defend | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| dependency-reachability | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| differential-security-review | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| exploit-chain-analysis | core | stable | 1 | 1/8 | methodology | composes | Added stable |
| feature-threat-model | core | stable | 1 | 1/8 | methodology | composes | Added stable |
| file-upload | file | stable | 9 | 8/8 | expert | distinct | Deepened |
| fuzzing | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| git-history-security | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| graphql | api | stable | 9 | 8/8 | expert | distinct | Deepened |
| grpc-security | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| header-injection | injection | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| host-header | infra | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| http-parameter-pollution | protocol | stable | 3 | 8/8 | expert | distinct | Added stable |
| hypothesize | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| idor | authnz | draft/deprecated | 0 | 0/8 | alias | canonicalized | Route to api-authorization |
| information-disclosure | crypto-config | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| insecure-deserialization | crypto-config | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| jwt | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| jwt-misuse | authnz | draft/deprecated | 0 | 0/8 | alias | canonicalized | Route to jwt |
| ldap-injection | injection | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| lfi | file | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| llm-ai-security | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| mass-assignment | business-logic | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| mobile-security | platform | draft | 1 | 1/8 | gated | optional | Added draft pack |
| nosqli | injection | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| oauth-misuse | authnz | draft/deprecated | 0 | 0/8 | alias | canonicalized | Route to oauth-oidc |
| oauth-oidc | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| observe | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| open-redirect | web | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| path-traversal | file | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| payment-logic | business-logic | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| postmessage | client-side | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| privilege-escalation | authnz | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| prototype-pollution | client-side | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| race-condition | business-logic | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| rate-limit-bypass | crypto-config | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| recon-passive | recon | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| report | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| request-smuggling | infra | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| research-loop | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| saml-sso | protocol | stable | 3 | 8/8 | expert | distinct | Added stable |
| secret-exposure-analysis | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| session-fixation | authnz | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| session-management | authnz | stable | 9 | 8/8 | expert | distinct | Deepened |
| source-audit-context | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| source-authorization-analysis | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| source-dataflow-analysis | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| sql-injection | injection | stable | 9 | 8/8 | expert | distinct | Deepened |
| sqli | injection | draft/deprecated | 0 | 0/8 | alias | canonicalized | Route to sql-injection |
| ssrf | web | stable | 9 | 8/8 | expert | distinct | Deepened |
| ssti | injection | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| subdomain-takeover | infra | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| triage | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| unrestricted-download | file | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
| validate | core | stable | 0 | 0/8 | established | reviewed | Retain stable |
| variant-analysis | whitebox | stable | 3 | 8/8 | expert | plane-specific | Added stable |
| webhook-security | protocol | stable | 3 | 8/8 | expert | distinct | Added stable |
| websocket | client-side | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| workflow-bypass | business-logic | stable | 3 | 8/8 | expert | bounded | Promoted stable |
| xss | injection | stable | 9 | 8/8 | expert | distinct | Deepened |
| xxe | injection | draft | 0 | 0/8 | baseline | candidate | Retain draft; future metrics |
