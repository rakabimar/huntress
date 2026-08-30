# Agents

Canonical specs live in `agent-specs/`; `./harness sync` renders each runtime's
format. General stances remain recon observer, attacker, defender, triager,
validator, reporter, hypothesis architect, and researcher.

Five domain specialists add depth without creating one agent per bug class:

- `api-authz-specialist`: REST, GraphQL, BOLA/IDOR, BFLA, tenant/property checks,
  and mass assignment.
- `auth-identity-specialist`: login, registration, sessions, JWT, OAuth/OIDC,
  reset, MFA, and identity transitions.
- `client-side-specialist`: JavaScript routes, DOM, postMessage, and frontend /
  backend trust boundaries.
- `business-logic-specialist`: workflow sequence, pricing, quantity, discount,
  role restrictions, and bounded race hypotheses.
- `whitebox-audit-specialist`: commit-pinned architecture/control context,
  dataflow and sibling-invariant analysis, Source Leads, and runtime correlation.

Source Leads then route to the vulnerability owner when the boundary is clear:
missing ownership checks to `api-authz-specialist`, tainted outbound URLs to the
SSRF methodology, unsafe deserialization to its canonical skill, and CI policy
issues to `cicd-security`. The router loads one primary and no more than two
supporting skills.

`finding-validator` is independent: it reads only the candidate's linked tests
and evidence, attempts to disprove it, and submits the structured review from a
session different from the creator. `harness finding validate-auto` creates the
separate role-bound Claude process; the validator cannot finalize its own
review, and its live replay allowance is capped at one linked research test.
