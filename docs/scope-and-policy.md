# Scope & policy (authorization model)

The harness centralizes "what may I touch, and how hard?" in two deterministic
engines. **The model never decides the class or the verdict** — it only decides
*what to try next*, and the engines say yes/no/wait-for-a-human.

## Scope engine

Config lives in each program's `scope.yaml` (`include` + `exclude` `ScopeSet`s).
A `ScopeSet` holds these selector lists:

- `domains` — exact hosts (`example.com`)
- `wildcards` — `*.example.com`
- `subdomains` — explicit subhosts (treated as exact)
- `urls` — full absolute URLs (scheme+host+port)
- `path_urls` — URLs scoped to a path prefix (segment-boundary aware)
- `ipv4`, `cidr` — IP addresses and CIDR ranges

Invariants:

1. **Exclusion always wins** over inclusion.
2. `*.example.com` matches `a.example.com` and `a.b.example.com` but **not**
   `example.com` itself and **not** `evil-example.com`.
3. An exact domain matches only itself; subdomains need a wildcard or explicit entry.
4. A URL-rule path prefix matches only at `/` segment boundaries
   (`/api` matches `/api/v1`, not `/apiv2`).

`scope check` returns a structured `ScopeDecision` (decision = `ALLOWED` /
`BLOCKED` + reason + matched rule).

## Policy engine & risk classes

Actions are classified in `bughunt_harness/actions.py`:

| Class | Meaning | Example actions |
|---|---|---|
| **R0** | analysis only, no network | `analyze` |
| **R1** | low-impact active request | `read_http`, `replay_http` |
| **R2** | controlled active mutation | `parameter_mutation`, `authorization_test`, `business_logic_test`, `upload_test`, `csrf_test`, `limited_fuzz`, `state_changing_request` |
| **R3** | explicit human approval required | `race_test`, `oob_test`, `brute_force` |
| **R4** | disabled by default | `dos`, `destructive` |

The **Rules of Engagement** (`roe.yaml`) overlay program-specific constraints:
`automation_allowed`, per-activity flags (`authentication_testing`,
`authorization_testing`, `file_upload`, `race_conditions`, `fuzzing`,
`out_of_band_testing`, `state_changing_actions`, `brute_force`,
`denial_of_service`, `destructive_testing`), `max_rps`, `max_concurrency`,
`manual_approval_actions`, `forbidden_actions`, and `required_headers`.

Evaluation order (first match wins):

1. unknown action → error
2. `roe.forbidden_actions` → **deny**
3. risk class R4 → **deny**
4. target out of scope → **deny**
5. `roe` activity flag false → **deny**
6. `roe.manual_approval_actions` → **approval_required**
7. risk class R3 → **approval_required**
8. network action + `automation_allowed=false` → **approval_required**
9. otherwise → **allow**

Every verdict is available via the CLI (`policy check`) and the MCP tool
(`policy_preflight`), and the same engine is what the broker enforces at request
time. `PolicyEngine.require_allow` raises typed errors
(`ActionForbiddenError`, `ApprovalRequiredError`).