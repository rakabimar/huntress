# Architecture

The harness is a Python package (`bughunt_harness`) plus a thin CLI
(`./harness`), a local MCP server, and generated per-runtime config. The design
centers on one idea: **the enumerated engine does the gate-keeping; the model
does the thinking.**

```
                    ┌───────────────────────────────────────────┐
                    │              AI runtime (Claude/Codex/OpenCode)│
                    │   skills + agent-specs + injected program brief │
                    └───────────────┬───────────────────────────┘
                                    │ hooks (SessionStart/PreToolUse/Stop)
                                    │ MCP tools (scope/policy/broker/entities)
                    ┌───────────────▼───────────────────────────┐
                    │            bughunt_harness package          │
                    │ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
                    │ │ scope    │ │ policy   │ │ broker      │  │
                    │ │ engine   │ │ engine   │ │ (requests)  │  │
                    │ └──────────┘ └──────────┘ └──────┬──────┘  │
                    │ ┌──────────┐ ┌──────────┐         │        │
                    │ │ cvss     │ │ secrets  │ ◄───────┘        │
                    │ │ (FIRST)  │ │ manager  │ (secret resolve) │
                    │ └──────────┘ └──────────┘                  │
                    │ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
                    │ │ state db │ │ skills   │ │ adapters    │  │
                    │ │ (SQLite) │ │ registry │ │ (sync)      │  │
                    │ └──────────┘ └──────────┘ └─────────────┘  │
                    └───────────────┬───────────────────────────┘
                                    │
                       ~/.bughunt/  (registry.db, programs/, secrets/)
```

## Deterministic core (engines, no model)

- **Scope engine** (`bughunt_harness/scope/engine.py`) — resolves any target
  (URL / bare host / IP / CIDR) against include/exclude `ScopeSet`s. Invariants:
  exclusion always wins; `*.example.test` matches descendants but not the apex or
  `evil-example.test`; URL rules match scheme+host(+port)+path-prefix at segment
  boundaries.
- **Policy engine** (`bughunt_harness/policy/engine.py`) — classifies an action
  (16-action taxonomy, risk classes R0–R4) on a target against ROE. Evaluation
  order is fixed (forbidden → R4 → out-of-scope → ROE activity flag → manual
  approval → R3 → automation → allow) and emits `allow` / `approval_required` /
  `deny`.
- **CVSS facade** (`bughunt_harness/cvss/engine.py`) — the *number* always comes
  from the official FIRST `cvss` library; severity banding is applied here.

## State

- **Registry** (`bughunt_harness/registry.py`) — global, non-sensitive program
  metadata in `~/.bughunt/registry.db` (slug, name, platform, workspace path).
- **Hunt DB** (`bughunt_harness/state/db.py`) — per-program SQLite with WAL +
  foreign keys, bound to one `program_slug` (hard isolation invariant). Holds
  sessions, leads, hypotheses, research tests, evidence, findings, checkpoints,
  agent actions, and approvals. A state machine (`state/constants.py`) enforces
  legal transitions.

## Controlled IO

- **Request broker** (`bughunt_harness/requests/broker.py`) — the only sanctioned
  HTTP path: scope → policy → rate-limit → header/secret resolution →
  (optional Burp) → execution → redaction → evidence persistence → action log.
- **Secret manager** (`bughunt_harness/secrets/manager.py`) — resolves
  `env:` / `keyring:` / `file:` references; only availability metadata is
  surfaced to the model.

## Knowledge, skills, agents

- **Skills** (`skills/`) — 48 skills with YAML frontmatter + required body
  sections; validated structurally by `bughunt_harness/skills/registry.py`.
- **Agent specs** (`agent-specs/`) — canonical, runtime-agnostic specialist
  definitions rendered into each runtime's native agent format.
- **Adapters** (`bughunt_harness/adapters/`) — `harness sync` derives
  `CLAUDE.md`, `AGENTS.md`, `.claude/settings.json`, `.mcp.json`, and per-runtime
  agent/skill/session files from the canonical sources.

## MCP server

`bughunt_harness/mcp/server.py` exposes narrow, vendor-neutral tools
(`scope_preflight`, `policy_preflight`, `send_authorized_http_request`, and the
entity/state tools) so agents never manipulate SQLite directly and every write
retains provenance.